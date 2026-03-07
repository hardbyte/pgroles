//! Shared operator context — database pool cache, metrics, and configuration.

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::postgres::PgPool;
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
struct CachedPool {
    resource_version: Option<String>,
    pool: PgPool,
}

/// Guard returned by [`OperatorContext::try_lock_database`].
///
/// Holding this guard prevents other reconcile loops (within the same process)
/// from starting work on the same database target. The lock is released when
/// the guard is dropped.
pub struct DatabaseLockGuard {
    key: String,
    locks: Arc<Mutex<HashMap<String, ()>>>,
}

impl Drop for DatabaseLockGuard {
    fn drop(&mut self) {
        // Best-effort removal — `try_lock` avoids blocking the drop.
        if let Ok(mut map) = self.locks.try_lock() {
            map.remove(&self.key);
            tracing::debug!(database = %self.key, "released in-memory database lock");
        } else {
            // Spawn a task to clean up if the mutex is currently held.
            let key = self.key.clone();
            let locks = Arc::clone(&self.locks);
            tokio::spawn(async move {
                locks.lock().await.remove(&key);
                tracing::debug!(database = %key, "released in-memory database lock (deferred)");
            });
        }
    }
}

/// Shared state for the operator, passed to every reconciliation.
#[derive(Clone)]
pub struct OperatorContext {
    /// Kubernetes client for API calls.
    pub kube_client: kube::Client,

    /// Cached database connection pools keyed by `"namespace/secret-name/secret-key"`.
    pool_cache: Arc<RwLock<HashMap<String, CachedPool>>>,

    /// In-process per-database reconciliation locks.
    ///
    /// Prevents concurrent reconcile loops from operating on the same database
    /// within a single operator replica. Cross-replica safety is provided by
    /// PostgreSQL advisory locks (see [`crate::advisory`]).
    database_locks: Arc<Mutex<HashMap<String, ()>>>,
}

impl OperatorContext {
    /// Create a new operator context with an empty pool cache.
    pub fn new(kube_client: kube::Client) -> Self {
        Self {
            kube_client,
            pool_cache: Arc::new(RwLock::new(HashMap::new())),
            database_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to acquire the in-process lock for the given database identity.
    ///
    /// Returns `Some(guard)` if no other reconcile is in progress for this
    /// database, `None` if one is already running. The lock is released when
    /// the guard is dropped.
    pub async fn try_lock_database(&self, database_identity: &str) -> Option<DatabaseLockGuard> {
        let mut locks = self.database_locks.lock().await;
        if locks.contains_key(database_identity) {
            tracing::info!(
                database = %database_identity,
                "in-memory database lock contention — another reconcile is in progress"
            );
            return None;
        }
        locks.insert(database_identity.to_string(), ());
        tracing::debug!(database = %database_identity, "acquired in-memory database lock");
        Some(DatabaseLockGuard {
            key: database_identity.to_string(),
            locks: Arc::clone(&self.database_locks),
        })
    }

    /// Get or create a PgPool for the given secret reference.
    ///
    /// Reads the `DATABASE_URL` (or custom key) from the referenced Secret,
    /// and caches the resulting pool for reuse.
    pub async fn get_or_create_pool(
        &self,
        namespace: &str,
        secret_name: &str,
        secret_key: &str,
    ) -> Result<PgPool, ContextError> {
        let cache_key = format!("{namespace}/{secret_name}/{secret_key}");

        // Fetch secret from k8s API.
        let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> =
            kube::Api::namespaced(self.kube_client.clone(), namespace);

        let secret =
            secrets_api
                .get(secret_name)
                .await
                .map_err(|err| ContextError::SecretFetch {
                    name: secret_name.to_string(),
                    namespace: namespace.to_string(),
                    source: err,
                })?;

        let resource_version = secret.metadata.resource_version.clone();

        // Check cache after reading the current Secret version.
        {
            let cache = self.pool_cache.read().await;
            if let Some(cached) = cache.get(&cache_key)
                && cached.resource_version == resource_version
            {
                return Ok(cached.pool.clone());
            }
        }

        let data = secret.data.ok_or_else(|| ContextError::SecretMissing {
            name: secret_name.to_string(),
            key: secret_key.to_string(),
        })?;

        let url_bytes = data
            .get(secret_key)
            .ok_or_else(|| ContextError::SecretMissing {
                name: secret_name.to_string(),
                key: secret_key.to_string(),
            })?;

        let database_url =
            String::from_utf8(url_bytes.0.clone()).map_err(|_| ContextError::SecretMissing {
                name: secret_name.to_string(),
                key: secret_key.to_string(),
            })?;

        // Create pool.
        let pool = PgPool::connect(&database_url)
            .await
            .map_err(|err| ContextError::DatabaseConnect { source: err })?;

        // Cache it (write lock).
        {
            let mut cache = self.pool_cache.write().await;
            cache.insert(
                cache_key,
                CachedPool {
                    resource_version,
                    pool: pool.clone(),
                },
            );
        }

        Ok(pool)
    }

    /// Remove a cached pool (e.g. when secret changes or CR is deleted).
    pub async fn evict_pool(&self, namespace: &str, secret_name: &str, secret_key: &str) {
        let cache_key = format!("{namespace}/{secret_name}/{secret_key}");
        let mut cache = self.pool_cache.write().await;
        cache.remove(&cache_key);
    }
}

/// Errors from operator context operations.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("failed to fetch Secret {namespace}/{name}: {source}")]
    SecretFetch {
        name: String,
        namespace: String,
        source: kube::Error,
    },

    #[error("Secret \"{name}\" does not contain key \"{key}\"")]
    SecretMissing { name: String, key: String },

    #[error("failed to connect to database: {source}")]
    DatabaseConnect { source: sqlx::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_cache_key_format() {
        // Verify the cache key format is "namespace/secret-name/secret-key"
        let key = format!("{}/{}/{}", "prod", "pg-credentials", "DATABASE_URL");
        assert_eq!(key, "prod/pg-credentials/DATABASE_URL");
    }

    #[tokio::test]
    async fn try_lock_database_acquires_when_free() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: locks,
        };
        let guard = ctx.try_lock("db-a").await;
        assert!(guard.is_some(), "should acquire lock on free database");
    }

    #[tokio::test]
    async fn try_lock_database_contention_returns_none() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: locks,
        };

        let _guard1 = ctx
            .try_lock("db-a")
            .await
            .expect("first lock should succeed");
        let guard2 = ctx.try_lock("db-a").await;
        assert!(guard2.is_none(), "second lock on same database should fail");
    }

    #[tokio::test]
    async fn try_lock_database_different_databases_independent() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: locks,
        };

        let guard_a = ctx.try_lock("db-a").await;
        let guard_b = ctx.try_lock("db-b").await;
        assert!(guard_a.is_some(), "lock on db-a should succeed");
        assert!(
            guard_b.is_some(),
            "lock on db-b should succeed (different database)"
        );
    }

    #[tokio::test]
    async fn try_lock_database_released_after_drop() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: Arc::clone(&locks),
        };

        {
            let _guard = ctx.try_lock("db-a").await.expect("should acquire");
            // guard is dropped here
        }

        // After drop, should be able to acquire again.
        let guard2 = ctx.try_lock("db-a").await;
        assert!(
            guard2.is_some(),
            "should re-acquire after previous guard dropped"
        );
    }

    #[tokio::test]
    async fn try_lock_database_concurrent_contention() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));

        // Simulate two concurrent reconciles for the same database.
        let locks1 = Arc::clone(&locks);
        let locks2 = Arc::clone(&locks);

        let handle1 = tokio::spawn(async move {
            let ctx = OperatorContextLockHelper {
                database_locks: locks1,
            };
            let guard = ctx.try_lock("shared-db").await;
            if guard.is_some() {
                // Hold the lock briefly.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            guard.is_some()
        });

        // Small delay so handle1 is likely first.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let handle2 = tokio::spawn(async move {
            let ctx = OperatorContextLockHelper {
                database_locks: locks2,
            };
            let guard = ctx.try_lock("shared-db").await;
            guard.is_some()
        });

        let (r1, r2) = tokio::join!(handle1, handle2);
        let acquired1 = r1.unwrap();
        let acquired2 = r2.unwrap();

        // Exactly one should succeed.
        assert!(
            acquired1 ^ acquired2,
            "exactly one of two concurrent locks should succeed: got ({acquired1}, {acquired2})"
        );
    }

    /// Helper to test locking without a real kube client.
    struct OperatorContextLockHelper {
        database_locks: Arc<Mutex<HashMap<String, ()>>>,
    }

    impl OperatorContextLockHelper {
        async fn try_lock(&self, database_identity: &str) -> Option<DatabaseLockGuard> {
            let mut locks = self.database_locks.lock().await;
            if locks.contains_key(database_identity) {
                return None;
            }
            locks.insert(database_identity.to_string(), ());
            Some(DatabaseLockGuard {
                key: database_identity.to_string(),
                locks: Arc::clone(&self.database_locks),
            })
        }
    }
}
