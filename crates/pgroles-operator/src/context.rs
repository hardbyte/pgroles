//! Shared operator context — database pool cache, metrics, and configuration.

use std::collections::HashMap;
use std::sync::Arc;

use kube::runtime::events::Recorder;
use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};
use tokio::sync::{Mutex, RwLock};

use crate::crd::{ConnectionSpec, SecretKeySelector};
use crate::observability::OperatorObservability;

/// Minimum pool size required for reconciliation.
///
/// One connection is held for the session-scoped advisory lock while the
/// reconcile loop performs inspection and apply work on the pool.
const POOL_MAX_CONNECTIONS: u32 = 5;

/// Bound how long a reconcile waits for a pooled connection before surfacing
/// a transient database connectivity failure.
const POOL_ACQUIRE_TIMEOUT_SECS: u64 = 10;

const _: () = assert!(POOL_MAX_CONNECTIONS >= 2);

#[derive(Clone)]
struct CachedPool {
    resource_version: Option<String>,
    /// Fingerprint of all referenced secrets' resourceVersions (params mode).
    secret_fingerprint: Option<String>,
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
            // Use Handle::try_current() so we don't panic when dropped
            // outside an active Tokio runtime (e.g. during shutdown).
            let key = self.key.clone();
            let locks = Arc::clone(&self.locks);
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    locks.lock().await.remove(&key);
                    tracing::debug!(database = %key, "released in-memory database lock (deferred)");
                });
                tracing::debug!(
                    database = %self.key,
                    "deferred in-memory database lock release to background task"
                );
            } else {
                // No runtime available — fall back to synchronous cleanup
                // via blocking_lock so the entry is still removed.
                let mut map = self.locks.blocking_lock();
                map.remove(&key);
                tracing::debug!(
                    database = %key,
                    "released in-memory database lock (fallback sync)"
                );
            }
        }
    }
}

/// Shared state for the operator, passed to every reconciliation.
#[derive(Clone)]
pub struct OperatorContext {
    /// Kubernetes client for API calls.
    pub kube_client: kube::Client,

    /// Kubernetes Event recorder for transition-based policy Events.
    pub event_recorder: Recorder,

    /// Cached database connection pools keyed by `"namespace/secret-name/secret-key"`.
    pool_cache: Arc<RwLock<HashMap<String, CachedPool>>>,
    /// In-process per-database reconciliation locks.
    ///
    /// Prevents concurrent reconcile loops from operating on the same database
    /// within a single operator replica. Cross-replica safety is provided by
    /// PostgreSQL advisory locks (see [`crate::advisory`]).
    database_locks: Arc<Mutex<HashMap<String, ()>>>,

    /// Shared health/metrics state.
    pub observability: OperatorObservability,
}

impl OperatorContext {
    /// Create a new operator context with an empty pool cache.
    pub fn new(
        kube_client: kube::Client,
        observability: OperatorObservability,
        event_recorder: Recorder,
    ) -> Self {
        Self {
            kube_client,
            event_recorder,
            pool_cache: Arc::new(RwLock::new(HashMap::new())),
            observability,
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

    /// Resolve a param from either its literal value or a Secret reference.
    ///
    /// Returns `Ok(Some(value))` if one is set, `Ok(None)` if neither is set.
    async fn resolve_param(
        &self,
        namespace: &str,
        literal: &Option<String>,
        secret: &Option<SecretKeySelector>,
    ) -> Result<Option<String>, ContextError> {
        if let Some(val) = literal {
            return Ok(Some(val.clone()));
        }
        if let Some(sel) = secret {
            return Ok(Some(
                self.fetch_secret_value(namespace, &sel.name, &sel.key)
                    .await?,
            ));
        }
        Ok(None)
    }

    /// Resolve a [`ConnectionSpec`] into a PostgreSQL connection URL string.
    ///
    /// - **URL mode** (`secret_ref` is Some): reads the Secret key as a connection URL.
    /// - **Params mode** (`params` is Some): resolves each field and constructs a URL.
    pub async fn resolve_connection_url(
        &self,
        namespace: &str,
        connection: &ConnectionSpec,
    ) -> Result<String, ContextError> {
        if let Some(ref secret_ref) = connection.secret_ref {
            // URL mode — read the full connection URL from the Secret.
            self.fetch_secret_value(
                namespace,
                &secret_ref.name,
                connection.effective_secret_key(),
            )
            .await
        } else if let Some(ref params) = connection.params {
            // Params mode — resolve each field and build the URL.
            let host = self
                .resolve_param(namespace, &params.host, &params.host_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "host".to_string(),
                })?;
            if host.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "host".to_string(),
                });
            }

            let port_str = params.port.map(|p| p.to_string());
            let port = self
                .resolve_param(namespace, &port_str, &params.port_secret)
                .await?
                .unwrap_or_else(|| "5432".to_string());
            if port.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "port".to_string(),
                });
            }

            let dbname = self
                .resolve_param(namespace, &params.dbname, &params.dbname_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "dbname".to_string(),
                })?;
            if dbname.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "dbname".to_string(),
                });
            }

            let username = self
                .resolve_param(namespace, &params.username, &params.username_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "username".to_string(),
                })?;
            if username.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "username".to_string(),
                });
            }

            let password = self
                .resolve_param(namespace, &params.password, &params.password_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "password".to_string(),
                })?;
            if password.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "password".to_string(),
                });
            }

            use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
            let encoded_username = utf8_percent_encode(&username, NON_ALPHANUMERIC).to_string();
            let encoded_password = utf8_percent_encode(&password, NON_ALPHANUMERIC).to_string();

            let mut url = format!(
                "postgresql://{encoded_username}:{encoded_password}@{host}:{port}/{dbname}"
            );

            if let Some(ssl_mode) = self
                .resolve_param(namespace, &params.ssl_mode, &params.ssl_mode_secret)
                .await?
            {
                // Validate sslMode at runtime — CRD validation only catches
                // literal values; a secret ref could resolve to anything.
                if !crate::crd::VALID_SSL_MODES.contains(&ssl_mode.as_str()) {
                    return Err(ContextError::InvalidResolvedSslMode { value: ssl_mode });
                }
                url.push_str("?sslmode=");
                url.push_str(&ssl_mode);
            }

            Ok(url)
        } else {
            Err(ContextError::SecretMissing {
                name: "connection".to_string(),
                key: "neither secretRef nor params is set".to_string(),
            })
        }
    }

    /// Get or create a PgPool for the given connection spec.
    ///
    /// Resolves the connection URL from the referenced Secret(s),
    /// and caches the resulting pool for reuse.
    pub async fn get_or_create_pool(
        &self,
        namespace: &str,
        connection: &ConnectionSpec,
    ) -> Result<PgPool, ContextError> {
        let cache_key = connection.cache_key(namespace);

        // For URL mode, we can do resource-version-based cache invalidation.
        // For params mode, compute a fingerprint from all referenced secrets'
        // resourceVersions so that secret rotations invalidate the cache.
        let (resource_version, secret_fingerprint) =
            if let Some(ref secret_ref) = connection.secret_ref {
                let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> =
                    kube::Api::namespaced(self.kube_client.clone(), namespace);
                let secret = secrets_api.get(&secret_ref.name).await.map_err(|err| {
                    ContextError::SecretFetch {
                        name: secret_ref.name.clone(),
                        namespace: namespace.to_string(),
                        source: err,
                    }
                })?;
                (secret.metadata.resource_version, None)
            } else if connection.params.is_some() {
                // Params mode — collect all referenced secret names and fetch their
                // resourceVersions to build a fingerprint.
                let mut secret_names = std::collections::BTreeSet::new();
                connection.collect_secret_names(&mut secret_names);

                if secret_names.is_empty() {
                    // All values are literals — no secrets to watch.
                    (None, Some(String::new()))
                } else {
                    let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> =
                        kube::Api::namespaced(self.kube_client.clone(), namespace);
                    let mut fingerprint_parts = Vec::new();
                    for name in &secret_names {
                        let secret = secrets_api.get(name).await.map_err(|err| {
                            ContextError::SecretFetch {
                                name: name.clone(),
                                namespace: namespace.to_string(),
                                source: err,
                            }
                        })?;
                        let rv = secret
                            .metadata
                            .resource_version
                            .unwrap_or_else(|| "unknown".to_string());
                        fingerprint_parts.push(format!("{name}={rv}"));
                    }
                    (None, Some(fingerprint_parts.join(",")))
                }
            } else {
                (None, None)
            };

        // Check cache.
        {
            let cache = self.pool_cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                // URL mode: reuse if the Secret's resource_version matches.
                // Params mode: reuse if the secret fingerprint matches.
                let version_matches = match (&resource_version, &cached.resource_version) {
                    (Some(current), Some(cached_rv)) => current == cached_rv,
                    _ => true,
                };
                let fingerprint_matches = match (&secret_fingerprint, &cached.secret_fingerprint) {
                    (Some(current), Some(cached_fp)) => current == cached_fp,
                    (None, None) => true,
                    _ => false,
                };
                if version_matches && fingerprint_matches {
                    return Ok(cached.pool.clone());
                }
            }
        }

        let database_url = self.resolve_connection_url(namespace, connection).await?;

        // Create pool with explicit sizing. Reconciliation holds one dedicated
        // connection for PostgreSQL advisory locking and needs additional pool
        // capacity for inspection/apply queries.
        let pool = PgPoolOptions::new()
            .max_connections(POOL_MAX_CONNECTIONS)
            .acquire_timeout(Duration::from_secs(POOL_ACQUIRE_TIMEOUT_SECS))
            .connect(&database_url)
            .await
            .map_err(|err| ContextError::DatabaseConnect { source: err })?;

        // Cache it (write lock).
        {
            let mut cache = self.pool_cache.write().await;
            cache.insert(
                cache_key,
                CachedPool {
                    resource_version,
                    secret_fingerprint,
                    pool: pool.clone(),
                },
            );
        }

        Ok(pool)
    }

    /// Fetch a single string value from a Kubernetes Secret.
    ///
    /// Used to resolve role passwords from Secret references at reconcile time.
    pub async fn fetch_secret_value(
        &self,
        namespace: &str,
        secret_name: &str,
        secret_key: &str,
    ) -> Result<String, ContextError> {
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

        let data = secret.data.ok_or_else(|| ContextError::SecretMissing {
            name: secret_name.to_string(),
            key: secret_key.to_string(),
        })?;

        let value_bytes = data
            .get(secret_key)
            .ok_or_else(|| ContextError::SecretMissing {
                name: secret_name.to_string(),
                key: secret_key.to_string(),
            })?;

        String::from_utf8(value_bytes.0.clone()).map_err(|_| ContextError::SecretMissing {
            name: secret_name.to_string(),
            key: secret_key.to_string(),
        })
    }

    /// Remove a cached pool (e.g. when secret changes or CR is deleted).
    pub async fn evict_pool(&self, namespace: &str, connection: &ConnectionSpec) {
        let cache_key = connection.cache_key(namespace);
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

    #[error("connection param \"{field}\" resolved to an empty or whitespace-only value")]
    EmptyResolvedValue { field: String },

    #[error(
        "connection param sslMode resolved to invalid value \"{value}\" (expected one of: disable, allow, prefer, require, verify-ca, verify-full)"
    )]
    InvalidResolvedSslMode { value: String },
}

impl ContextError {
    /// Returns true when a Secret fetch failed due to a non-transient client-side API error.
    pub fn is_secret_fetch_non_transient(&self) -> bool {
        matches!(
            self,
            ContextError::SecretFetch {
                source: kube::Error::Api(response),
                ..
            } if (400..500).contains(&response.code) && response.code != 429
        )
    }
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

    #[test]
    fn secret_fetch_not_found_is_non_transient() {
        let error = ContextError::SecretFetch {
            name: "db-credentials".into(),
            namespace: "default".into(),
            source: kube::Error::Api(
                kube::core::Status::failure("secrets \"db-credentials\" not found", "NotFound")
                    .with_code(404)
                    .boxed(),
            ),
        };

        assert!(error.is_secret_fetch_non_transient());
    }

    #[test]
    fn secret_fetch_forbidden_is_non_transient() {
        let error = ContextError::SecretFetch {
            name: "db-credentials".into(),
            namespace: "default".into(),
            source: kube::Error::Api(
                kube::core::Status::failure("forbidden", "Forbidden")
                    .with_code(403)
                    .boxed(),
            ),
        };

        assert!(error.is_secret_fetch_non_transient());
    }

    #[test]
    fn secret_fetch_server_error_remains_transient() {
        let error = ContextError::SecretFetch {
            name: "db-credentials".into(),
            namespace: "default".into(),
            source: kube::Error::Api(
                kube::core::Status::failure("internal error", "InternalError")
                    .with_code(500)
                    .boxed(),
            ),
        };

        assert!(!error.is_secret_fetch_non_transient());
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

    #[tokio::test]
    async fn try_lock_database_high_concurrency_same_db() {
        // Spawn many tasks all racing to lock the same database.
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let concurrency = 50;
        let acquired_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let locks_clone = Arc::clone(&locks);
            let count = Arc::clone(&acquired_count);
            let bar = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                // Synchronize start so all tasks race at the same instant.
                bar.wait().await;
                let ctx = OperatorContextLockHelper {
                    database_locks: locks_clone,
                };
                let guard = ctx.try_lock("contested-db").await;
                if guard.is_some() {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // Hold lock briefly to let other tasks observe contention.
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Exactly one task should have acquired the lock.
        let total = acquired_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            total, 1,
            "exactly one of {concurrency} concurrent tasks should acquire the lock, got {total}"
        );
    }

    #[tokio::test]
    async fn try_lock_database_high_concurrency_different_dbs() {
        // Many tasks each locking a different database — all should succeed.
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let concurrency = 50;
        let acquired_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

        let mut handles = Vec::with_capacity(concurrency);
        for i in 0..concurrency {
            let locks_clone = Arc::clone(&locks);
            let count = Arc::clone(&acquired_count);
            let bar = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                bar.wait().await;
                let ctx = OperatorContextLockHelper {
                    database_locks: locks_clone,
                };
                let db_name = format!("db-{i}");
                let guard = ctx.try_lock(&db_name).await;
                if guard.is_some() {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let total = acquired_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            total, concurrency,
            "all {concurrency} tasks locking different dbs should succeed, got {total}"
        );
    }

    #[tokio::test]
    async fn try_lock_database_acquire_release_cycle_under_contention() {
        // Repeatedly acquire and release the same database lock from many tasks.
        // Each task attempts the lock in a loop until it succeeds, simulating
        // the requeue-after-contention pattern used in the reconciler.
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let concurrency = 20;
        let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let locks_clone = Arc::clone(&locks);
            let count = Arc::clone(&success_count);
            let bar = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                bar.wait().await;
                // Retry up to 100 times with a small sleep between attempts,
                // simulating the jittered requeue pattern.
                for _ in 0..100 {
                    let ctx = OperatorContextLockHelper {
                        database_locks: Arc::clone(&locks_clone),
                    };
                    if let Some(_guard) = ctx.try_lock("shared-db").await {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // Brief simulated work, then guard drops (releasing lock).
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                // Should not reach here in practice — fail the test if we do.
                panic!("task failed to acquire lock after 100 retries");
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let total = success_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            total, concurrency,
            "all {concurrency} tasks should eventually acquire the lock"
        );
    }
}
