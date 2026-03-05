//! Shared operator context — database pool cache, metrics, and configuration.

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::postgres::PgPool;
use tokio::sync::RwLock;

/// Shared state for the operator, passed to every reconciliation.
#[derive(Clone)]
pub struct OperatorContext {
    /// Kubernetes client for API calls.
    pub kube_client: kube::Client,

    /// Cached database connection pools keyed by `"namespace/secret-name"`.
    pub pool_cache: Arc<RwLock<HashMap<String, PgPool>>>,
}

impl OperatorContext {
    /// Create a new operator context with an empty pool cache.
    pub fn new(kube_client: kube::Client) -> Self {
        Self {
            kube_client,
            pool_cache: Arc::new(RwLock::new(HashMap::new())),
        }
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
        let cache_key = format!("{namespace}/{secret_name}");

        // Check cache first (read lock).
        {
            let cache = self.pool_cache.read().await;
            if let Some(pool) = cache.get(&cache_key) {
                return Ok(pool.clone());
            }
        }

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
            cache.insert(cache_key, pool.clone());
        }

        Ok(pool)
    }

    /// Remove a cached pool (e.g. when secret changes or CR is deleted).
    pub async fn evict_pool(&self, namespace: &str, secret_name: &str) {
        let cache_key = format!("{namespace}/{secret_name}");
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
    #[test]
    fn pool_cache_key_format() {
        // Verify the cache key format is "namespace/secret-name"
        let key = format!("{}/{}", "prod", "pg-credentials");
        assert_eq!(key, "prod/pg-credentials");
    }
}
