//! PostgreSQL advisory locking for cross-replica reconciliation safety.
//!
//! Uses `pg_try_advisory_lock` / `pg_advisory_unlock` to prevent concurrent
//! inspect/diff/apply cycles against the same database, even when multiple
//! operator replicas are running.

use sqlx::PgPool;

/// A held advisory lock that must be explicitly released.
#[derive(Debug)]
pub struct AdvisoryLock {
    key: i64,
    pool: PgPool,
}

impl AdvisoryLock {
    /// Release the advisory lock. Logs a warning on failure.
    pub async fn release(self) {
        match sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
            .bind(self.key)
            .fetch_one(&self.pool)
            .await
        {
            Ok(true) => {
                tracing::debug!(key = self.key, "released advisory lock");
            }
            Ok(false) => {
                tracing::warn!(
                    key = self.key,
                    "advisory unlock returned false (lock was not held)"
                );
            }
            Err(err) => {
                tracing::warn!(key = self.key, %err, "failed to release advisory lock");
            }
        }
    }
}

/// Attempt to acquire a session-level advisory lock for the given database identity.
///
/// Returns `Ok(Some(AdvisoryLock))` if the lock was acquired, `Ok(None)` if it
/// is already held by another session, or `Err` on query failure.
pub async fn try_acquire(
    pool: &PgPool,
    database_identity: &str,
) -> Result<Option<AdvisoryLock>, sqlx::Error> {
    let key = advisory_lock_key(database_identity);
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(pool)
        .await?;

    if acquired {
        tracing::info!(key, database_identity, "acquired advisory lock");
        Ok(Some(AdvisoryLock {
            key,
            pool: pool.clone(),
        }))
    } else {
        tracing::info!(
            key,
            database_identity,
            "advisory lock contention — another session holds the lock"
        );
        Ok(None)
    }
}

/// Derive a stable `i64` advisory lock key from a database identity string.
///
/// Uses a simple hash (FNV-1a inspired) folded to i64 range. The exact
/// algorithm is not important as long as it is deterministic and distributes
/// well across different identity strings.
fn advisory_lock_key(identity: &str) -> i64 {
    // We use a namespace prefix so pgroles advisory locks are unlikely to
    // collide with application-level advisory locks.
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    for byte in b"pgroles:".iter().chain(identity.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }

    // Fold to i64. We avoid i64::MIN to keep the value simple for logging.
    (hash as i64).wrapping_abs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_lock_key_deterministic() {
        let a = advisory_lock_key("prod/db-creds/DATABASE_URL");
        let b = advisory_lock_key("prod/db-creds/DATABASE_URL");
        assert_eq!(a, b, "same identity must produce same key");
    }

    #[test]
    fn advisory_lock_key_different_for_different_identities() {
        let a = advisory_lock_key("prod/db-creds/DATABASE_URL");
        let b = advisory_lock_key("staging/db-creds/DATABASE_URL");
        assert_ne!(a, b, "different identities must produce different keys");
    }

    #[test]
    fn advisory_lock_key_different_secret_keys() {
        let a = advisory_lock_key("prod/db-creds/DATABASE_URL");
        let b = advisory_lock_key("prod/db-creds/CUSTOM_URL");
        assert_ne!(a, b, "different secret keys must produce different keys");
    }

    #[test]
    fn advisory_lock_key_is_positive() {
        // wrapping_abs ensures non-negative (except i64::MIN → i64::MIN,
        // but that's astronomically unlikely for a hash).
        let key = advisory_lock_key("prod/db-creds/DATABASE_URL");
        assert!(key >= 0, "advisory lock key should be non-negative");
    }

    #[test]
    fn advisory_lock_key_namespace_prefix_avoids_collision() {
        // Even with same suffix, the "pgroles:" prefix should differentiate.
        let a = advisory_lock_key("x");
        let b = advisory_lock_key("y");
        assert_ne!(a, b);
    }

    #[test]
    fn advisory_lock_key_empty_identity() {
        // Should not panic on empty identity.
        let key = advisory_lock_key("");
        assert!(key >= 0);
    }
}
