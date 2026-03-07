//! PostgreSQL advisory locking for cross-replica reconciliation safety.
//!
//! Uses `pg_try_advisory_lock` / `pg_advisory_unlock` to prevent concurrent
//! inspect/diff/apply cycles against the same database, even when multiple
//! operator replicas are running.
//!
//! Session-level advisory locks are bound to the connection that acquired them,
//! so this module checks out a dedicated [`PoolConnection`] and holds it for
//! the lifetime of the lock. Both acquire and release execute on the same
//! underlying database session.

use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};

/// A held advisory lock that must be explicitly released.
///
/// Holds a dedicated [`PoolConnection`] so that the lock acquire and release
/// always run on the same PostgreSQL session (advisory locks are
/// session-scoped).
pub struct AdvisoryLock {
    key: i64,
    conn: PoolConnection<Postgres>,
}

impl AdvisoryLock {
    /// Release the advisory lock. Logs a warning on failure.
    ///
    /// The unlock runs on the same connection that acquired the lock, ensuring
    /// `pg_advisory_unlock` targets the correct session.
    pub async fn release(mut self) {
        match sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
            .bind(self.key)
            .fetch_one(&mut *self.conn)
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
        // `self.conn` is returned to the pool on drop.
    }
}

/// Attempt to acquire a session-level advisory lock for the given database identity.
///
/// Checks out a dedicated connection from the pool and executes
/// `pg_try_advisory_lock` on it. If the lock is acquired, the connection is
/// kept inside the returned [`AdvisoryLock`] so that both acquire and release
/// run on the same session.
///
/// Returns `Ok(Some(AdvisoryLock))` if the lock was acquired, `Ok(None)` if it
/// is already held by another session, or `Err` on query failure.
pub async fn try_acquire(
    pool: &PgPool,
    database_identity: &str,
) -> Result<Option<AdvisoryLock>, sqlx::Error> {
    let key = advisory_lock_key(database_identity);

    let mut conn = pool.acquire().await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *conn)
        .await?;

    if acquired {
        tracing::info!(key, database_identity, "acquired advisory lock");
        Ok(Some(AdvisoryLock { key, conn }))
    } else {
        tracing::info!(
            key,
            database_identity,
            "advisory lock contention — another session holds the lock"
        );
        // `conn` is returned to the pool on drop — no lock was acquired.
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

    // Shift right by 1 to clear the sign bit, guaranteeing a non-negative i64.
    (hash >> 1) as i64
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
        // The `hash >> 1` conversion guarantees a non-negative i64.
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
