//! PostgreSQL advisory locking for cross-replica reconciliation safety.
//!
//! Uses `pg_try_advisory_lock` / `pg_advisory_unlock` to prevent concurrent
//! inspect/diff/apply cycles against the same database, even when multiple
//! operator replicas are running.
//!
//! The lock key is computed **server-side**, on the very connection that will
//! take the lock:
//!
//! ```sql
//! SELECT hashtextextended('pgroles-reconcile:' || current_database(), 0)
//! ```
//!
//! Server-side keying is what makes the key canonical. A client-side key
//! derived from how the operator *names* a database (Secret coordinates,
//! hostnames, connection strings) would give the same physical database a
//! different key for every alias — two Secrets pointing at one database, a
//! CNAME versus the raw host, a pooler in front of the server — and each
//! alias would sail past the others' locks. `current_database()` is evaluated
//! by the server itself, so any two sessions connected to the same database
//! compute the same key regardless of the client-side path that got them
//! there, and they contend on the same lock.
//!
//! Session-level advisory locks are bound to the connection that acquired
//! them, so this module checks out a dedicated [`PoolConnection`] and holds it
//! for the lifetime of the lock. Key computation, acquire, and release all
//! execute on that same underlying database session.

use sqlx::pool::PoolConnection;
use sqlx::{Connection, PgPool, Postgres};

/// A held advisory lock that must be explicitly released.
///
/// Holds a dedicated [`PoolConnection`] so that the lock acquire and release
/// always run on the same PostgreSQL session (advisory locks are
/// session-scoped).
pub struct AdvisoryLock {
    key: i64,
    /// `None` once [`AdvisoryLock::release`] has taken the connection, which
    /// is what tells [`Drop`] there is nothing left to make safe.
    conn: Option<PoolConnection<Postgres>>,
}

impl AdvisoryLock {
    /// Release the advisory lock. Logs a warning on failure.
    ///
    /// The unlock runs on the same connection that acquired the lock, ensuring
    /// `pg_advisory_unlock` targets the correct session.
    pub async fn release(mut self) {
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        match sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
            .bind(self.key)
            .fetch_one(&mut *conn)
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
        // `conn` is returned to the pool here, with the lock released.
    }
}

/// Last-resort safety net for a lock that was never released.
///
/// `release()` is async, so it cannot be called from `Drop`; the only ways to
/// get here are a cancelled reconcile future (controller shutdown, a timeout
/// wrapped around the locked phase) or a future refactor that adds an early
/// return between acquire and release. Simply dropping the [`PoolConnection`]
/// would be the dangerous outcome: sqlx hands that connection *back to the
/// pool* with the session-level lock still held, so the next reconcile to
/// check it out would re-enter the lock as its own while every other session
/// stays blocked out until `max_lifetime` recycles it. Detaching the
/// connection instead takes it out of the pool for good, and closing the
/// socket is what makes PostgreSQL drop the session's advisory locks.
impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else {
            return;
        };
        tracing::warn!(
            key = self.key,
            "advisory lock dropped without release — closing its connection so PostgreSQL frees \
             the session lock instead of returning a locked session to the pool"
        );
        let detached = conn.detach();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(err) = detached.close().await {
                        tracing::warn!(%err, "failed to close a leaked advisory-lock connection");
                    }
                });
            }
            // No runtime to close politely on (process shutdown): dropping the
            // detached connection closes the socket, which is enough for the
            // server to release the lock.
            Err(_) => drop(detached),
        }
    }
}

/// Attempt to acquire a session-level advisory lock on the connected database.
///
/// Checks out a dedicated connection from the pool, computes the canonical
/// lock key **on that connection** via
/// `hashtextextended('pgroles-reconcile:' || current_database(), 0)`
/// (`hashtextextended` exists since PostgreSQL 11; the project requires 16+;
/// negative keys are fine for `pg_try_advisory_lock`), and then executes
/// `pg_try_advisory_lock` on the same connection. If the lock is acquired, the
/// connection is kept inside the returned [`AdvisoryLock`] so that both
/// acquire and release run on the same session.
///
/// `database_identity` is logging context only — the key derives entirely from
/// the server's own `current_database()`, so differently-named identities that
/// reach the same database contend on the same key.
///
/// Returns `Ok(Some(AdvisoryLock))` if the lock was acquired, `Ok(None)` if it
/// is already held by another session, or `Err` on query failure.
pub async fn try_acquire(
    pool: &PgPool,
    database_identity: &str,
) -> Result<Option<AdvisoryLock>, sqlx::Error> {
    let mut conn = pool.acquire().await?;

    let key: i64 = sqlx::query_scalar(
        "SELECT hashtextextended('pgroles-reconcile:' || current_database(), 0)",
    )
    .fetch_one(&mut *conn)
    .await?;

    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *conn)
        .await?;

    if acquired {
        tracing::info!(key, database_identity, "acquired advisory lock");
        Ok(Some(AdvisoryLock {
            key,
            conn: Some(conn),
        }))
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
