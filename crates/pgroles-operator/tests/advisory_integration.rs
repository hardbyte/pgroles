//! Integration test for the canonical (server-side) advisory lock key.
//!
//! Run with a live PostgreSQL:
//!
//! ```text
//! DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test \
//!     cargo test -p pgroles-operator --test advisory_integration -- --ignored
//! ```
//!
//! The advisory lock key is computed server-side from `current_database()`,
//! not from the client-side `DatabaseIdentity` string. Two pools connected to
//! the same database — simulating two different Kubernetes Secret coordinates
//! naming the same physical database — must therefore contend on the same
//! lock even though their identity strings differ.

use pgroles_operator::advisory;
use sqlx::PgPool;
use std::sync::LazyLock;
use tokio::sync::Mutex;

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

/// Every test in this file takes the lock the tests are *about*, and the key is
/// canonical per database — so two of them running concurrently contend with
/// each other and whichever ran second would fail its very first acquire. The
/// harness runs a binary's tests in parallel by default, so they serialize here
/// rather than relying on the caller passing `--test-threads=1`.
static ONE_AT_A_TIME: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[tokio::test]
#[ignore]
async fn the_canonical_key_contends_within_and_not_across_databases() {
    let _serial = ONE_AT_A_TIME.lock().await;

    // Two separate pools to the same database, as if resolved through two
    // different Secrets.
    let pool_a = PgPool::connect(&database_url())
        .await
        .expect("failed to connect pool_a to live test database");
    let pool_b = PgPool::connect(&database_url())
        .await
        .expect("failed to connect pool_b to live test database");

    // Session A acquires the lock under one identity string.
    let lock_a = advisory::try_acquire(&pool_a, "ns/secret-a/KEY")
        .await
        .expect("advisory acquire on pool_a must not error")
        .expect("first acquire must succeed — no one else holds the lock");

    // Session B, under a *different* identity string but connected to the
    // same database, must collide: the key is canonical because the server
    // computes it from current_database().
    let contended = advisory::try_acquire(&pool_b, "ns/secret-b/OTHER")
        .await
        .expect("advisory acquire on pool_b must not error");
    assert!(
        contended.is_none(),
        "second session must see contention despite a different identity string"
    );

    // Release the first lock; the second acquire must now succeed.
    lock_a.release().await;

    let lock_b = advisory::try_acquire(&pool_b, "ns/secret-b/OTHER")
        .await
        .expect("advisory acquire on pool_b must not error after release")
        .expect("acquire must succeed once the first lock is released");

    // The negative direction: a key that ignored `current_database()` — a
    // constant, say — would pass the contention assertions above while
    // serializing every database in the cluster behind one lock. A different
    // database on the same server must hold its lock concurrently with ours.
    // The maintenance database always exists beside the test database.
    let other = database_url()
        .rsplit_once('/')
        .map(|(prefix, _)| format!("{prefix}/postgres"))
        .expect("DATABASE_URL must name a database");
    let pool_c = PgPool::connect(&other)
        .await
        .expect("failed to connect pool_c to the postgres database");
    let lock_c = advisory::try_acquire(&pool_c, "ns/secret-c/KEY")
        .await
        .expect("advisory acquire on pool_c must not error")
        .expect("a different database must not contend on the same key");

    lock_b.release().await;
    lock_c.release().await;
}

/// Dropping a lock without releasing it must not strand the session lock.
///
/// `release()` is async, so `Drop` cannot call it; the ways to get here are a
/// cancelled reconcile — controller shutdown, or a timeout wrapped around the
/// locked phase — and a future refactor that adds an early return between
/// acquire and release. The dangerous outcome would be sqlx handing the
/// connection back to the pool with the lock still held: the next checkout
/// would re-enter the lock as its own while every other session stayed blocked
/// out until `max_lifetime` recycled it. `Drop` detaches and closes instead,
/// and closing the socket is what makes PostgreSQL free the session's locks.
///
/// The assertion is deliberately made from a *separate* pool. Checking that
/// the same pool can re-acquire would pass even in the broken case, because
/// re-entering one's own session lock succeeds.
#[tokio::test]
#[ignore]
async fn a_dropped_lock_frees_the_session_lock_for_other_sessions() {
    let _serial = ONE_AT_A_TIME.lock().await;

    let holder = PgPool::connect(&database_url())
        .await
        .expect("failed to connect the holding pool");
    let observer = PgPool::connect(&database_url())
        .await
        .expect("failed to connect the observing pool");

    let lock = advisory::try_acquire(&holder, "ns/dropped/KEY")
        .await
        .expect("advisory acquire must not error")
        .expect("first acquire must succeed");

    // Precondition: while held, another session genuinely cannot take it —
    // otherwise the release assertion below would prove nothing.
    assert!(
        advisory::try_acquire(&observer, "ns/observer/KEY")
            .await
            .expect("advisory acquire must not error")
            .is_none(),
        "another session must not acquire a held lock"
    );

    drop(lock);

    // The close is dispatched onto the runtime by `Drop`, so give the server a
    // moment to notice the socket going away before concluding it is stuck.
    let freed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(acquired) = advisory::try_acquire(&observer, "ns/observer/KEY")
                .await
                .expect("advisory acquire must not error")
            {
                return acquired;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("a dropped lock must free its session lock for other sessions");

    freed.release().await;
}
