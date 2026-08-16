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

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

// One test, both directions in sequence: the harness runs tests in one binary
// in parallel, and with a canonical key two concurrent tests against the same
// database would contend with *each other* — the first acquire below would
// flake on whichever test ran second.
#[tokio::test]
#[ignore]
async fn the_canonical_key_contends_within_and_not_across_databases() {
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
