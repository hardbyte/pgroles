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

#[tokio::test]
#[ignore]
async fn differently_named_identities_contend_on_the_same_canonical_key() {
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
    lock_b.release().await;
}
