//! Integration test for `connection.params.setRole`.
//!
//! Run with a live PostgreSQL:
//!
//! ```text
//! DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test \
//!     cargo test -p pgroles-operator --test set_role_integration -- --ignored
//! ```
//!
//! The test creates a low-privilege login role and a privileged role that
//! holds `CREATEROLE`, grants the privileged role to the low-privilege role,
//! and then exercises a `CREATE ROLE` statement that is **only permitted
//! when `SET ROLE` is applied**. Two pools are constructed:
//!
//! 1. **without** the `after_connect` hook — `CREATE ROLE` must fail with
//!    `permission denied`.
//! 2. **with** the hook (using the operator's `build_set_role_stmt` helper) —
//!    the same statement must succeed.
//!
//! Together these two assertions prove that the privileged operation only
//! works when the `SET ROLE` plumbing is in effect.

use pgroles_operator::context::build_set_role_stmt;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{ConnectOptions, Executor, Row};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}

async fn superuser_pool() -> PgPool {
    PgPool::connect(&database_url())
        .await
        .expect("failed to connect to live test database as superuser")
}

/// Build connect options for the low-privilege role by overriding username
/// and password on the base `DATABASE_URL`.
fn low_priv_options(low_user: &str, low_password: &str) -> PgConnectOptions {
    PgConnectOptions::from_str(&database_url())
        .expect("DATABASE_URL must parse as Postgres connect options")
        .username(low_user)
        .password(low_password)
        // Quiet the per-statement INFO logs that sqlx emits at debug.
        .log_statements(tracing::log::LevelFilter::Off)
}

#[tokio::test]
#[ignore]
async fn set_role_grants_create_role_privilege_to_low_priv_user() {
    let suffix = unique_suffix();
    let low_user = format!("pgr_setrole_low_{suffix}");
    let high_role = format!("pgr_setrole_high_{suffix}");
    let target_role = format!("pgr_setrole_target_{suffix}");
    let low_password = "low_priv_password";

    let admin = superuser_pool().await;

    // Setup: create a low-privilege LOGIN role and a privileged role with
    // CREATEROLE, then grant the privileged role to the low-privilege one.
    // NOINHERIT on the low role ensures attribute privileges of `high_role`
    // are never available unless `SET ROLE` is explicitly invoked.
    let setup_sql = format!(
        r#"
        DROP ROLE IF EXISTS "{target_role}";
        DROP ROLE IF EXISTS "{low_user}";
        DROP ROLE IF EXISTS "{high_role}";
        CREATE ROLE "{high_role}" CREATEROLE NOINHERIT;
        CREATE ROLE "{low_user}" LOGIN NOINHERIT PASSWORD '{low_password}';
        GRANT "{high_role}" TO "{low_user}";
        "#
    );
    admin
        .execute(setup_sql.as_str())
        .await
        .expect("failed to set up test roles");

    // Pool 1 — no SET ROLE hook. `CREATE ROLE` must fail.
    let plain_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(low_priv_options(&low_user, low_password))
        .await
        .expect("low-priv pool without SET ROLE should still be able to connect");

    let create_without_set_role = plain_pool
        .execute(format!(r#"CREATE ROLE "{target_role}""#).as_str())
        .await;
    assert!(
        create_without_set_role.is_err(),
        "CREATE ROLE must fail when SET ROLE is NOT applied (got: {:?})",
        create_without_set_role,
    );
    if let Err(err) = &create_without_set_role {
        let msg = err.to_string();
        assert!(
            msg.contains("permission denied"),
            "expected permission denied error, got: {msg}",
        );
    }
    drop(plain_pool);

    // Pool 2 — same low-priv connection, but with the operator's
    // `after_connect` hook running `SET ROLE "<high_role>"`. The same
    // `CREATE ROLE` statement must now succeed.
    let high_role_for_hook = high_role.clone();
    let set_role_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(move |conn, _meta| {
            let stmt = build_set_role_stmt(&high_role_for_hook);
            Box::pin(async move {
                sqlx::Executor::execute(&mut *conn, stmt.as_str()).await?;
                Ok(())
            })
        })
        .connect_with(low_priv_options(&low_user, low_password))
        .await
        .expect("low-priv pool with SET ROLE hook should connect");

    // Sanity: confirm the hook actually flipped the effective role.
    let effective: String = sqlx::query("SELECT current_user::text AS u")
        .fetch_one(&set_role_pool)
        .await
        .expect("should be able to read current_user")
        .get("u");
    assert_eq!(
        effective, high_role,
        "after_connect hook must make current_user = high_role"
    );

    set_role_pool
        .execute(format!(r#"CREATE ROLE "{target_role}""#).as_str())
        .await
        .expect("CREATE ROLE must succeed once SET ROLE is applied");

    // Confirm the role really exists.
    let exists: bool = sqlx::query("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
        .bind(&target_role)
        .fetch_one(&admin)
        .await
        .expect("should be able to query pg_roles")
        .get(0);
    assert!(exists, "target role should have been created");

    drop(set_role_pool);

    // Cleanup.
    let cleanup_sql = format!(
        r#"
        DROP ROLE IF EXISTS "{target_role}";
        DROP ROLE IF EXISTS "{low_user}";
        DROP ROLE IF EXISTS "{high_role}";
        "#
    );
    admin
        .execute(cleanup_sql.as_str())
        .await
        .expect("failed to clean up test roles");
}
