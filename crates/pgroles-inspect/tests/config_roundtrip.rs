//! Live round-trip test for role configuration defaults.
//!
//! Exercises the full pipeline against a real PostgreSQL server:
//! manifest → expand → diff → SQL → execute → inspect → diff again.
//! This is the coverage that catches version- or quoting-dependent drift
//! in how `pg_roles.rolconfig` stores values (e.g. list-typed settings set
//! from a single literal come back double-quoted), which unit tests with
//! hand-written rolconfig fixtures cannot see.
//!
//! Requires DATABASE_URL; run with `cargo test -- --include-ignored`.

use sqlx::{Executor, PgPool};

use pgroles_core::diff::diff;
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::RoleGraph;
use pgroles_core::sql::render_statements;
use pgroles_inspect::{InspectConfig, inspect};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos()
}

fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(future)
}

async fn execute_all(pool: &PgPool, statements: &[String]) {
    for statement in statements {
        pool.execute(statement.as_str())
            .await
            .unwrap_or_else(|error| panic!("failed to execute `{statement}`: {error}"));
    }
}

struct RoleCleanup {
    roles: Vec<String>,
}

impl Drop for RoleCleanup {
    fn drop(&mut self) {
        let roles = self.roles.clone();
        with_runtime(async move {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect for cleanup");
            for role in roles {
                let _ = pool
                    .execute(format!(r#"DROP ROLE IF EXISTS "{role}";"#).as_str())
                    .await;
            }
        });
    }
}

#[test]
#[ignore]
fn role_config_converges_and_detects_drift() {
    let suffix = unique_suffix();
    let blue = format!("cfg_blue_{suffix}");
    let green = format!("cfg_green_{suffix}");
    let combined = format!("cfg_combined_{suffix}");
    let _cleanup = RoleCleanup {
        roles: vec![blue.clone(), green.clone(), combined.clone()],
    };

    // The issue-132 blue/green pattern, plus a list-valued setting written
    // in the form PostgreSQL re-quotes on storage.
    let yaml = format!(
        r#"
roles:
  - name: {combined}
  - name: {blue}
    login: true
    config:
      role: {combined}
      search_path: "app, public"
  - name: {green}
    login: true
    config:
      role: {combined}

memberships:
  - role: {combined}
    members:
      - name: {blue}
      - name: {green}
"#
    );

    let manifest = parse_manifest(&yaml).expect("manifest should parse");
    let expanded = expand_manifest(&manifest).expect("manifest should expand");
    let desired = RoleGraph::from_expanded(&expanded, None).expect("graph should build");
    let config = InspectConfig::from_expanded(&expanded, false);

    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect to live test database");

        // Fresh state: plan creates everything, including config alters.
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(!changes.is_empty(), "fresh plan should not be empty");
        let statements: Vec<String> = changes.iter().flat_map(render_statements).collect();
        execute_all(&pool, &statements).await;

        // Converged: a re-inspect must produce an empty plan. This is the
        // no-flapping property — if rolconfig normalization ever disagrees
        // with what we applied, this assertion catches it.
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(
            changes.is_empty(),
            "expected converged state, got: {changes:?}"
        );

        // Drift both ways: green loses its setting, blue gains a stray one.
        execute_all(
            &pool,
            &[
                format!(r#"ALTER ROLE "{green}" RESET "role";"#),
                format!(r#"ALTER ROLE "{blue}" SET "statement_timeout" = '10s';"#),
            ],
        )
        .await;

        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        let statements: Vec<String> = changes.iter().flat_map(render_statements).collect();
        assert!(
            statements
                .iter()
                .any(|s| s == &format!(r#"ALTER ROLE "{green}" SET "role" = '{combined}';"#)),
            "expected drift plan to restore green's role setting, got: {statements:?}"
        );
        assert!(
            statements
                .iter()
                .any(|s| s == &format!(r#"ALTER ROLE "{blue}" RESET "statement_timeout";"#)),
            "expected drift plan to reset blue's stray setting, got: {statements:?}"
        );

        // Applying the drift plan converges again.
        execute_all(&pool, &statements).await;
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(
            changes.is_empty(),
            "expected re-converged state, got: {changes:?}"
        );
    });
}
