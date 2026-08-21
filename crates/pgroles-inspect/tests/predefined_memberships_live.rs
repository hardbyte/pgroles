//! Live end-to-end coverage for memberships granted from predefined (`pg_*`)
//! roles: declared members converge, undeclared members are untouched unless
//! the stanza is `exclusive: true`, plans are idempotent, and the preflight
//! reports missing predefined roles with a version hint.
//!
//! Requires DATABASE_URL; run with `cargo test -- --include-ignored`.

use sqlx::{Executor, PgPool};

use pgroles_core::diff::{
    Change, ReconciliationMode, diff, filter_changes, filter_external_role_changes,
};
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::RoleGraph;
use pgroles_core::sql::render_statements;
use pgroles_inspect::{AuthorityIssue, InspectConfig, inspect, preflight_authority_issues};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(future)
}

/// Drop-guard removing the test roles even on panic.
struct RoleCleanup;

impl Drop for RoleCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                for role in ["predef_auditor", "predef_forgotten"] {
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

async fn plan(pool: &PgPool, manifest_yaml: &str) -> (Vec<Change>, RoleGraph) {
    let manifest = parse_manifest(manifest_yaml).expect("manifest should parse");
    let expanded = expand_manifest(&manifest).expect("manifest should expand");
    let desired = RoleGraph::from_expanded(&expanded, None).expect("desired graph should build");
    let config = InspectConfig::from_expanded(&expanded, false);
    let current = inspect(pool, &config).await.expect("inspection should run");
    let changes = filter_external_role_changes(
        filter_changes(diff(&current, &desired), ReconciliationMode::Authoritative),
        &expanded.roles,
        &expanded.memberships,
    );
    (changes, current)
}

async fn apply(pool: &PgPool, changes: &[Change]) {
    for change in changes {
        for statement in render_statements(change) {
            pool.execute(statement.as_str())
                .await
                .unwrap_or_else(|error| panic!("failed `{statement}`: {error}"));
        }
    }
}

async fn is_member(pool: &PgPool, member: &str) -> bool {
    let (result,): (bool,) = sqlx::query_as("SELECT pg_has_role($1, 'pg_read_all_data', 'MEMBER')")
        .bind(member)
        .fetch_one(pool)
        .await
        .expect("membership probe should run");
    result
}

const DECLARED: &str = r#"
roles:
  - name: predef_auditor
    login: true
  - name: predef_forgotten
    login: true

memberships:
  - role: pg_read_all_data
    members:
      - name: predef_auditor
"#;

const EXCLUSIVE: &str = r#"
roles:
  - name: predef_auditor
    login: true
  - name: predef_forgotten
    login: true

memberships:
  - role: pg_read_all_data
    exclusive: true
    members:
      - name: predef_auditor
"#;

#[test]
#[ignore]
fn predefined_membership_lifecycle_end_to_end() {
    let _cleanup = RoleCleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        for role in ["predef_auditor", "predef_forgotten"] {
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        pool.execute(
            "CREATE ROLE predef_auditor LOGIN; CREATE ROLE predef_forgotten LOGIN; \
             GRANT pg_read_all_data TO predef_forgotten;",
        )
        .await
        .expect("seed should run");

        // 1. Declared member converges; the provider-style grant to
        //    predef_forgotten is untouched.
        let (changes, _) = plan(&pool, DECLARED).await;
        assert!(
            changes.iter().any(|change| matches!(
                change,
                Change::AddMember { role, member, .. }
                    if role == "pg_read_all_data" && member == "predef_auditor"
            )),
            "expected a grant for the declared member, got {changes:?}"
        );
        assert!(
            !changes
                .iter()
                .any(|change| matches!(change, Change::RemoveMember { .. })),
            "undeclared member must not be revoked without exclusive, got {changes:?}"
        );
        apply(&pool, &changes).await;
        assert!(is_member(&pool, "predef_auditor").await);
        assert!(is_member(&pool, "predef_forgotten").await);

        // 2. Idempotent once converged.
        let (changes, _) = plan(&pool, DECLARED).await;
        assert!(changes.is_empty(), "expected no changes, got {changes:?}");

        // 3. `exclusive: true` revokes the undeclared member.
        let (changes, _) = plan(&pool, EXCLUSIVE).await;
        assert_eq!(
            changes,
            vec![Change::RemoveMember {
                role: "pg_read_all_data".to_string(),
                member: "predef_forgotten".to_string(),
            }],
            "exclusive should plan exactly the undeclared revoke"
        );
        apply(&pool, &changes).await;
        assert!(is_member(&pool, "predef_auditor").await);
        assert!(!is_member(&pool, "predef_forgotten").await);

        // 4. Idempotent again.
        let (changes, _) = plan(&pool, EXCLUSIVE).await;
        assert!(changes.is_empty(), "expected no changes, got {changes:?}");
    });
}

#[test]
#[ignore]
fn preflight_reports_missing_predefined_role() {
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        let changes = vec![Change::AddMember {
            role: "pg_role_that_does_not_exist".to_string(),
            member: "whoever".to_string(),
            inherit: true,
            admin: false,
        }];
        let issues = preflight_authority_issues(&pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            issues.iter().any(|issue| matches!(
                issue,
                AuthorityIssue::MissingPredefinedRole { role, .. }
                    if role == "pg_role_that_does_not_exist"
            )),
            "expected a missing-predefined-role issue, got {issues:?}"
        );
    });
}
