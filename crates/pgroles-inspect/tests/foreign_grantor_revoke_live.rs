//! Live coverage for the foreign-grantor revoke preflight.
//!
//! PostgreSQL's REVOKE removes only ACL entries whose grantor the executor
//! can act as, and a REVOKE matching none of them succeeds silently — no
//! error, no warning. A privilege granted onward by a delegate
//! (`WITH GRANT OPTION`) therefore survives the executor's revoke and the
//! same drift re-plans forever. The preflight must name exactly the entries
//! that would survive, per grantor, and stay quiet for executors that can
//! reach every grantor.
//!
//! Requires DATABASE_URL (superuser); run with `cargo test -- --include-ignored`.

use std::collections::BTreeSet;
use std::str::FromStr;

use sqlx::postgres::PgConnectOptions;
use sqlx::{Executor, PgPool};

use pgroles_core::diff::Change;
use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::{Grantee, RoleGraph};
use pgroles_inspect::{AuthorityIssue, preflight_authority_issues};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(future)
}

/// Drop-guard removing the test objects and roles even on panic.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                let _ = pool.execute("DROP TABLE IF EXISTS fgr_t").await;
                for role in ["fgr_exec", "fgr_grantee", "fgr_delegate", "fgr_owner"] {
                    let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

fn revoke_select() -> Vec<Change> {
    vec![Change::Revoke {
        role: Grantee::Role("fgr_grantee".to_string()),
        object_type: ObjectType::Table,
        schema: Some("public".to_string()),
        name: Some("fgr_t".to_string()),
        privileges: BTreeSet::from([Privilege::Select]),
    }]
}

fn foreign_grantor_issues(issues: &[AuthorityIssue]) -> Vec<&AuthorityIssue> {
    issues
        .iter()
        .filter(|issue| matches!(issue, AuthorityIssue::ForeignGrantorRevoke { .. }))
        .collect()
}

#[test]
#[ignore]
fn preflight_names_acl_entries_the_executor_cannot_revoke() {
    let _cleanup = Cleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        pool.execute(
            "DROP TABLE IF EXISTS fgr_t; \
             DROP ROLE IF EXISTS fgr_exec; DROP ROLE IF EXISTS fgr_grantee; \
             DROP ROLE IF EXISTS fgr_delegate; DROP ROLE IF EXISTS fgr_owner; \
             CREATE ROLE fgr_owner; CREATE ROLE fgr_delegate; CREATE ROLE fgr_grantee; \
             CREATE ROLE fgr_exec LOGIN PASSWORD 'fgr_exec_pw'; \
             CREATE TABLE fgr_t(i int); ALTER TABLE fgr_t OWNER TO fgr_owner; \
             SET ROLE fgr_owner; \
             GRANT SELECT ON fgr_t TO fgr_grantee; \
             GRANT SELECT ON fgr_t TO fgr_exec WITH GRANT OPTION; \
             GRANT SELECT ON fgr_t TO fgr_delegate WITH GRANT OPTION; \
             RESET ROLE; \
             SET ROLE fgr_delegate; \
             GRANT SELECT ON fgr_t TO fgr_grantee; \
             RESET ROLE;",
        )
        .await
        .expect("setup should succeed");

        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("fgr_exec")
            .password("fgr_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");

        // The executor holds its own grant option but is a member of neither
        // grantor: both the owner-granted and the delegate-granted entries
        // for fgr_grantee are out of reach and must be reported.
        let issues =
            preflight_authority_issues(&exec_pool, &revoke_select(), &RoleGraph::default())
                .await
                .expect("preflight should run");
        let foreign = foreign_grantor_issues(&issues);
        assert_eq!(foreign.len(), 1, "one issue per grantee group: {issues:?}");
        let AuthorityIssue::ForeignGrantorRevoke {
            grantee,
            skipped_count,
            examples,
            ..
        } = foreign[0]
        else {
            unreachable!()
        };
        assert_eq!(grantee, "fgr_grantee");
        assert_eq!(*skipped_count, 2, "owner- and delegate-granted entries");
        let grantors: BTreeSet<&str> = examples
            .iter()
            .map(|(_, grantor)| grantor.as_str())
            .collect();
        assert_eq!(grantors, BTreeSet::from(["fgr_owner", "fgr_delegate"]));

        // Membership in the owner brings the owner-granted entry into reach;
        // the delegate-granted one alone survives and stays reported.
        pool.execute("GRANT fgr_owner TO fgr_exec")
            .await
            .expect("grant should succeed");
        let issues =
            preflight_authority_issues(&exec_pool, &revoke_select(), &RoleGraph::default())
                .await
                .expect("preflight should run");
        let foreign = foreign_grantor_issues(&issues);
        assert_eq!(
            foreign.len(),
            1,
            "delegate entry still unreachable: {issues:?}"
        );
        let AuthorityIssue::ForeignGrantorRevoke {
            skipped_count,
            examples,
            ..
        } = foreign[0]
        else {
            unreachable!()
        };
        assert_eq!(*skipped_count, 1);
        assert_eq!(
            examples,
            &[("fgr_t".to_string(), "fgr_delegate".to_string())]
        );

        // A superuser executor can act as every grantor: no issue.
        let issues = preflight_authority_issues(&pool, &revoke_select(), &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            foreign_grantor_issues(&issues).is_empty(),
            "superuser must not be flagged: {issues:?}"
        );
    });
}
