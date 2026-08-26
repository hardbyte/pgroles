//! Live coverage for the foreign-grantor revoke preflight.
//!
//! PostgreSQL's REVOKE removes only grants attributed to the revoker — a
//! superuser's revoke acts as the object owner (or, for role memberships,
//! the bootstrap superuser) — and a REVOKE matching no such entry succeeds
//! silently (objects) or with only a WARNING (memberships). A privilege
//! granted onward by a delegate therefore survives everyone's plain revoke,
//! superusers included, and the same drift re-plans forever. The preflight
//! must name exactly the entries that would survive, per grantor.
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
                let _ = pool.execute("DROP TABLE IF EXISTS fgr_t2").await;
                for role in [
                    "fgr_exec",
                    "fgr_grantee",
                    "fgr_delegate",
                    "fgr_delegate2",
                    "fgr_owner",
                ] {
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
        grantor: None,
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

        // A superuser's plain REVOKE is performed as though issued by the
        // owner (verified live): the owner-granted entry is removable, but
        // the delegate-granted one survives even a superuser's revoke and
        // must stay reported.
        let issues = preflight_authority_issues(&pool, &revoke_select(), &RoleGraph::default())
            .await
            .expect("preflight should run");
        let foreign = foreign_grantor_issues(&issues);
        assert_eq!(
            foreign.len(),
            1,
            "delegate entry unremovable even for a superuser: {issues:?}"
        );
        let AuthorityIssue::ForeignGrantorRevoke { examples, .. } = foreign[0] else {
            unreachable!()
        };
        assert_eq!(
            examples,
            &[("fgr_t".to_string(), "fgr_delegate".to_string())],
            "owner-attributed entry must not be flagged for a superuser"
        );

        // Heterogeneous revokes in one schema must not be checked as their
        // cross-product: a foreign-grantor UPDATE entry on fgr_t is untargeted
        // when the plan revokes SELECT on fgr_t and UPDATE on fgr_t2, and must
        // not be reported.
        pool.execute(
            "DROP TABLE IF EXISTS fgr_t2; DROP ROLE IF EXISTS fgr_delegate2; \
             CREATE ROLE fgr_delegate2; \
             CREATE TABLE fgr_t2(i int); ALTER TABLE fgr_t2 OWNER TO fgr_owner; \
             SET ROLE fgr_owner; \
             GRANT UPDATE ON fgr_t TO fgr_delegate2 WITH GRANT OPTION; \
             RESET ROLE; \
             SET ROLE fgr_delegate2; \
             GRANT UPDATE ON fgr_t TO fgr_grantee; \
             RESET ROLE;",
        )
        .await
        .expect("cross-product setup should succeed");
        let mut heterogeneous = revoke_select();
        heterogeneous.push(Change::Revoke {
            grantor: None,
            role: Grantee::Role("fgr_grantee".to_string()),
            object_type: ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("fgr_t2".to_string()),
            privileges: BTreeSet::from([Privilege::Update]),
        });
        let issues = preflight_authority_issues(&exec_pool, &heterogeneous, &RoleGraph::default())
            .await
            .expect("preflight should run");
        let foreign = foreign_grantor_issues(&issues);
        assert_eq!(foreign.len(), 1, "one issue for the grantee: {issues:?}");
        let AuthorityIssue::ForeignGrantorRevoke { examples, .. } = foreign[0] else {
            unreachable!()
        };
        assert_eq!(
            examples,
            &[("fgr_t".to_string(), "fgr_delegate".to_string())],
            "the untargeted UPDATE entry on fgr_t (grantor fgr_delegate2) must not be flagged"
        );
    });
}

/// Drop-guard for the membership-revoke roles.
struct MembershipCleanup;

impl Drop for MembershipCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                for role in ["fgrm_exec", "fgrm_alice", "fgrm_grantor", "fgrm_reader"] {
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

/// Membership revokes are grantor-targeted: the diff carries the inspected
/// edge's grantor and rendering emits `REVOKE ... GRANTED BY`, which requires
/// the privileges of that grantor. The preflight flags exactly the grantors
/// the executor lacks; a superuser has every role's privileges and is never
/// flagged (its GRANTED BY succeeds).
#[test]
#[ignore]
fn preflight_names_membership_grantors_the_executor_lacks() {
    let _cleanup = MembershipCleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        for role in ["fgrm_exec", "fgrm_alice", "fgrm_grantor", "fgrm_reader"] {
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        pool.execute(
            "CREATE ROLE fgrm_reader; CREATE ROLE fgrm_alice; CREATE ROLE fgrm_grantor; \
             CREATE ROLE fgrm_exec LOGIN PASSWORD 'fgrm_exec_pw'; \
             GRANT fgrm_reader TO fgrm_grantor WITH ADMIN OPTION; \
             GRANT fgrm_reader TO fgrm_exec WITH ADMIN OPTION; \
             SET ROLE fgrm_grantor; \
             GRANT fgrm_reader TO fgrm_alice; \
             RESET ROLE;",
        )
        .await
        .expect("setup should succeed");

        let changes = vec![Change::RemoveMember {
            role: "fgrm_reader".to_string(),
            member: "fgrm_alice".to_string(),
            grantor: Some("fgrm_grantor".to_string()),
        }];

        // The executor holds ADMIN OPTION on the role but not the grantor's
        // privileges: its rendered `REVOKE ... GRANTED BY "fgrm_grantor"`
        // would be rejected, so the preflight names the missing grantor.
        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("fgrm_exec")
            .password("fgrm_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");
        let issues = preflight_authority_issues(&exec_pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        let membership: Vec<_> = issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityIssue::ForeignGrantorMembershipRevoke { .. }))
            .collect();
        assert_eq!(membership.len(), 1, "one missing grantor: {issues:?}");
        let AuthorityIssue::ForeignGrantorMembershipRevoke {
            role,
            member,
            grantor,
            ..
        } = membership[0]
        else {
            unreachable!()
        };
        assert_eq!(
            (role.as_str(), member.as_str(), grantor.as_str()),
            ("fgrm_reader", "fgrm_alice", "fgrm_grantor")
        );

        // Membership in the grantor supplies its privileges: no issue, and
        // the rendered GRANTED BY revoke actually removes the edge.
        pool.execute("GRANT fgrm_grantor TO fgrm_exec")
            .await
            .expect("grant should succeed");
        let issues = preflight_authority_issues(&exec_pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            !issues.iter().any(|issue| matches!(
                issue,
                AuthorityIssue::ForeignGrantorMembershipRevoke { .. }
            )),
            "grantor privileges satisfy GRANTED BY: {issues:?}"
        );

        // A superuser holds every role's privileges: never flagged.
        let issues = preflight_authority_issues(&pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            !issues.iter().any(|issue| matches!(
                issue,
                AuthorityIssue::ForeignGrantorMembershipRevoke { .. }
            )),
            "superuser must not be flagged: {issues:?}"
        );
    });
}

struct GapCleanup;

impl Drop for GapCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                for role in ["gap_exec", "gap_alice", "gap_grantor", "gap_reader"] {
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

/// Grantor authority is checked against execution order, not just the current
/// graph: a plan can remove the executor's membership path to a grantor and
/// then need that grantor's privileges later in the same transaction — a
/// `REVOKE ... GRANTED BY` in the removal batch, or an
/// `ALTER DEFAULT PRIVILEGES FOR ROLE` after it. The preflight re-checks
/// those roles against the graph with the plan's removals applied and flags
/// the dependency-breaking plan instead of letting the apply fail mid-way.
#[test]
#[ignore]
fn preflight_flags_grantor_paths_the_plan_itself_removes() {
    let _cleanup = GapCleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        let (version,): (i32,) =
            sqlx::query_as("SELECT current_setting('server_version_num')::int")
                .fetch_one(&pool)
                .await
                .expect("version probe should run");
        if version < 160_000 {
            return;
        }
        for role in ["gap_exec", "gap_alice", "gap_grantor", "gap_reader"] {
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        pool.execute(
            "CREATE ROLE gap_reader; CREATE ROLE gap_alice; CREATE ROLE gap_grantor; \
             CREATE ROLE gap_exec LOGIN PASSWORD 'gap_exec_pw'; \
             GRANT gap_reader TO gap_grantor WITH ADMIN OPTION; \
             SET ROLE gap_grantor; \
             GRANT gap_reader TO gap_alice; \
             RESET ROLE; \
             GRANT gap_grantor TO gap_exec;",
        )
        .await
        .expect("setup should succeed");

        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("gap_exec")
            .password("gap_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");

        // The plan removes the executor's own membership in the grantor and
        // still needs GRANTED BY that grantor in the same removal batch.
        let breaking = vec![
            Change::RemoveMember {
                role: "gap_grantor".to_string(),
                member: "gap_exec".to_string(),
                grantor: None,
            },
            Change::RemoveMember {
                role: "gap_reader".to_string(),
                member: "gap_alice".to_string(),
                grantor: Some("gap_grantor".to_string()),
            },
        ];
        let issues = preflight_authority_issues(&exec_pool, &breaking, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            issues.iter().any(|issue| matches!(
                issue,
                AuthorityIssue::GrantorAuthorityRemovedByPlan { grantor, .. }
                    if grantor == "gap_grantor"
            )),
            "the removed path must be flagged: {issues:?}"
        );

        // Without the path-removing change, the same GRANTED BY revoke is
        // fine against the current graph — no issue.
        let issues = preflight_authority_issues(&exec_pool, &breaking[1..], &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            !issues
                .iter()
                .any(|issue| matches!(issue, AuthorityIssue::GrantorAuthorityRemovedByPlan { .. })),
            "no path is removed: {issues:?}"
        );

        // An ALTER DEFAULT PRIVILEGES FOR ROLE after the removal batch loses
        // the owner's privileges the same way.
        let defaults_breaking = vec![
            Change::RemoveMember {
                role: "gap_grantor".to_string(),
                member: "gap_exec".to_string(),
                grantor: None,
            },
            Change::RevokeDefaultPrivilege {
                owner: "gap_grantor".to_string(),
                scope: pgroles_core::model::DefaultPrivilegeScope::Global,
                on_type: ObjectType::Table,
                grantee: Grantee::Role("gap_alice".to_string()),
                privileges: BTreeSet::from([Privilege::Select]),
            },
        ];
        let issues =
            preflight_authority_issues(&exec_pool, &defaults_breaking, &RoleGraph::default())
                .await
                .expect("preflight should run");
        assert!(
            issues.iter().any(|issue| matches!(
                issue,
                AuthorityIssue::GrantorAuthorityRemovedByPlan { grantor, .. }
                    if grantor == "gap_grantor"
            )),
            "the defaults owner's removed path must be flagged: {issues:?}"
        );

        // A superuser's authority does not depend on membership paths.
        let issues = preflight_authority_issues(&pool, &breaking, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            !issues
                .iter()
                .any(|issue| matches!(issue, AuthorityIssue::GrantorAuthorityRemovedByPlan { .. })),
            "superusers keep authority: {issues:?}"
        );
    });
}
