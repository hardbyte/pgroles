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

/// Since PostgreSQL 16 a membership edge records its grantor, and a bare
/// `REVOKE <role> FROM <member>` removes only the edge attributed to the
/// executor: with ADMIN OPTION but a different grantor it succeeds with a
/// WARNING and the edge survives. The preflight must name the grantor.
#[test]
#[ignore]
fn preflight_names_membership_edges_the_executor_cannot_revoke() {
    let _cleanup = MembershipCleanup;
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
            // Pre-16 revokes are not grantor-attributed; nothing to check.
            return;
        }
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
        }];

        // The executor holds ADMIN OPTION on the role, yet the targeted edge
        // was granted by fgrm_grantor: PostgreSQL would accept the REVOKE
        // with a WARNING and leave the membership in place.
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
        assert_eq!(membership.len(), 1, "one unreachable edge: {issues:?}");
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
            (role.as_str(), member.as_str()),
            ("fgrm_reader", "fgrm_alice")
        );
        assert_eq!(grantor, "fgrm_grantor");

        // A superuser's bare membership revoke is attributed to the bootstrap
        // superuser (verified live): the edge fgrm_grantor granted still
        // survives it — with only a WARNING — and must stay reported, while
        // an edge the bootstrap superuser granted (fgrm_reader → fgrm_exec)
        // is removable and must not be.
        let both = vec![
            Change::RemoveMember {
                role: "fgrm_reader".to_string(),
                member: "fgrm_alice".to_string(),
            },
            Change::RemoveMember {
                role: "fgrm_reader".to_string(),
                member: "fgrm_exec".to_string(),
            },
        ];
        let issues = preflight_authority_issues(&pool, &both, &RoleGraph::default())
            .await
            .expect("preflight should run");
        let membership: Vec<_> = issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityIssue::ForeignGrantorMembershipRevoke { .. }))
            .collect();
        assert_eq!(
            membership.len(),
            1,
            "only the ordinary-grantor edge survives a superuser's revoke: {issues:?}"
        );
        let AuthorityIssue::ForeignGrantorMembershipRevoke {
            member, grantor, ..
        } = membership[0]
        else {
            unreachable!()
        };
        assert_eq!(
            (member.as_str(), grantor.as_str()),
            ("fgrm_alice", "fgrm_grantor")
        );
    });
}
