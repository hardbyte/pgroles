//! Differential test: one shared read must answer exactly like N narrow ones.
//!
//! `RawInspection` exists so the operator can read the database once per
//! reconcile and derive a scoped inspection per open candidate, instead of
//! running a full inspection per candidate under the parent's locks. That is
//! only acceptable if the derived answer is *identical* to the narrow one —
//! a candidate's plan is what a human approves, so a quietly different diff is
//! far worse than a slow one.
//!
//! So this suite asserts equality, per config, against the real server:
//!
//! ```text
//! RawInspection::read(pool, union_of(configs)).derive(pool, config)
//!     ==  inspect_with_diagnostics(pool, config)
//! ```
//!
//! for both halves of the result — the `RoleGraph` and the diagnostics — over
//! configs with genuinely different scopes: disjoint roles, overlapping roles,
//! a role only one config declares (and that does not exist in the database at
//! all), wildcards that match objects, wildcards that match nothing, and
//! `include_database_privileges` set for one config and not another.
//!
//! Equality is the right property but a weak assertion on its own, and it is
//! worth being explicit about why: `inspect_with_diagnostics` is itself
//! read-then-derive, so it is not an independent reference implementation —
//! both sides of every comparison run the same scoping code. A bug that drops
//! a whole class of row drops it from both sides, and equality then holds over
//! two equally-empty answers. What equality does prove is the property this
//! change actually puts at risk: that narrowing from a *union* read returns
//! what narrowing from an already-narrow read returns, so the extra rows a
//! wider scope drags in change nothing. Absolute correctness of the narrowing
//! is pinned by `snapshot.rs`'s unit tests, and each call below names the row
//! classes its fixture must exercise so the two suites cannot share a blind
//! spot by both going empty.
//!
//! The blocking case gets its own test, because it is the one that changes
//! what the operator *does*: a wildcard grant that is unsatisfiable for one
//! config and satisfiable for another must still block exactly the first one.
//! Grantability depends on the connected role, so that test creates a
//! restricted executor and reconnects as it — a superuser can grant anything
//! and would never produce the diagnostic.
//!
//! Requires DATABASE_URL; run with `cargo test -- --include-ignored`.

use sqlx::{Executor, PgPool};

use pgroles_core::manifest::{ObjectType, expand_manifest, parse_manifest};
use pgroles_inspect::{InspectConfig, InspectionResult, RawInspection, inspect_with_diagnostics};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

/// The same database, connected as `role` instead of the configured user.
///
/// Grantability — and therefore every unsatisfiable-wildcard diagnostic — is a
/// property of `current_user`, so the blocking test has to actually connect as
/// a role that cannot grant.
fn database_url_as(role: &str, password: &str) -> String {
    let url = database_url();
    let (scheme, rest) = url
        .split_once("://")
        .expect("DATABASE_URL must have a scheme");
    let host_and_path = rest.rsplit_once('@').map(|(_, tail)| tail).unwrap_or(rest);
    format!("{scheme}://{role}:{password}@{host_and_path}")
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

fn execute_sql(sql: &str) {
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect to live test database");
        pool.execute(sql)
            .await
            .expect("failed to execute setup SQL");
    });
}

struct Cleanup {
    sql: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        execute_sql(&self.sql);
    }
}

fn config_from_yaml(yaml: &str, include_database_privileges: bool) -> InspectConfig {
    let manifest = parse_manifest(yaml).expect("test manifest must parse");
    let expanded = expand_manifest(&manifest).expect("test manifest must expand");
    InspectConfig::from_expanded(&expanded, include_database_privileges)
}

/// Assert that deriving `config` from a snapshot of the union equals
/// inspecting `config` on its own — graph and diagnostics alike.
async fn assert_derivation_matches_narrow_inspection(
    pool: &PgPool,
    snapshot: &RawInspection,
    configs: &[(&str, InspectConfig)],
    must_exercise: &[ObjectType],
) {
    // Which row classes the fixtures actually put in front of the assertions —
    // see the vacuity guard after the loop.
    let mut exercised: std::collections::BTreeSet<ObjectType> = std::collections::BTreeSet::new();
    let mut exercised_roles = false;

    for (label, config) in configs {
        assert!(
            snapshot.covers(config),
            "{label}: the union snapshot must cover every member config"
        );

        let derived: InspectionResult = snapshot
            .derive(pool, config)
            .await
            .unwrap_or_else(|error| panic!("{label}: derivation failed: {error}"));
        let narrow: InspectionResult = inspect_with_diagnostics(pool, config)
            .await
            .unwrap_or_else(|error| panic!("{label}: narrow inspection failed: {error}"));

        // `RoleGraph` does not implement `PartialEq`, so compare every axis of
        // it explicitly — which also names the axis that differs.
        assert_eq!(
            derived.graph.roles, narrow.graph.roles,
            "{label}: derived roles differ from the narrow inspection"
        );
        assert_eq!(
            derived.graph.schemas, narrow.graph.schemas,
            "{label}: derived schemas differ from the narrow inspection"
        );
        assert_eq!(
            derived.graph.grants, narrow.graph.grants,
            "{label}: derived grants differ from the narrow inspection"
        );
        assert_eq!(
            derived.graph.default_privileges, narrow.graph.default_privileges,
            "{label}: derived default privileges differ from the narrow inspection"
        );
        assert_eq!(
            derived.graph.memberships, narrow.graph.memberships,
            "{label}: derived memberships differ from the narrow inspection"
        );
        assert_eq!(
            derived.diagnostics, narrow.diagnostics,
            "{label}: derived diagnostics differ from the narrow inspection"
        );
        assert_eq!(
            derived.diagnostics.blocking_message(),
            narrow.diagnostics.blocking_message(),
            "{label}: derived blocking message differs from the narrow inspection"
        );

        for key in narrow.graph.grants.keys() {
            exercised.insert(key.object_type);
        }
        if !narrow.graph.roles.is_empty() {
            exercised_roles = true;
        }
    }

    // Equality alone is a weak bar here, and deliberately so: since
    // `inspect_with_diagnostics` is itself read-then-derive, both sides of
    // every assertion above run the *same* scoping code. A bug that drops a
    // whole class of row drops it identically on both sides, and the equality
    // then holds over two equally-empty answers. Scoping schema-level ACL rows
    // by `schema_name` — always NULL for them — is exactly that shape, and it
    // satisfies every assertion above.
    //
    // What proves narrowing is *correct* rather than merely self-consistent is
    // `snapshot.rs`'s unit tests, which assert content instead of equality.
    // This guard is what stops the two suites sharing a blind spot: it fails
    // if the fixtures stop exercising a row class, so the equality assertions
    // can never quietly become vacuous.
    //
    // Suite-level, not per-config: some configs are meant to come back empty —
    // the one naming a role that does not exist in the database is the whole
    // point of that case. Each caller names the classes its own fixture is
    // built to exercise, so a test focused on grantability is not forced to
    // grow schema ACLs it has no opinion about.
    assert!(
        exercised_roles,
        "no config produced a role — the equality assertions prove nothing"
    );
    for object_type in must_exercise {
        assert!(
            exercised.contains(object_type),
            "no config produced a {object_type:?} grant — the equality assertions \
             would hold over two equally-empty answers"
        );
    }
}

#[test]
#[ignore]
fn derived_inspections_match_narrow_inspections_across_differing_scopes() {
    let suffix = unique_suffix();
    let app = format!("snap_app_{suffix}");
    let ops = format!("snap_ops_{suffix}");
    let empty = format!("snap_empty_{suffix}");
    let owner = format!("snap_owner_{suffix}");
    let shared = format!("snap_shared_{suffix}");
    let only_a = format!("snap_only_a_{suffix}");
    let only_b = format!("snap_only_b_{suffix}");
    // Declared by a config but never created: a candidate proposing a new role
    // has exactly this shape, and the narrow inspection must report its
    // absence identically to the derived one.
    let never_created = format!("snap_ghost_{suffix}");

    let _cleanup = Cleanup {
        sql: format!(
            r#"
            DROP SCHEMA IF EXISTS "{app}" CASCADE;
            DROP SCHEMA IF EXISTS "{ops}" CASCADE;
            DROP SCHEMA IF EXISTS "{empty}" CASCADE;
            -- Database-level privileges are a dependency of the role, so every
            -- role granted one must be revoked before it can be dropped.
            REVOKE ALL ON DATABASE "{database}" FROM "{shared}";
            REVOKE ALL ON DATABASE "{database}" FROM "{only_b}";
            DROP ROLE IF EXISTS "{shared}";
            DROP ROLE IF EXISTS "{only_a}";
            DROP ROLE IF EXISTS "{only_b}";
            DROP ROLE IF EXISTS "{owner}";
            "#,
            database = current_database(),
        ),
    };

    execute_sql(&format!(
        r#"
        CREATE ROLE "{owner}" NOLOGIN;
        CREATE ROLE "{shared}" NOLOGIN;
        CREATE ROLE "{only_a}" NOLOGIN;
        CREATE ROLE "{only_b}" NOLOGIN;
        CREATE SCHEMA "{app}" AUTHORIZATION "{owner}";
        CREATE SCHEMA "{ops}" AUTHORIZATION "{owner}";
        CREATE SCHEMA "{empty}" AUTHORIZATION "{owner}";
        CREATE TABLE "{app}".widgets (id int);
        CREATE TABLE "{app}".gadgets (id int);
        CREATE TABLE "{ops}".runbooks (id int);
        CREATE SEQUENCE "{ops}".counter;
        CREATE FUNCTION "{app}".noop() RETURNS int LANGUAGE sql AS 'SELECT 1';
        GRANT USAGE ON SCHEMA "{app}" TO "{shared}";
        GRANT USAGE ON SCHEMA "{ops}" TO "{shared}";
        GRANT SELECT ON "{app}".widgets TO "{shared}";
        GRANT SELECT ON "{app}".gadgets TO "{shared}";
        GRANT SELECT, INSERT ON "{app}".widgets TO "{only_a}";
        GRANT SELECT ON "{ops}".runbooks TO "{only_b}";
        GRANT USAGE ON SCHEMA "{ops}" TO "{only_b}";
        GRANT USAGE, SELECT ON SEQUENCE "{ops}".counter TO "{only_b}";
        GRANT EXECUTE ON FUNCTION "{app}".noop() TO "{shared}";
        GRANT SELECT (id) ON "{app}".gadgets TO "{only_a}";
        GRANT CONNECT ON DATABASE "{database}" TO "{shared}";
        GRANT CONNECT ON DATABASE "{database}" TO "{only_b}";
        ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" IN SCHEMA "{app}"
            GRANT SELECT ON TABLES TO "{shared}";
        ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" IN SCHEMA "{ops}"
            GRANT SELECT ON TABLES TO "{only_b}";
        GRANT "{shared}" TO "{only_a}";
        "#,
        database = current_database(),
    ));

    // A: `app` only, wildcard that is fully satisfied for the shared role.
    let config_a = config_from_yaml(
        &format!(
            r#"
roles:
  - name: "{shared}"
grants:
  - role: "{shared}"
    privileges: [SELECT]
    object: {{ type: table, schema: "{app}", name: "*" }}
  - role: "{shared}"
    privileges: [USAGE]
    object: {{ type: schema, name: "{app}" }}
"#
        ),
        false,
    );

    // B: disjoint roles and schemas from A, a wildcard that is NOT satisfied
    // (the sequence has no wildcard grant for this role on tables), and
    // database privileges switched on. The CONNECT grant names the connected
    // database and a role B actually manages, so the database axis is compared
    // against real rows — naming an unrelated database would make both sides
    // empty and the assertion vacuous on the one axis `derive` newly filters
    // by `managed_roles`.
    let config_b = config_from_yaml(
        &format!(
            r#"
roles:
  - name: "{only_b}"
grants:
  - role: "{only_b}"
    privileges: [SELECT, INSERT]
    object: {{ type: table, schema: "{ops}", name: "*" }}
  - role: "{only_b}"
    privileges: [USAGE]
    object: {{ type: schema, name: "{ops}" }}
  - role: "{only_b}"
    privileges: [CONNECT]
    object: {{ type: database, name: "{database}" }}
"#,
            database = current_database(),
        ),
        true,
    );

    // C: overlaps A on the shared role and the `app` schema, but adds a role
    // A never mentions and a schema with no objects at all — the vacuous
    // wildcard path.
    let config_c = config_from_yaml(
        &format!(
            r#"
roles:
  - name: "{shared}"
  - name: "{only_a}"
grants:
  - role: "{only_a}"
    privileges: [SELECT, INSERT]
    object: {{ type: table, schema: "{app}", name: "*" }}
  - role: "{shared}"
    privileges: [SELECT]
    object: {{ type: table, schema: "{empty}", name: "*" }}
  - role: "{shared}"
    privileges: [EXECUTE]
    object: {{ type: function, schema: "{app}", name: "*" }}
"#
        ),
        false,
    );

    // D: a role that does not exist in the database, plus every schema.
    let config_d = config_from_yaml(
        &format!(
            r#"
roles:
  - name: "{never_created}"
grants:
  - role: "{never_created}"
    privileges: [SELECT]
    object: {{ type: table, schema: "{app}", name: "*" }}
  - role: "{never_created}"
    privileges: [SELECT]
    object: {{ type: table, schema: "{ops}", name: "*" }}
"#
        ),
        false,
    );

    // E: the union of everything, as the parent policy's own scope might be.
    let config_e = config_from_yaml(
        &format!(
            r#"
roles:
  - name: "{shared}"
  - name: "{only_a}"
  - name: "{only_b}"
  - name: "{owner}"
grants:
  - role: "{shared}"
    privileges: [USAGE]
    object: {{ type: schema, name: "{ops}" }}
  - role: "{only_b}"
    privileges: [USAGE, SELECT]
    object: {{ type: sequence, schema: "{ops}", name: "*" }}
"#
        ),
        false,
    );

    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect to live test database");

        let configs = vec![
            ("A/app-wildcard", config_a),
            ("B/disjoint+database-privileges", config_b),
            ("C/overlapping+vacuous-wildcard", config_c),
            ("D/role-that-does-not-exist", config_d),
            ("E/superset", config_e),
        ];
        let union = InspectConfig::union_of(configs.iter().map(|(_, config)| config));
        let snapshot = RawInspection::read(&pool, &union)
            .await
            .expect("shared read should succeed");

        assert_derivation_matches_narrow_inspection(
            &pool,
            &snapshot,
            &configs,
            &[
                ObjectType::Schema,
                ObjectType::Table,
                ObjectType::Sequence,
                ObjectType::Database,
            ],
        )
        .await;
    });
}

#[test]
#[ignore]
fn an_unsatisfiable_wildcard_blocks_only_the_config_that_declares_it() {
    let suffix = unique_suffix();
    let locked = format!("snap_locked_{suffix}");
    let open = format!("snap_open_{suffix}");
    let owner = format!("snap_lowner_{suffix}");
    let reader = format!("snap_lreader_{suffix}");
    let executor = format!("snap_exec_{suffix}");
    let executor_password = "pgroles-shared-snapshot-test";

    let _cleanup = Cleanup {
        sql: format!(
            r#"
            DROP SCHEMA IF EXISTS "{locked}" CASCADE;
            DROP SCHEMA IF EXISTS "{open}" CASCADE;
            DROP ROLE IF EXISTS "{reader}";
            DROP ROLE IF EXISTS "{executor}";
            DROP ROLE IF EXISTS "{owner}";
            "#
        ),
    };

    // `executor` is deliberately NOT a member of `owner` and holds no grant
    // option on anything, so it cannot satisfy a wildcard over `locked`.
    execute_sql(&format!(
        r#"
        CREATE ROLE "{owner}" NOLOGIN;
        CREATE ROLE "{reader}" NOLOGIN;
        CREATE ROLE "{executor}" LOGIN PASSWORD '{executor_password}';
        CREATE SCHEMA "{locked}" AUTHORIZATION "{owner}";
        CREATE SCHEMA "{open}" AUTHORIZATION "{owner}";
        CREATE TABLE "{locked}".secrets (id int);
        CREATE TABLE "{open}".public_facts (id int);
        GRANT SELECT ON "{open}".public_facts TO "{reader}";
        "#
    ));

    // The candidate: wants SELECT on everything in `locked`, where the one
    // table has no such grant and the executor cannot create one.
    let candidate = config_from_yaml(
        &format!(
            r#"
roles:
  - name: "{reader}"
grants:
  - role: "{reader}"
    privileges: [SELECT]
    object: {{ type: table, schema: "{locked}", name: "*" }}
"#
        ),
        false,
    );

    // The parent: the same shape over `open`, where the grant already exists,
    // so the wildcard is satisfied and nothing blocks.
    let parent = config_from_yaml(
        &format!(
            r#"
roles:
  - name: "{reader}"
grants:
  - role: "{reader}"
    privileges: [SELECT]
    object: {{ type: table, schema: "{open}", name: "*" }}
"#
        ),
        false,
    );

    with_runtime(async {
        let pool = PgPool::connect(&database_url_as(&executor, executor_password))
            .await
            .expect("failed to connect as the restricted executor");

        let configs = vec![
            ("candidate/unsatisfiable", candidate),
            ("parent/satisfiable", parent),
        ];
        let union = InspectConfig::union_of(configs.iter().map(|(_, config)| config));
        let snapshot = RawInspection::read(&pool, &union)
            .await
            .expect("shared read should succeed");

        assert_derivation_matches_narrow_inspection(
            &pool,
            &snapshot,
            &configs,
            &[ObjectType::Table],
        )
        .await;

        let candidate_result = snapshot
            .derive(&pool, &configs[0].1)
            .await
            .expect("derivation should succeed");
        let parent_result = snapshot
            .derive(&pool, &configs[1].1)
            .await
            .expect("derivation should succeed");

        let blocking = candidate_result
            .diagnostics
            .blocking_message()
            .expect("the unsatisfiable wildcard must block the candidate");
        assert!(
            blocking.contains(&executor),
            "the diagnostic must name the executor it was computed for: {blocking}"
        );
        assert!(
            blocking.contains(&locked),
            "the diagnostic must name the schema it is about: {blocking}"
        );
        assert_eq!(
            parent_result.diagnostics.blocking_message(),
            None,
            "the satisfiable wildcard must not block, even though it shares a snapshot \
             with one that does"
        );
    });
}

/// The database name, needed for the `GRANT CONNECT ON DATABASE` fixture.
fn current_database() -> String {
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect to live test database");
        let (name,): (String,) = sqlx::query_as("SELECT current_database()::text")
            .fetch_one(&pool)
            .await
            .expect("current_database() should be readable");
        name
    })
}
