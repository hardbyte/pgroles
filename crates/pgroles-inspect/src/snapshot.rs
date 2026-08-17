//! One scoped read of the database, many scoped inspections.
//!
//! [`crate::inspect_with_diagnostics`] answers a question about *one*
//! [`InspectConfig`]: these roles, these schemas, these wildcard patterns.
//! The operator asks that question repeatedly against the same database in a
//! single reconcile — once for the policy and once for every open candidate —
//! and each answer is scoped differently, because a candidate proposing a new
//! role has a role in scope the policy does not.
//!
//! The two halves of an inspection have different scope-sensitivity:
//!
//! * The **read** is a filter over `pg_catalog`. Every query is
//!   `WHERE schema = ANY(...) AND grantee = ANY(...)`, so a read over the
//!   *union* of several scopes contains, row for row, every read over a
//!   narrower scope inside it.
//! * The **derivation** — wildcard expansion, vacuous-wildcard synthesis,
//!   unsatisfiable-wildcard diagnostics — is scope-*dependent*, and must run
//!   per config against exactly that config's rows and patterns.
//!
//! [`RawInspection`] is that split. Read once over
//! [`InspectConfig::union_of`], then [`RawInspection::derive`] per config.
//! Deriving is in-memory except for one lazy, at-most-once grantability read
//! that only happens when some config has an unsatisfied wildcard — the same
//! query the narrow path issues, hoisted so N candidates cannot issue N of
//! them.
//!
//! `inspect_with_diagnostics` is itself read-then-derive over a single config,
//! so the shared path is not a second implementation that can drift from it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use tracing::debug;

use pgroles_core::model::{
    DefaultPrivKey, DefaultPrivState, GrantKey, GrantState, RoleGraph, SchemaState,
};

use crate::defaults::fetch_default_privileges;
use crate::memberships::{MembershipRow, fetch_memberships};
use crate::privileges::{
    self, RawGrantability, RawPrivilegeState, fetch_column_level_grants, fetch_database_privileges,
};
use crate::roles::{RoleRow, fetch_roles};
use crate::{
    ColumnLevelGrantDiagnostic, InspectConfig, InspectError, InspectionDiagnostics,
    InspectionResult, InspectionStats, SchemaRow, fetch_schemas,
    remove_redundant_schema_owner_grants,
};

/// A raw, uninterpreted read of the database over one scope.
///
/// Safe to derive any config whose scope is contained in the one that was
/// read — [`RawInspection::covers`] decides, and [`RawInspection::derive`]
/// refuses otherwise rather than quietly returning a narrower answer than the
/// caller asked for.
pub struct RawInspection {
    scope: InspectConfig,
    roles: Vec<RoleRow>,
    memberships: Vec<MembershipRow>,
    schemas: Vec<SchemaRow>,
    privileges: RawPrivilegeState,
    column_level_grants: Vec<ColumnLevelGrantDiagnostic>,
    database_grants: BTreeMap<GrantKey, GrantState>,
    default_privileges: BTreeMap<DefaultPrivKey, DefaultPrivState>,
    /// Durations of the shared read's phases, copied into every derived
    /// [`InspectionStats`]: they describe the one read all derivations share.
    phase_durations: BTreeMap<&'static str, Duration>,
    /// Filled on the first derivation that finds an unsatisfied wildcard, and
    /// reused by every later one. Read over the *whole* scope's wildcard
    /// pairs with every privilege requested, which
    /// [`crate::privileges::GrantabilityRow::masked`] narrows per config.
    grantability: Mutex<Option<Arc<RawGrantability>>>,
}

impl RawInspection {
    /// Read every row inside `scope`.
    pub async fn read(pool: &PgPool, scope: &InspectConfig) -> Result<Self, InspectError> {
        let mut phase_durations: BTreeMap<&'static str, Duration> = BTreeMap::new();
        let mut record = |phase: &'static str, started: Instant| {
            phase_durations.insert(phase, started.elapsed());
        };

        let role_refs: Vec<&str> = scope.managed_roles.iter().map(String::as_str).collect();
        let schema_refs: Vec<&str> = scope.managed_schemas.iter().map(String::as_str).collect();
        let privilege_schema_refs: Vec<&str> =
            scope.privilege_schemas.iter().map(String::as_str).collect();

        debug!(
            roles = role_refs.len(),
            schemas = schema_refs.len(),
            privilege_schemas = privilege_schema_refs.len(),
            "reading raw database state"
        );

        let started = Instant::now();
        let roles = fetch_roles(pool, Some(&role_refs)).await?;
        record("roles", started);

        let started = Instant::now();
        let memberships = fetch_memberships(pool, Some(&role_refs)).await?;
        record("memberships", started);

        let schemas = if schema_refs.is_empty() {
            Vec::new()
        } else {
            let started = Instant::now();
            let rows = fetch_schemas(pool, &schema_refs).await?;
            record("schemas", started);
            rows
        };

        let (privileges, column_level_grants, default_privileges) =
            if privilege_schema_refs.is_empty() {
                (
                    RawPrivilegeState {
                        acl_rows: Vec::new(),
                        inventory: BTreeMap::new(),
                    },
                    Vec::new(),
                    BTreeMap::new(),
                )
            } else {
                let wildcard_scopes = privileges::wildcard_scopes_of(&scope.wildcard_grants);

                let started = Instant::now();
                let privileges = privileges::read_raw_privileges(
                    pool,
                    &privilege_schema_refs,
                    &role_refs,
                    &wildcard_scopes,
                )
                .await?;
                record("object_privileges", started);

                let started = Instant::now();
                let column_level_grants =
                    fetch_column_level_grants(pool, &privilege_schema_refs).await?;
                record("column_level_grants", started);

                let started = Instant::now();
                let default_privileges =
                    fetch_default_privileges(pool, &privilege_schema_refs, &role_refs).await?;
                record("default_privileges", started);

                (privileges, column_level_grants, default_privileges)
            };

        let database_grants = if scope.include_database_privileges {
            let started = Instant::now();
            let grants = fetch_database_privileges(pool, &role_refs).await?;
            record("database_privileges", started);
            grants
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            scope: scope.clone(),
            roles,
            memberships,
            schemas,
            privileges,
            column_level_grants,
            database_grants,
            default_privileges,
            phase_durations,
            grantability: Mutex::new(None),
        })
    }

    /// The scope this snapshot was read over.
    pub fn scope(&self) -> &InspectConfig {
        &self.scope
    }

    /// Can `config` be derived from this snapshot without a further read?
    ///
    /// True exactly when every axis of `config`'s scope is contained in the
    /// scope that was read. Wildcard *privileges* deliberately play no part:
    /// the inventory read ignores them and the grantability read asks about
    /// all of them, so only the `(object_type, schema)` pairs must be covered.
    pub fn covers(&self, config: &InspectConfig) -> bool {
        let roles: BTreeSet<&str> = self
            .scope
            .managed_roles
            .iter()
            .map(String::as_str)
            .collect();
        let schemas: BTreeSet<&str> = self
            .scope
            .managed_schemas
            .iter()
            .map(String::as_str)
            .collect();
        let privilege_schemas: BTreeSet<&str> = self
            .scope
            .privilege_schemas
            .iter()
            .map(String::as_str)
            .collect();
        let wildcard_scopes = privileges::wildcard_scopes_of(&self.scope.wildcard_grants);

        (!config.include_database_privileges || self.scope.include_database_privileges)
            && config
                .managed_roles
                .iter()
                .all(|role| roles.contains(role.as_str()))
            && config
                .managed_schemas
                .iter()
                .all(|schema| schemas.contains(schema.as_str()))
            && config
                .privilege_schemas
                .iter()
                .all(|schema| privilege_schemas.contains(schema.as_str()))
            && privileges::wildcard_scopes_of(&config.wildcard_grants)
                .iter()
                .all(|scope| wildcard_scopes.contains(scope))
    }

    /// Produce the inspection `config` would have produced on its own.
    ///
    /// Pure except for the lazy grantability read, which happens at most once
    /// per snapshot and only when some config leaves a wildcard unsatisfied.
    pub async fn derive(
        &self,
        pool: &PgPool,
        config: &InspectConfig,
    ) -> Result<InspectionResult, InspectError> {
        if !self.covers(config) {
            return Err(InspectError::ScopeNotCovered(
                "the requested inspection scope is not contained in this snapshot's scope"
                    .to_string(),
            ));
        }

        let started = Instant::now();
        let managed_roles: BTreeSet<String> = config.managed_roles.iter().cloned().collect();
        let managed_schemas: BTreeSet<String> = config.managed_schemas.iter().cloned().collect();
        let privilege_schemas: BTreeSet<String> =
            config.privilege_schemas.iter().cloned().collect();

        let mut graph = RoleGraph::default();
        let mut diagnostics = InspectionDiagnostics::default();
        let mut stats = InspectionStats {
            phase_durations: self.phase_durations.clone(),
            ..InspectionStats::default()
        };

        // --- Roles ---
        for row in &self.roles {
            if managed_roles.contains(&row.rolname) {
                graph.roles.insert(row.rolname.clone(), row.to_role_state());
            }
        }
        stats.roles = graph.roles.len();

        // --- Memberships ---
        for row in &self.memberships {
            if managed_roles.contains(&row.role_name) {
                graph.memberships.insert(row.to_membership_edge());
            }
        }
        stats.memberships = graph.memberships.len();

        // --- Schemas ---
        if !managed_schemas.is_empty() {
            for row in &self.schemas {
                if managed_schemas.contains(&row.schema_name) {
                    graph.schemas.insert(
                        row.schema_name.clone(),
                        SchemaState {
                            owner: Some(row.owner_name.clone()),
                            owner_privileges: row.owner_privileges(),
                        },
                    );
                }
            }
            stats.schemas = graph.schemas.len();
        }

        // --- Object privileges (+ wildcard expansion and diagnostics) ---
        if !privilege_schemas.is_empty() {
            let derived = privileges::derive_privileges(
                &self.privileges,
                &privilege_schemas,
                &managed_roles,
                &config.wildcard_grants,
            );
            let grantability = if derived.unsatisfied.is_empty() {
                None
            } else {
                Some(self.grantability(pool).await?)
            };
            let result = derived.finish(grantability.as_deref());

            stats.wildcard = result.wildcard_stats;
            diagnostics
                .unsatisfiable_wildcard_grants
                .extend(result.diagnostics);
            for (key, state) in result.grants {
                graph.grants.insert(key, state);
            }
            remove_redundant_schema_owner_grants(&mut graph);
            stats.grants = graph.grants.len();

            diagnostics.column_level_grants = self
                .column_level_grants
                .iter()
                .filter(|diagnostic| privilege_schemas.contains(&diagnostic.schema))
                .cloned()
                .collect();
        }

        // --- Database-level privileges ---
        if config.include_database_privileges {
            for (key, state) in &self.database_grants {
                if managed_roles.contains(&key.role) {
                    graph.grants.insert(key.clone(), state.clone());
                }
            }
            stats.grants = graph.grants.len();
        }

        // --- Default privileges ---
        if !privilege_schemas.is_empty() {
            for (key, state) in &self.default_privileges {
                if privilege_schemas.contains(&key.schema) && managed_roles.contains(&key.grantee) {
                    graph.default_privileges.insert(key.clone(), state.clone());
                }
            }
            stats.default_privileges = graph.default_privileges.len();
        }

        stats.phase_durations.insert("derive", started.elapsed());

        Ok(InspectionResult {
            graph,
            diagnostics,
            stats,
        })
    }

    /// The grantability read, performed at most once per snapshot.
    async fn grantability(&self, pool: &PgPool) -> Result<Arc<RawGrantability>, InspectError> {
        if let Some(cached) = self
            .grantability
            .lock()
            .expect("grantability cache poisoned")
            .clone()
        {
            return Ok(cached);
        }

        let scopes = privileges::wildcard_scopes_of(&self.scope.wildcard_grants);
        let fresh = Arc::new(privileges::read_raw_grantability(pool, &scopes).await?);

        let mut cache = self
            .grantability
            .lock()
            .expect("grantability cache poisoned");
        Ok(cache.get_or_insert(fresh).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::manifest::{ObjectType, Privilege};
    use pgroles_core::model::RoleState;

    use crate::WildcardGrantPattern;
    use crate::memberships::MembershipRow;
    use crate::privileges::AclRow;
    use crate::roles::RoleRow;

    fn role_row(name: &str) -> RoleRow {
        RoleRow {
            rolname: name.to_string(),
            rolsuper: false,
            rolinherit: true,
            rolcreaterole: false,
            rolcreatedb: false,
            rolcanlogin: false,
            rolreplication: false,
            rolbypassrls: false,
            rolconnlimit: -1,
            comment: None,
            rolvaliduntil: None,
            rolconfig: None,
        }
    }

    fn membership_row(role: &str, member: &str) -> MembershipRow {
        MembershipRow {
            role_name: role.to_string(),
            member_name: member.to_string(),
            admin_option: false,
            inherit_option: true,
        }
    }

    fn schema_row(name: &str, owner: &str) -> SchemaRow {
        SchemaRow {
            schema_name: name.to_string(),
            owner_name: owner.to_string(),
            owner_has_create: true,
            owner_has_usage: true,
        }
    }

    fn table_acl(schema: &str, table: &str, grantee: &str, privilege: &str) -> AclRow {
        AclRow {
            grantee: Some(grantee.to_string()),
            privilege_type: privilege.to_string(),
            schema_name: Some(schema.to_string()),
            object_name: table.to_string(),
            obj_type: "table".to_string(),
        }
    }

    fn schema_acl(schema: &str, grantee: &str, privilege: &str) -> AclRow {
        AclRow {
            grantee: Some(grantee.to_string()),
            privilege_type: privilege.to_string(),
            schema_name: None,
            object_name: schema.to_string(),
            obj_type: "schema".to_string(),
        }
    }

    fn config(
        roles: &[&str],
        schemas: &[&str],
        include_database_privileges: bool,
        wildcards: Vec<WildcardGrantPattern>,
    ) -> InspectConfig {
        InspectConfig {
            managed_roles: roles.iter().map(|r| r.to_string()).collect(),
            managed_schemas: schemas.iter().map(|s| s.to_string()).collect(),
            privilege_schemas: schemas.iter().map(|s| s.to_string()).collect(),
            include_database_privileges,
            wildcard_grants: wildcards,
        }
    }

    /// A snapshot over `{alice, bob} × {app, ops}` with a table grant to each
    /// role in each schema, plus one database grant to alice.
    fn snapshot() -> RawInspection {
        let mut database_grants = BTreeMap::new();
        database_grants.insert(
            GrantKey {
                role: "alice".to_string(),
                object_type: ObjectType::Database,
                schema: None,
                name: Some("mydb".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Connect]),
            },
        );
        database_grants.insert(
            GrantKey {
                role: "bob".to_string(),
                object_type: ObjectType::Database,
                schema: None,
                name: Some("mydb".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Connect]),
            },
        );

        let mut default_privileges = BTreeMap::new();
        for (schema, grantee) in [("app", "alice"), ("ops", "bob")] {
            default_privileges.insert(
                DefaultPrivKey {
                    owner: "owner".to_string(),
                    schema: schema.to_string(),
                    on_type: ObjectType::Table,
                    grantee: grantee.to_string(),
                },
                DefaultPrivState {
                    privileges: BTreeSet::from([Privilege::Select]),
                },
            );
        }

        RawInspection {
            scope: config(
                &["alice", "bob"],
                &["app", "empty", "ops"],
                true,
                ["app", "empty", "ops"]
                    .into_iter()
                    .flat_map(|schema| {
                        ["alice", "bob"]
                            .into_iter()
                            .map(move |role| WildcardGrantPattern {
                                role: role.to_string(),
                                object_type: ObjectType::Table,
                                schema: schema.to_string(),
                                privileges: BTreeSet::from([Privilege::Select]),
                            })
                    })
                    .collect(),
            ),
            roles: vec![role_row("alice"), role_row("bob")],
            memberships: vec![
                membership_row("alice", "bob"),
                membership_row("bob", "alice"),
            ],
            schemas: vec![schema_row("app", "owner"), schema_row("ops", "owner")],
            privileges: RawPrivilegeState {
                acl_rows: vec![
                    table_acl("app", "widgets", "alice", "r"),
                    table_acl("app", "widgets", "bob", "r"),
                    table_acl("ops", "gadgets", "bob", "r"),
                    schema_acl("app", "alice", "U"),
                    schema_acl("ops", "bob", "U"),
                ],
                inventory: BTreeMap::from([
                    (
                        (ObjectType::Table, "app".to_string()),
                        BTreeSet::from(["widgets".to_string()]),
                    ),
                    (
                        (ObjectType::Table, "ops".to_string()),
                        BTreeSet::from(["gadgets".to_string(), "cogs".to_string()]),
                    ),
                ]),
            },
            column_level_grants: vec![
                ColumnLevelGrantDiagnostic {
                    schema: "app".to_string(),
                    relation: "widgets".to_string(),
                    grantee: "alice".to_string(),
                    columns: vec!["secret".to_string()],
                    skipped_columns: 0,
                    privileges: BTreeSet::from([Privilege::Select]),
                },
                ColumnLevelGrantDiagnostic {
                    schema: "ops".to_string(),
                    relation: "gadgets".to_string(),
                    grantee: "bob".to_string(),
                    columns: vec!["secret".to_string()],
                    skipped_columns: 0,
                    privileges: BTreeSet::from([Privilege::Select]),
                },
            ],
            database_grants,
            default_privileges,
            phase_durations: BTreeMap::new(),
            grantability: Mutex::new(None),
        }
    }

    fn derive_pure(snapshot: &RawInspection, config: &InspectConfig) -> InspectionResult {
        // No fixture here reaches the lazy grantability read, so the pool
        // below is never connected to.
        with_runtime(async { snapshot.derive(&unreachable_pool(), config).await })
            .expect("derivation should succeed")
    }

    /// A `PgPool` handle that is never connected to — `derive` only touches it
    /// on the grantability path, which these fixtures never take. Built inside
    /// the runtime because even a lazy pool wants a Tokio context.
    fn unreachable_pool() -> PgPool {
        sqlx::pool::PoolOptions::new()
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
            .expect("lazy pool construction never connects")
    }

    fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(future)
    }

    #[test]
    fn derive_filters_roles_memberships_and_schemas_to_the_narrow_scope() {
        let snapshot = snapshot();
        let result = derive_pure(&snapshot, &config(&["alice"], &["app"], false, vec![]));

        assert_eq!(
            result.graph.roles.keys().collect::<Vec<_>>(),
            vec!["alice"],
            "a role outside the config must not appear"
        );
        assert_eq!(
            result
                .graph
                .memberships
                .iter()
                .map(|edge| edge.role.as_str())
                .collect::<Vec<_>>(),
            vec!["alice"],
            "memberships are scoped by the group role, as the query is"
        );
        assert_eq!(result.graph.schemas.keys().collect::<Vec<_>>(), vec!["app"]);
        assert_eq!(result.stats.roles, 1);
        assert_eq!(result.stats.memberships, 1);
        assert_eq!(result.stats.schemas, 1);
    }

    #[test]
    fn derive_filters_grants_by_both_role_and_schema() {
        let snapshot = snapshot();
        let result = derive_pure(&snapshot, &config(&["alice"], &["app"], false, vec![]));

        let keys: Vec<(&str, ObjectType, Option<&str>)> = result
            .graph
            .grants
            .keys()
            .map(|key| (key.role.as_str(), key.object_type, key.schema.as_deref()))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("alice", ObjectType::Schema, None),
                ("alice", ObjectType::Table, Some("app")),
            ],
            "bob's grants and the ops schema are both out of scope"
        );
    }

    #[test]
    fn derive_scopes_schema_level_rows_by_their_object_name() {
        // Schema-level ACL rows carry the schema in `object_name`, not
        // `schema_name`; scoping them by the wrong column would drop every
        // schema grant from a narrowed derivation.
        let snapshot = snapshot();
        let result = derive_pure(&snapshot, &config(&["bob"], &["ops"], false, vec![]));

        assert!(
            result
                .graph
                .grants
                .keys()
                .any(|key| key.object_type == ObjectType::Schema
                    && key.name.as_deref() == Some("ops")),
            "the schema-level grant must survive narrowing"
        );
    }

    #[test]
    fn derive_honours_include_database_privileges_per_config() {
        let snapshot = snapshot();

        let with = derive_pure(&snapshot, &config(&["alice"], &["app"], true, vec![]));
        assert!(
            with.graph
                .grants
                .keys()
                .any(|key| key.object_type == ObjectType::Database),
            "a config that asks for database privileges must get them"
        );

        let without = derive_pure(&snapshot, &config(&["alice"], &["app"], false, vec![]));
        assert!(
            !without
                .graph
                .grants
                .keys()
                .any(|key| key.object_type == ObjectType::Database),
            "a config that does not ask for database privileges must not get them"
        );
    }

    #[test]
    fn derive_scopes_column_level_and_default_privilege_diagnostics() {
        let snapshot = snapshot();
        let result = derive_pure(&snapshot, &config(&["alice"], &["app"], false, vec![]));

        assert_eq!(result.diagnostics.column_level_grants.len(), 1);
        assert_eq!(result.diagnostics.column_level_grants[0].schema, "app");
        assert_eq!(
            result
                .graph
                .default_privileges
                .keys()
                .map(|key| key.schema.as_str())
                .collect::<Vec<_>>(),
            vec!["app"],
            "default privileges are scoped by schema and grantee"
        );
    }

    #[test]
    fn derive_runs_each_configs_own_wildcard_expansion() {
        let snapshot = snapshot();
        let wildcard = |role: &str, schema: &str| {
            vec![WildcardGrantPattern {
                role: role.to_string(),
                object_type: ObjectType::Table,
                schema: schema.to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            }]
        };

        // alice holds SELECT on the only table in `app`, so her wildcard
        // collapses into a single `*` grant.
        let collapsed = derive_pure(
            &snapshot,
            &config(&["alice"], &["app"], false, wildcard("alice", "app")),
        );
        assert!(
            collapsed
                .graph
                .grants
                .keys()
                .any(|key| key.name.as_deref() == Some("*")),
            "a fully-satisfied wildcard collapses to `*`"
        );
        assert_eq!(collapsed.stats.wildcard.unsatisfied_grants, 0);

        // The same snapshot, a config whose wildcard is NOT satisfied: `ops`
        // holds a second table bob has no grant on. Computing that verdict is
        // the pure half of the derivation — the grantability read that would
        // follow it is the operator's shared, at-most-once query.
        let derived = privileges::derive_privileges(
            &snapshot.privileges,
            &BTreeSet::from(["ops".to_string()]),
            &BTreeSet::from(["bob".to_string()]),
            &wildcard("bob", "ops"),
        );
        assert_eq!(
            derived.unsatisfied.len(),
            1,
            "the same snapshot yields a different wildcard verdict per config"
        );
        assert_eq!(
            derived.wildcard_stats.inventory_objects, 2,
            "both objects in the wildcard scope are considered"
        );

        // A wildcard over a schema with no objects at all is vacuously
        // satisfied and synthesized as a `*` grant.
        let vacuous = derive_pure(
            &snapshot,
            &config(&["alice"], &["app"], false, wildcard("alice", "empty")),
        );
        assert!(
            vacuous
                .graph
                .grants
                .keys()
                .any(|key| key.name.as_deref() == Some("*")
                    && key.schema.as_deref() == Some("empty")),
            "a wildcard matching nothing is vacuously satisfied"
        );
    }

    #[test]
    fn derive_refuses_a_config_the_snapshot_does_not_cover() {
        let snapshot = snapshot();
        let uncovered = config(&["carol"], &["app"], false, vec![]);

        assert!(!snapshot.covers(&uncovered));
        let error = with_runtime(async { snapshot.derive(&unreachable_pool(), &uncovered).await })
            .expect_err("deriving an uncovered scope must fail rather than under-report");
        assert!(matches!(error, InspectError::ScopeNotCovered(_)));
    }

    #[test]
    fn covers_checks_every_axis_of_the_scope() {
        let snapshot = snapshot();

        assert!(snapshot.covers(&config(&["alice"], &["app"], true, vec![])));
        assert!(
            !snapshot.covers(&config(&["alice"], &["nope"], false, vec![])),
            "an unread schema is not covered"
        );
        assert!(
            !snapshot.covers(&config(
                &["alice"],
                &["app"],
                false,
                vec![WildcardGrantPattern {
                    role: "alice".to_string(),
                    object_type: ObjectType::Function,
                    schema: "app".to_string(),
                    privileges: BTreeSet::from([Privilege::Execute]),
                }]
            )),
            "a wildcard over an object type whose inventory was never read is not covered"
        );
    }

    #[test]
    fn union_of_covers_every_member() {
        let a = config(&["alice"], &["app"], false, vec![]);
        let b = config(&["bob"], &["ops"], true, vec![]);
        let union = InspectConfig::union_of([&a, &b]);

        assert_eq!(union.managed_roles, vec!["alice", "bob"]);
        assert_eq!(union.managed_schemas, vec!["app", "ops"]);
        assert!(union.include_database_privileges);

        // A snapshot is only ever as wide as the scope it was read over, so
        // proving the union config contains both members proves coverage.
        let snapshot = RawInspection {
            scope: union,
            roles: Vec::new(),
            memberships: Vec::new(),
            schemas: Vec::new(),
            privileges: RawPrivilegeState {
                acl_rows: Vec::new(),
                inventory: BTreeMap::new(),
            },
            column_level_grants: Vec::new(),
            database_grants: BTreeMap::new(),
            default_privileges: BTreeMap::new(),
            phase_durations: BTreeMap::new(),
            grantability: Mutex::new(None),
        };
        assert!(snapshot.covers(&a));
        assert!(snapshot.covers(&b));
    }

    #[test]
    fn union_merges_wildcard_privileges_for_the_same_pattern() {
        let pattern = |privilege: Privilege| WildcardGrantPattern {
            role: "alice".to_string(),
            object_type: ObjectType::Table,
            schema: "app".to_string(),
            privileges: BTreeSet::from([privilege]),
        };
        let a = config(
            &["alice"],
            &["app"],
            false,
            vec![pattern(Privilege::Select)],
        );
        let b = config(
            &["alice"],
            &["app"],
            false,
            vec![pattern(Privilege::Insert)],
        );

        let union = InspectConfig::union_of([&a, &b]);
        assert_eq!(union.wildcard_grants.len(), 1);
        assert_eq!(
            union.wildcard_grants[0].privileges,
            BTreeSet::from([Privilege::Select, Privilege::Insert])
        );
    }

    #[test]
    fn role_state_is_carried_through_unchanged() {
        let snapshot = snapshot();
        let result = derive_pure(&snapshot, &config(&["alice"], &[], false, vec![]));
        let expected: RoleState = role_row("alice").to_role_state();
        assert_eq!(result.graph.roles.get("alice"), Some(&expected));
    }
}
