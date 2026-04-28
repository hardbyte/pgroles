//! Database introspection for pgroles.
//!
//! Queries `pg_catalog` tables to build a [`pgroles_core::model::RoleGraph`]
//! representing the current state of roles, grants, default privileges, and
//! memberships in a PostgreSQL database.

pub mod cloud;
mod defaults;
mod memberships;
mod privileges;
mod public_grants;
mod roles;
mod safety;
mod version;

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;
use thiserror::Error;
use tracing::debug;

use pgroles_core::manifest::Privilege;
use pgroles_core::model::RoleGraph;
use pgroles_core::ownership::ManagedScope;

// Re-export the sub-modules' public items for testing / advanced use.
pub use cloud::{CloudProvider, PrivilegeLevel, detect_privilege_level};
pub use defaults::fetch_default_privileges;
pub use memberships::fetch_memberships;
pub use privileges::{fetch_database_privileges, fetch_privileges, fetch_relation_inventory};
pub use public_grants::{PublicGrants, fetch_public_grants, format_public_grants};
pub use roles::fetch_roles;
pub use safety::{
    DropRoleSafetyAssessment, DropRoleSafetyIssue, DropRoleSafetyReport, inspect_drop_role_safety,
};
pub use version::{PgVersion, detect_pg_version};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum InspectError {
    #[error("database query error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WildcardGrantPattern {
    pub role: String,
    pub object_type: pgroles_core::manifest::ObjectType,
    pub schema: String,
    /// The desired privileges for this wildcard grant. Used to construct a
    /// vacuously-satisfied wildcard when no objects of this type exist in the
    /// schema, so the diff engine sees exact parity and produces no change.
    pub privileges: std::collections::BTreeSet<pgroles_core::manifest::Privilege>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for what to inspect from the database.
///
/// Scoped to only the roles and schemas that the manifest manages, so we
/// don't pull in the entire pg_catalog.
#[derive(Debug, Clone)]
pub struct InspectConfig {
    /// The role names that the manifest manages (created by pgroles).
    /// Privileges and memberships are filtered to only include these roles.
    pub managed_roles: Vec<String>,

    /// The schema names that the manifest manages for schema-owner inspection.
    pub managed_schemas: Vec<String>,

    /// The schema names whose grants/default privileges are managed.
    pub privilege_schemas: Vec<String>,

    /// Whether to also inspect database-level privileges (CONNECT, CREATE, TEMPORARY).
    /// Usually only needed if the manifest includes database-level grants.
    pub include_database_privileges: bool,

    /// Wildcard grant selectors from the desired manifest.
    pub(crate) wildcard_grants: Vec<WildcardGrantPattern>,
}

impl InspectConfig {
    /// Create an `InspectConfig` from an expanded manifest by extracting
    /// the unique set of managed role names and schema names.
    pub fn from_expanded(
        expanded: &pgroles_core::manifest::ExpandedManifest,
        include_database_privileges: bool,
    ) -> Self {
        let mut managed_roles: BTreeSet<String> = BTreeSet::new();
        let mut managed_schemas: BTreeSet<String> = BTreeSet::new();
        // Key for deduplicating wildcard grants: (role, object_type, schema).
        type WildcardKey = (String, pgroles_core::manifest::ObjectType, String);
        let mut wildcard_map: BTreeMap<WildcardKey, BTreeSet<pgroles_core::manifest::Privilege>> =
            BTreeMap::new();

        // Collect role names
        for role_def in &expanded.roles {
            managed_roles.insert(role_def.name.clone());
        }

        // Collect schema names from grants
        for grant in &expanded.grants {
            if let Some(ref schema) = grant.object.schema {
                managed_schemas.insert(schema.clone());
            }
            // Schema-level grants use the name field as the schema name
            if grant.object.object_type == pgroles_core::manifest::ObjectType::Schema
                && let Some(ref name) = grant.object.name
            {
                managed_schemas.insert(name.clone());
            }
            if grant.object.name.as_deref() == Some("*")
                && !matches!(
                    grant.object.object_type,
                    pgroles_core::manifest::ObjectType::Schema
                        | pgroles_core::manifest::ObjectType::Database
                )
                && let Some(schema) = &grant.object.schema
            {
                let key = (grant.role.clone(), grant.object.object_type, schema.clone());
                wildcard_map
                    .entry(key)
                    .or_default()
                    .extend(grant.privileges.iter().copied());
            }
        }

        // Collect schema names from default privileges
        for dp in &expanded.default_privileges {
            managed_schemas.insert(dp.schema.clone());
        }

        for schema in &expanded.schemas {
            managed_schemas.insert(schema.name.clone());
        }

        Self {
            managed_roles: managed_roles.into_iter().collect(),
            managed_schemas: managed_schemas.clone().into_iter().collect(),
            privilege_schemas: managed_schemas.into_iter().collect(),
            include_database_privileges,
            wildcard_grants: wildcard_map
                .into_iter()
                .map(
                    |((role, object_type, schema), privileges)| WildcardGrantPattern {
                        role,
                        object_type,
                        schema,
                        privileges,
                    },
                )
                .collect(),
        }
    }

    /// Create an `InspectConfig` from a managed scope plus an expanded desired
    /// manifest so current-state inspection can be restricted to composed policy
    /// boundaries.
    pub fn from_managed_scope(
        scope: &ManagedScope,
        expanded: &pgroles_core::manifest::ExpandedManifest,
        include_database_privileges: bool,
    ) -> Self {
        let base = Self::from_expanded(expanded, include_database_privileges);

        Self {
            managed_roles: scope.roles.iter().cloned().collect(),
            managed_schemas: scope.schemas.keys().cloned().collect(),
            privilege_schemas: scope
                .schemas
                .iter()
                .filter_map(|(schema, managed)| managed.bindings.then_some(schema.clone()))
                .collect(),
            include_database_privileges,
            wildcard_grants: base
                .wildcard_grants
                .into_iter()
                .filter(|pattern| {
                    scope
                        .schemas
                        .get(&pattern.schema)
                        .is_some_and(|managed| managed.bindings)
                })
                .collect(),
        }
    }

    /// Extend the managed role scope with additional explicit role names.
    pub fn with_additional_roles<I>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut managed_roles: BTreeSet<String> = self.managed_roles.into_iter().collect();
        managed_roles.extend(roles);
        self.managed_roles = managed_roles.into_iter().collect();
        self
    }
}

// ---------------------------------------------------------------------------
// Top-level inspect function
// ---------------------------------------------------------------------------

/// Configuration for unscoped inspection (used by `generate` command).
#[derive(Debug, Clone)]
pub struct InspectAllConfig {
    /// Whether to exclude PostgreSQL system roles (pg_*, postgres).
    pub exclude_system_roles: bool,
}

/// Inspect all non-system roles and their privileges for manifest generation.
///
/// Unlike [`inspect`], this does not require a manifest to scope the query.
/// It discovers all user-defined roles, schemas they have access to, and
/// reconstructs the full RoleGraph.
pub async fn inspect_all(
    pool: &PgPool,
    config: &InspectAllConfig,
) -> Result<RoleGraph, InspectError> {
    let mut graph = RoleGraph::default();

    // Fetch all non-system roles.
    // fetch_roles(None) already excludes pg_* and postgres system roles.
    // The exclude_system_roles flag is reserved for future use with broader filtering.
    let _ = config.exclude_system_roles;
    let role_rows = fetch_roles(pool, None).await?;
    for row in &role_rows {
        graph.roles.insert(row.rolname.clone(), row.to_role_state());
    }
    debug!(found = graph.roles.len(), "roles discovered for generation");

    let role_names: Vec<String> = graph.roles.keys().cloned().collect();
    let role_refs: Vec<&str> = role_names.iter().map(|s| s.as_str()).collect();

    // Discover schemas these roles have access to
    let schema_rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT nspname::text FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%'
          AND nspname <> 'information_schema'
        ORDER BY nspname
        "#,
    )
    .fetch_all(pool)
    .await?;
    let schema_names: Vec<String> = schema_rows.into_iter().map(|r| r.0).collect();
    let schema_refs: Vec<&str> = schema_names.iter().map(|s| s.as_str()).collect();

    // Memberships
    let membership_rows = fetch_memberships(pool, Some(&role_refs)).await?;
    for row in &membership_rows {
        graph.memberships.insert(row.to_membership_edge());
    }

    // Schemas
    let schema_rows = fetch_schemas(pool, &schema_refs).await?;
    for row in &schema_rows {
        graph.schemas.insert(
            row.schema_name.clone(),
            pgroles_core::model::SchemaState {
                owner: Some(row.owner_name.clone()),
                owner_privileges: row.owner_privileges(),
            },
        );
    }

    if graph.roles.is_empty() && graph.schemas.is_empty() {
        return Ok(graph);
    }

    // Object privileges (no wildcard patterns for unscoped inspection)
    if !schema_refs.is_empty() {
        let privilege_grants = privileges::fetch_privileges_with_wildcards(
            pool,
            &schema_refs,
            &role_refs,
            &[], // no wildcard patterns
        )
        .await?;
        for (key, state) in privilege_grants {
            graph.grants.insert(key, state);
        }
        remove_redundant_schema_owner_grants(&mut graph);
    }

    // Database privileges
    let db_grants = fetch_database_privileges(pool, &role_refs).await?;
    for (key, state) in db_grants {
        graph.grants.insert(key, state);
    }

    // Default privileges
    if !schema_refs.is_empty() {
        let default_privs = fetch_default_privileges(pool, &schema_refs, &role_refs).await?;
        for (key, state) in default_privs {
            graph.default_privileges.insert(key, state);
        }
    }

    Ok(graph)
}

/// Inspect the current state of the database and build a `RoleGraph`.
///
/// Queries roles, memberships, object privileges, and default privileges,
/// scoped to the managed set defined by `config`.
pub async fn inspect(pool: &PgPool, config: &InspectConfig) -> Result<RoleGraph, InspectError> {
    let mut graph = RoleGraph::default();

    // Build &str slices for the query functions
    let role_refs: Vec<&str> = config.managed_roles.iter().map(|s| s.as_str()).collect();
    let schema_refs: Vec<&str> = config.managed_schemas.iter().map(|s| s.as_str()).collect();
    let privilege_schema_refs: Vec<&str> = config
        .privilege_schemas
        .iter()
        .map(|s| s.as_str())
        .collect();

    // --- Roles ---
    debug!(
        count = role_refs.len(),
        "inspecting managed roles from pg_roles"
    );
    let role_rows = fetch_roles(pool, Some(&role_refs)).await?;
    for row in &role_rows {
        graph.roles.insert(row.rolname.clone(), row.to_role_state());
    }
    debug!(found = graph.roles.len(), "roles inspected");

    // --- Memberships ---
    debug!("inspecting memberships from pg_auth_members");
    let membership_rows = fetch_memberships(pool, Some(&role_refs)).await?;
    for row in &membership_rows {
        graph.memberships.insert(row.to_membership_edge());
    }
    // Also add memberships where the member (not the group) is a managed role.
    // This captures cases like "user@example.com is a member of inventory-editor"
    // where inventory-editor is the group (managed) and user@example.com is the member.
    // The fetch above already handles this (filters on group role = managed).
    debug!(found = graph.memberships.len(), "memberships inspected");

    // --- Schemas ---
    if !schema_refs.is_empty() {
        debug!(schemas = ?schema_refs, "inspecting schemas from pg_namespace");
        let schema_rows = fetch_schemas(pool, &schema_refs).await?;
        for row in &schema_rows {
            graph.schemas.insert(
                row.schema_name.clone(),
                pgroles_core::model::SchemaState {
                    owner: Some(row.owner_name.clone()),
                    owner_privileges: row.owner_privileges(),
                },
            );
        }
        debug!(found = graph.schemas.len(), "schemas inspected");
    }

    // --- Object privileges ---
    if !privilege_schema_refs.is_empty() {
        debug!(
            schemas = ?privilege_schema_refs,
            "inspecting object privileges via aclexplode"
        );
        let privilege_grants = privileges::fetch_privileges_with_wildcards(
            pool,
            &privilege_schema_refs,
            &role_refs,
            &config.wildcard_grants,
        )
        .await?;
        for (key, state) in privilege_grants {
            graph.grants.insert(key, state);
        }
        remove_redundant_schema_owner_grants(&mut graph);
        debug!(found = graph.grants.len(), "privilege grants inspected");
    }

    // --- Database-level privileges ---
    if config.include_database_privileges {
        debug!("inspecting database-level privileges");
        let db_grants = fetch_database_privileges(pool, &role_refs).await?;
        for (key, state) in db_grants {
            graph.grants.insert(key, state);
        }
        debug!(
            total = graph.grants.len(),
            "grants after database privileges"
        );
    }

    // --- Default privileges ---
    if !privilege_schema_refs.is_empty() {
        debug!("inspecting default privileges from pg_default_acl");
        let default_privs =
            fetch_default_privileges(pool, &privilege_schema_refs, &role_refs).await?;
        for (key, state) in default_privs {
            graph.default_privileges.insert(key, state);
        }
        debug!(
            found = graph.default_privileges.len(),
            "default privileges inspected"
        );
    }

    Ok(graph)
}

/// Fetch the names of all non-system schemas in the target database.
///
/// Used for pre-flight validation — the operator checks that every schema
/// referenced by a policy exists before rendering GRANT statements that would
/// otherwise fail mid-transaction with `schema "X" does not exist`.
///
/// Returns a [`BTreeSet`] for efficient membership lookup. Excludes
/// `pg_catalog`, `pg_toast`, other `pg_*` schemas, and `information_schema`.
pub async fn fetch_existing_schemas(
    pool: &PgPool,
) -> Result<std::collections::BTreeSet<String>, InspectError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT nspname::text FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%'
          AND nspname <> 'information_schema'
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

#[derive(Debug, sqlx::FromRow)]
pub struct SchemaRow {
    pub schema_name: String,
    pub owner_name: String,
    pub owner_has_create: bool,
    pub owner_has_usage: bool,
}

impl SchemaRow {
    fn owner_privileges(&self) -> BTreeSet<Privilege> {
        let mut privileges = BTreeSet::new();
        if self.owner_has_create {
            privileges.insert(Privilege::Create);
        }
        if self.owner_has_usage {
            privileges.insert(Privilege::Usage);
        }
        privileges
    }
}

pub async fn fetch_schemas(
    pool: &PgPool,
    managed_schemas: &[&str],
) -> Result<Vec<SchemaRow>, InspectError> {
    let rows = sqlx::query_as::<_, SchemaRow>(
        r#"
        SELECT
            n.nspname AS schema_name,
            owner_role.rolname AS owner_name,
            has_schema_privilege(owner_role.rolname, n.nspname, 'CREATE') AS owner_has_create,
            has_schema_privilege(owner_role.rolname, n.nspname, 'USAGE') AS owner_has_usage
        FROM pg_namespace n
        JOIN pg_roles owner_role ON owner_role.oid = n.nspowner
        WHERE n.nspname = ANY($1)
        ORDER BY n.nspname
        "#,
    )
    .bind(managed_schemas)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

fn remove_redundant_schema_owner_grants(graph: &mut RoleGraph) {
    // Keep ordinary owner CREATE/USAGE management in SchemaState instead of the
    // grants map. This avoids noisy self-grants while still preserving drift
    // when the owner's ordinary privileges have been revoked.
    graph.grants.retain(|key, _| {
        if key.object_type != pgroles_core::manifest::ObjectType::Schema {
            return true;
        }

        let Some(schema_name) = key.name.as_deref() else {
            return true;
        };

        let Some(schema_state) = graph.schemas.get(schema_name) else {
            return true;
        };

        schema_state.owner.as_deref() != Some(key.role.as_str())
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::manifest::{expand_manifest, parse_manifest};
    use pgroles_core::ownership::ManagedSchemaScope;

    #[test]
    fn inspect_config_from_expanded_manifest() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT]
        on_type: table

schemas:
  - name: inventory
    profiles: [editor]
  - name: catalog
    profiles: [editor]

roles:
  - name: analytics
    login: true

grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let config = InspectConfig::from_expanded(&expanded, true);

        // Managed roles: inventory-editor, catalog-editor, analytics
        assert_eq!(config.managed_roles.len(), 3);
        assert!(
            config
                .managed_roles
                .contains(&"inventory-editor".to_string())
        );
        assert!(config.managed_roles.contains(&"catalog-editor".to_string()));
        assert!(config.managed_roles.contains(&"analytics".to_string()));

        // Managed schemas: inventory, catalog
        assert_eq!(config.managed_schemas.len(), 2);
        assert!(config.managed_schemas.contains(&"inventory".to_string()));
        assert!(config.managed_schemas.contains(&"catalog".to_string()));

        assert!(config.include_database_privileges);
        assert_eq!(config.privilege_schemas.len(), 2);
        assert_eq!(config.wildcard_grants.len(), 2);
    }

    #[test]
    fn inspect_config_can_include_retired_roles() {
        let yaml = r#"
roles:
  - name: analytics
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let config = InspectConfig::from_expanded(&expanded, false)
            .with_additional_roles(vec!["legacy-app".to_string(), "analytics".to_string()]);

        assert_eq!(config.managed_roles.len(), 2);
        assert!(config.managed_roles.contains(&"analytics".to_string()));
        assert!(config.managed_roles.contains(&"legacy-app".to_string()));
    }

    #[test]
    fn inspect_config_from_managed_scope_limits_privileges_to_binding_schemas() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }

schemas:
  - name: inventory
    owner: app_owner
    profiles: [editor]

roles:
  - name: app_owner
    login: false
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let scope = ManagedScope {
            roles: BTreeSet::from(["app_owner".to_string(), "inventory-editor".to_string()]),
            schemas: BTreeMap::from([(
                "inventory".to_string(),
                ManagedSchemaScope {
                    owner: true,
                    bindings: false,
                },
            )]),
        };

        let config = InspectConfig::from_managed_scope(&scope, &expanded, false);

        assert_eq!(config.managed_schemas, vec!["inventory".to_string()]);
        assert!(config.privilege_schemas.is_empty());
        assert!(config.wildcard_grants.is_empty());
    }

    #[test]
    fn remove_redundant_schema_owner_grants_keeps_only_non_owner_schema_grants() {
        let mut graph = RoleGraph::default();
        graph.schemas.insert(
            "inventory".to_string(),
            pgroles_core::model::SchemaState {
                owner: Some("inventory_owner".to_string()),
                owner_privileges: [pgroles_core::manifest::Privilege::Create]
                    .into_iter()
                    .collect(),
            },
        );
        graph.grants.insert(
            pgroles_core::model::GrantKey {
                role: "inventory_owner".to_string(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("inventory".to_string()),
            },
            pgroles_core::model::GrantState {
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        );
        graph.grants.insert(
            pgroles_core::model::GrantKey {
                role: "inventory_reader".to_string(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("inventory".to_string()),
            },
            pgroles_core::model::GrantState {
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        );

        remove_redundant_schema_owner_grants(&mut graph);

        assert_eq!(graph.grants.len(), 1);
        assert!(
            graph
                .grants
                .keys()
                .all(|key| key.role == "inventory_reader")
        );
    }
}
