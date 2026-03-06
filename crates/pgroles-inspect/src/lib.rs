//! Database introspection for pgroles.
//!
//! Queries `pg_catalog` tables to build a [`pgroles_core::model::RoleGraph`]
//! representing the current state of roles, grants, default privileges, and
//! memberships in a PostgreSQL database.

mod defaults;
mod memberships;
mod privileges;
mod roles;
mod safety;

use std::collections::BTreeSet;

use sqlx::PgPool;
use thiserror::Error;
use tracing::debug;

use pgroles_core::model::RoleGraph;

// Re-export the sub-modules' public items for testing / advanced use.
pub use defaults::fetch_default_privileges;
pub use memberships::fetch_memberships;
pub use privileges::{fetch_database_privileges, fetch_privileges};
pub use roles::fetch_roles;
pub use safety::{DropRoleSafetyIssue, DropRoleSafetyReport, inspect_drop_role_safety};

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

    /// The schema names that the manifest manages.
    /// Privileges and default privileges are scoped to these schemas.
    pub managed_schemas: Vec<String>,

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
        let mut wildcard_grants: BTreeSet<WildcardGrantPattern> = BTreeSet::new();

        // Collect role names
        for role_def in &expanded.roles {
            managed_roles.insert(role_def.name.clone());
        }

        // Collect schema names from grants
        for grant in &expanded.grants {
            if let Some(ref schema) = grant.on.schema {
                managed_schemas.insert(schema.clone());
            }
            // Schema-level grants use the name field as the schema name
            if grant.on.object_type == pgroles_core::manifest::ObjectType::Schema
                && let Some(ref name) = grant.on.name
            {
                managed_schemas.insert(name.clone());
            }
            if grant.on.name.as_deref() == Some("*")
                && !matches!(
                    grant.on.object_type,
                    pgroles_core::manifest::ObjectType::Schema
                        | pgroles_core::manifest::ObjectType::Database
                )
                && let Some(schema) = &grant.on.schema
            {
                wildcard_grants.insert(WildcardGrantPattern {
                    role: grant.role.clone(),
                    object_type: grant.on.object_type,
                    schema: schema.clone(),
                });
            }
        }

        // Collect schema names from default privileges
        for dp in &expanded.default_privileges {
            managed_schemas.insert(dp.schema.clone());
        }

        Self {
            managed_roles: managed_roles.into_iter().collect(),
            managed_schemas: managed_schemas.into_iter().collect(),
            include_database_privileges,
            wildcard_grants: wildcard_grants.into_iter().collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level inspect function
// ---------------------------------------------------------------------------

/// Inspect the current state of the database and build a `RoleGraph`.
///
/// Queries roles, memberships, object privileges, and default privileges,
/// scoped to the managed set defined by `config`.
pub async fn inspect(pool: &PgPool, config: &InspectConfig) -> Result<RoleGraph, InspectError> {
    let mut graph = RoleGraph::default();

    // Build &str slices for the query functions
    let role_refs: Vec<&str> = config.managed_roles.iter().map(|s| s.as_str()).collect();
    let schema_refs: Vec<&str> = config.managed_schemas.iter().map(|s| s.as_str()).collect();

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

    // --- Object privileges ---
    if !schema_refs.is_empty() {
        debug!(
            schemas = ?schema_refs,
            "inspecting object privileges via aclexplode"
        );
        let privilege_grants = privileges::fetch_privileges_with_wildcards(
            pool,
            &schema_refs,
            &role_refs,
            &config.wildcard_grants,
        )
        .await?;
        for (key, state) in privilege_grants {
            graph.grants.insert(key, state);
        }
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
    if !schema_refs.is_empty() {
        debug!("inspecting default privileges from pg_default_acl");
        let default_privs = fetch_default_privileges(pool, &schema_refs, &role_refs).await?;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::manifest::{expand_manifest, parse_manifest};

    #[test]
    fn inspect_config_from_expanded_manifest() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT]
        on: { type: table, name: "*" }
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
    on: { type: database, name: mydb }
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
        assert_eq!(config.wildcard_grants.len(), 2);
    }
}
