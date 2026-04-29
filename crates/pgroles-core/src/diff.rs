//! Convergent diff engine.
//!
//! Compares two [`RoleGraph`] instances (current vs desired) and produces an
//! ordered list of [`Change`] operations needed to bring the database from
//! its current state to the desired state.
//!
//! The model is convergent: anything present in the current state but absent
//! from the desired state is revoked/dropped. This is the Terraform-style
//! "manifest is the entire truth" approach.

use std::collections::BTreeSet;

use crate::manifest::{ObjectType, Privilege, RoleRetirement};
use crate::model::{
    DefaultPrivKey, GrantKey, MembershipEdge, RoleAttribute, RoleGraph, RoleState,
    default_schema_owner_privileges,
};

// ---------------------------------------------------------------------------
// Change enum
// ---------------------------------------------------------------------------

/// A single change to be applied to the database.
///
/// Changes are produced in dependency order by [`diff`]:
/// 1. Create roles (before granting anything to them)
/// 2. Alter roles (attribute changes)
/// 3. Grant privileges
/// 4. Set default privileges
/// 5. Remove memberships
/// 6. Add memberships
/// 7. Revoke default privileges
/// 8. Revoke privileges
/// 9. Drop roles (after revoking everything from them)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Change {
    /// Create a new role with the given attributes.
    CreateRole { name: String, state: RoleState },

    /// Create a schema, optionally assigning an owner up front.
    CreateSchema { name: String, owner: Option<String> },

    /// Change an existing schema's owner.
    AlterSchemaOwner { name: String, owner: String },

    /// Restore the schema owner's ordinary CREATE/USAGE privileges.
    EnsureSchemaOwnerPrivileges {
        name: String,
        owner: String,
        privileges: BTreeSet<Privilege>,
    },

    /// Alter an existing role's attributes.
    AlterRole {
        name: String,
        attributes: Vec<RoleAttribute>,
    },

    /// Update a role's comment (via COMMENT ON ROLE).
    SetComment {
        name: String,
        comment: Option<String>,
    },

    /// Grant privileges on an object to a role.
    Grant {
        role: String,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
    },

    /// Revoke privileges on an object from a role.
    Revoke {
        role: String,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
    },

    /// Set default privileges (ALTER DEFAULT PRIVILEGES ... GRANT ...).
    SetDefaultPrivilege {
        owner: String,
        schema: String,
        on_type: ObjectType,
        grantee: String,
        privileges: BTreeSet<Privilege>,
    },

    /// Revoke default privileges (ALTER DEFAULT PRIVILEGES ... REVOKE ...).
    RevokeDefaultPrivilege {
        owner: String,
        schema: String,
        on_type: ObjectType,
        grantee: String,
        privileges: BTreeSet<Privilege>,
    },

    /// Grant membership (GRANT role TO member).
    AddMember {
        role: String,
        member: String,
        inherit: bool,
        admin: bool,
    },

    /// Revoke membership (REVOKE role FROM member).
    RemoveMember { role: String, member: String },

    /// Reassign owned objects to a successor role before drop.
    ReassignOwned { from_role: String, to_role: String },

    /// Drop owned objects and revoke remaining privileges before drop.
    DropOwned { role: String },

    /// Terminate other active sessions before dropping a role.
    TerminateSessions { role: String },

    /// Set a role's password using a SCRAM-SHA-256 verifier.
    ///
    /// The `password` field contains a pre-computed SCRAM-SHA-256 verifier
    /// string (not cleartext). PostgreSQL detects the `SCRAM-SHA-256$` prefix
    /// and stores it directly without re-hashing.
    ///
    /// This change is injected by [`inject_password_changes`] after the core
    /// diff engine runs. The diff engine itself does not handle passwords
    /// because they cannot be read back from the database for comparison.
    SetPassword { name: String, password: String },

    /// Drop a role.
    DropRole { name: String },
}

// ---------------------------------------------------------------------------
// Reconciliation modes
// ---------------------------------------------------------------------------

/// Controls how aggressively pgroles converges the database to the manifest.
///
/// The diff engine always computes the full set of changes. The reconciliation
/// mode acts as a **post-filter** on the resulting `Vec<Change>`, stripping
/// out changes that the operator does not want applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub enum ReconciliationMode {
    /// Full convergence — the manifest is the entire truth.
    ///
    /// All changes (creates, alters, grants, revokes, drops) are applied.
    /// Anything present in the database but absent from the manifest is
    /// revoked or dropped.
    #[default]
    Authoritative,

    /// Only grant, never revoke — safe for incremental adoption.
    ///
    /// Additive mode filters out all destructive changes:
    /// - `Revoke` / `RevokeDefaultPrivilege`
    /// - `RemoveMember`
    /// - `DropRole` and its retirement steps (`TerminateSessions`,
    ///   `ReassignOwned`, `DropOwned`)
    ///
    /// Use this when onboarding pgroles into an existing environment where
    /// you want to guarantee that no existing access is removed.
    Additive,

    /// Manage declared resources fully, but never drop undeclared roles.
    ///
    /// Adopt mode is identical to authoritative **except** that it filters out
    /// `DropRole` and associated retirement steps (`TerminateSessions`,
    /// `ReassignOwned`, `DropOwned`). Revokes within the managed scope are
    /// still applied.
    ///
    /// Use this for brownfield onboarding where you want full privilege
    /// convergence for declared roles but don't want pgroles to drop roles
    /// it doesn't know about.
    Adopt,
}

impl std::fmt::Display for ReconciliationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconciliationMode::Authoritative => write!(f, "authoritative"),
            ReconciliationMode::Additive => write!(f, "additive"),
            ReconciliationMode::Adopt => write!(f, "adopt"),
        }
    }
}

/// Filter a list of changes according to the reconciliation mode.
///
/// - **Authoritative**: returns all changes unmodified.
/// - **Additive**: strips revokes, membership removals, owner transfers,
///   role rewrites, role drops, and retirement cleanup steps.
/// - **Adopt**: strips role drops and retirement cleanup steps, but keeps
///   revokes and membership removals.
pub fn filter_changes(changes: Vec<Change>, mode: ReconciliationMode) -> Vec<Change> {
    match mode {
        ReconciliationMode::Authoritative => changes,
        ReconciliationMode::Additive => filter_additive_changes(changes),
        ReconciliationMode::Adopt => changes
            .into_iter()
            .filter(|change| !is_role_drop_or_retirement(change))
            .collect(),
    }
}

fn filter_additive_changes(changes: Vec<Change>) -> Vec<Change> {
    let skipped_owner_transfers: BTreeSet<(String, String)> = changes
        .iter()
        .filter_map(|change| match change {
            Change::AlterSchemaOwner { name, owner } => Some((name.clone(), owner.clone())),
            _ => None,
        })
        .collect();

    changes
        .into_iter()
        .filter(|change| match change {
            Change::EnsureSchemaOwnerPrivileges { name, owner, .. } => {
                !skipped_owner_transfers.contains(&(name.clone(), owner.clone()))
            }
            Change::SetDefaultPrivilege { schema, owner, .. } => {
                !skipped_owner_transfers.contains(&(schema.clone(), owner.clone()))
            }
            Change::AlterRole { .. } | Change::SetComment { .. } => false,
            _ => !is_destructive(change),
        })
        .collect()
}

/// Returns `true` for any change that removes access or drops a role.
fn is_destructive(change: &Change) -> bool {
    matches!(
        change,
        Change::AlterSchemaOwner { .. }
            | Change::Revoke { .. }
            | Change::RevokeDefaultPrivilege { .. }
            | Change::RemoveMember { .. }
            | Change::DropRole { .. }
            | Change::DropOwned { .. }
            | Change::ReassignOwned { .. }
            | Change::TerminateSessions { .. }
    )
}

/// Returns `true` for role drops and their associated retirement cleanup steps.
fn is_role_drop_or_retirement(change: &Change) -> bool {
    matches!(
        change,
        Change::DropRole { .. }
            | Change::DropOwned { .. }
            | Change::ReassignOwned { .. }
            | Change::TerminateSessions { .. }
    )
}

// ---------------------------------------------------------------------------
// Diff function
// ---------------------------------------------------------------------------

/// Compute the list of changes needed to bring `current` to `desired`.
///
/// Changes are ordered so that dependencies are respected:
/// creates before grants, revokes before drops, etc.
pub fn diff(current: &RoleGraph, desired: &RoleGraph) -> Vec<Change> {
    let mut creates = Vec::new();
    let mut alters = Vec::new();
    let mut schema_changes = Vec::new();
    let mut schema_grants = Vec::new();
    let mut grants = Vec::new();
    let mut set_defaults = Vec::new();
    let mut add_members = Vec::new();
    let mut remove_members = Vec::new();
    let mut revoke_defaults = Vec::new();
    let mut revokes = Vec::new();
    let mut drops = Vec::new();

    // ----- Roles -----

    // Roles in desired but not in current → CREATE
    for (name, desired_state) in &desired.roles {
        match current.roles.get(name) {
            None => {
                creates.push(Change::CreateRole {
                    name: name.clone(),
                    state: desired_state.clone(),
                });
            }
            Some(current_state) => {
                // Role exists — check for attribute changes
                let attribute_changes = current_state.changed_attributes(desired_state);
                if !attribute_changes.is_empty() {
                    alters.push(Change::AlterRole {
                        name: name.clone(),
                        attributes: attribute_changes,
                    });
                }
                // Check comment change
                if current_state.comment != desired_state.comment {
                    alters.push(Change::SetComment {
                        name: name.clone(),
                        comment: desired_state.comment.clone(),
                    });
                }
            }
        }
    }

    // Roles in current but not in desired → DROP
    for name in current.roles.keys() {
        if !desired.roles.contains_key(name) {
            drops.push(Change::DropRole { name: name.clone() });
        }
    }

    // ----- Schemas -----

    diff_schemas(current, desired, &mut schema_changes, &mut schema_grants);

    // ----- Grants -----

    diff_grants(current, desired, &mut grants, &mut revokes);

    // ----- Default privileges -----

    diff_default_privileges(current, desired, &mut set_defaults, &mut revoke_defaults);

    // ----- Memberships -----

    diff_memberships(current, desired, &mut add_members, &mut remove_members);

    // ----- Assemble in dependency order -----
    let mut changes = Vec::new();
    changes.extend(creates);
    changes.extend(alters);
    changes.extend(schema_changes);
    changes.extend(schema_grants);
    changes.extend(grants);
    changes.extend(set_defaults);
    changes.extend(remove_members);
    changes.extend(add_members);
    changes.extend(revoke_defaults);
    changes.extend(revokes);
    changes.extend(drops);
    changes
}

fn diff_schemas(
    current: &RoleGraph,
    desired: &RoleGraph,
    schema_out: &mut Vec<Change>,
    grant_out: &mut Vec<Change>,
) {
    for (name, desired_state) in &desired.schemas {
        match current.schemas.get(name) {
            None => schema_out.push(Change::CreateSchema {
                name: name.clone(),
                owner: desired_state.owner.clone(),
            }),
            Some(current_state) => {
                if current_state.owner != desired_state.owner
                    && let Some(owner) = &desired_state.owner
                {
                    schema_out.push(Change::AlterSchemaOwner {
                        name: name.clone(),
                        owner: owner.clone(),
                    });
                }
            }
        }

        let Some(owner) = desired_state.owner.as_deref() else {
            continue;
        };

        if !current.schemas.contains_key(name) {
            continue;
        }

        let expected_privileges = default_schema_owner_privileges(owner);
        let current_privileges = current
            .schemas
            .get(name)
            .map(|state| state.owner_privileges.clone())
            .unwrap_or_default();
        let missing_privileges: BTreeSet<Privilege> = expected_privileges
            .difference(&current_privileges)
            .copied()
            .collect();

        if !missing_privileges.is_empty() {
            grant_out.push(Change::EnsureSchemaOwnerPrivileges {
                name: name.clone(),
                owner: owner.to_string(),
                privileges: missing_privileges,
            });
        }
    }
}

/// Augment a diff plan with explicit role-retirement actions.
///
/// Retirement steps are inserted immediately before the matching `DropRole`
/// so the final plan remains dependency-safe:
/// `TERMINATE SESSIONS` → `REASSIGN OWNED` → `DROP OWNED` → `DROP ROLE`.
pub fn apply_role_retirements(changes: Vec<Change>, retirements: &[RoleRetirement]) -> Vec<Change> {
    if retirements.is_empty() {
        return changes;
    }

    let retirement_by_role: std::collections::BTreeMap<&str, &RoleRetirement> = retirements
        .iter()
        .map(|retirement| (retirement.role.as_str(), retirement))
        .collect();

    let mut planned = Vec::with_capacity(changes.len());
    for change in changes {
        if let Change::DropRole { name } = &change
            && let Some(retirement) = retirement_by_role.get(name.as_str())
        {
            if retirement.terminate_sessions {
                planned.push(Change::TerminateSessions { role: name.clone() });
            }
            if let Some(successor) = &retirement.reassign_owned_to {
                planned.push(Change::ReassignOwned {
                    from_role: name.clone(),
                    to_role: successor.clone(),
                });
            }
            if retirement.drop_owned {
                planned.push(Change::DropOwned { role: name.clone() });
            }
        }
        planned.push(change);
    }

    planned
}

// ---------------------------------------------------------------------------
// Password injection
// ---------------------------------------------------------------------------

/// Resolve password sources from environment variables.
///
/// Returns a map of role name → resolved password for every role that declares
/// a `password.from_env` source. Returns an error if a referenced environment
/// variable is not set.
pub fn resolve_passwords(
    roles: &[crate::manifest::RoleDefinition],
) -> Result<std::collections::BTreeMap<String, String>, PasswordResolutionError> {
    let mut resolved = std::collections::BTreeMap::new();
    for role in roles {
        if let Some(source) = &role.password {
            let value = std::env::var(&source.from_env).map_err(|_| {
                PasswordResolutionError::MissingEnvVar {
                    role: role.name.clone(),
                    env_var: source.from_env.clone(),
                }
            })?;
            if value.is_empty() {
                return Err(PasswordResolutionError::EmptyPassword {
                    role: role.name.clone(),
                    env_var: source.from_env.clone(),
                });
            }
            resolved.insert(role.name.clone(), value);
        }
    }
    Ok(resolved)
}

/// Errors that can occur during password resolution.
#[derive(Debug, thiserror::Error)]
pub enum PasswordResolutionError {
    #[error("environment variable \"{env_var}\" for role \"{role}\" password is not set")]
    MissingEnvVar { role: String, env_var: String },

    #[error("environment variable \"{env_var}\" for role \"{role}\" password is empty")]
    EmptyPassword { role: String, env_var: String },
}

/// Inject `SetPassword` changes into a plan for roles that declare passwords.
///
/// For newly created roles, the `SetPassword` is inserted immediately after the
/// `CreateRole`. For existing roles with a password source, a `SetPassword` is
/// appended after all creates/alters (ensuring the role exists).
///
/// Cleartext passwords are converted to SCRAM-SHA-256 verifiers before being
/// placed in `SetPassword` changes, so the cleartext never appears in generated
/// SQL. PostgreSQL detects the `SCRAM-SHA-256$` prefix and stores the verifier
/// directly.
///
/// This function should be called after `diff()` and `apply_role_retirements()`.
pub fn inject_password_changes(
    changes: Vec<Change>,
    resolved_passwords: &std::collections::BTreeMap<String, String>,
) -> Vec<Change> {
    if resolved_passwords.is_empty() {
        return changes;
    }

    // Track which roles have CreateRole in the plan (newly created roles).
    let created_roles: std::collections::BTreeSet<String> = changes
        .iter()
        .filter_map(|c| match c {
            Change::CreateRole { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();

    let mut result = Vec::with_capacity(changes.len() + resolved_passwords.len());

    // Insert SetPassword immediately after CreateRole for new roles.
    for change in changes {
        if let Change::CreateRole { ref name, .. } = change
            && let Some(password) = resolved_passwords.get(name.as_str())
        {
            let role_name = name.clone();
            let verifier =
                crate::scram::compute_verifier(password, crate::scram::DEFAULT_ITERATIONS);
            result.push(change);
            result.push(Change::SetPassword {
                name: role_name,
                password: verifier,
            });
            continue;
        }
        result.push(change);
    }

    // For existing roles (not newly created), append SetPassword after all creates/alters.
    for (role_name, password) in resolved_passwords {
        if !created_roles.contains(role_name) {
            let verifier =
                crate::scram::compute_verifier(password, crate::scram::DEFAULT_ITERATIONS);
            result.push(Change::SetPassword {
                name: role_name.clone(),
                password: verifier,
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Grant diffing
// ---------------------------------------------------------------------------

fn diff_grants(
    current: &RoleGraph,
    desired: &RoleGraph,
    grants_out: &mut Vec<Change>,
    revokes_out: &mut Vec<Change>,
) {
    // Grants in desired but not in current → GRANT (full set)
    // Grants in both → diff the privilege sets
    for (key, desired_state) in &desired.grants {
        match current.grants.get(key) {
            None => {
                // Entirely new grant target — grant the full set
                grants_out.push(change_grant(key, &desired_state.privileges));
            }
            Some(current_state) => {
                // Grant target exists — find privileges to add/remove
                let to_add: BTreeSet<Privilege> = desired_state
                    .privileges
                    .difference(&current_state.privileges)
                    .copied()
                    .collect();
                let to_remove: BTreeSet<Privilege> = current_state
                    .privileges
                    .difference(&desired_state.privileges)
                    .copied()
                    .collect();

                if !to_add.is_empty() {
                    grants_out.push(change_grant(key, &to_add));
                }
                if !to_remove.is_empty() {
                    revokes_out.push(change_revoke(key, &to_remove));
                }
            }
        }
    }

    // Grant targets in current but not in desired → REVOKE all
    for (key, current_state) in &current.grants {
        if !desired.grants.contains_key(key) {
            revokes_out.push(change_revoke(key, &current_state.privileges));
        }
    }
}

fn change_grant(key: &GrantKey, privileges: &BTreeSet<Privilege>) -> Change {
    Change::Grant {
        role: key.role.clone(),
        privileges: privileges.clone(),
        object_type: key.object_type,
        schema: key.schema.clone(),
        name: key.name.clone(),
    }
}

fn change_revoke(key: &GrantKey, privileges: &BTreeSet<Privilege>) -> Change {
    Change::Revoke {
        role: key.role.clone(),
        privileges: privileges.clone(),
        object_type: key.object_type,
        schema: key.schema.clone(),
        name: key.name.clone(),
    }
}

// ---------------------------------------------------------------------------
// Default privilege diffing
// ---------------------------------------------------------------------------

fn diff_default_privileges(
    current: &RoleGraph,
    desired: &RoleGraph,
    set_out: &mut Vec<Change>,
    revoke_out: &mut Vec<Change>,
) {
    for (key, desired_state) in &desired.default_privileges {
        match current.default_privileges.get(key) {
            None => {
                set_out.push(change_set_default(key, &desired_state.privileges));
            }
            Some(current_state) => {
                let to_add: BTreeSet<Privilege> = desired_state
                    .privileges
                    .difference(&current_state.privileges)
                    .copied()
                    .collect();
                let to_remove: BTreeSet<Privilege> = current_state
                    .privileges
                    .difference(&desired_state.privileges)
                    .copied()
                    .collect();

                if !to_add.is_empty() {
                    set_out.push(change_set_default(key, &to_add));
                }
                if !to_remove.is_empty() {
                    revoke_out.push(change_revoke_default(key, &to_remove));
                }
            }
        }
    }

    for (key, current_state) in &current.default_privileges {
        if !desired.default_privileges.contains_key(key) {
            revoke_out.push(change_revoke_default(key, &current_state.privileges));
        }
    }
}

fn change_set_default(key: &DefaultPrivKey, privileges: &BTreeSet<Privilege>) -> Change {
    Change::SetDefaultPrivilege {
        owner: key.owner.clone(),
        schema: key.schema.clone(),
        on_type: key.on_type,
        grantee: key.grantee.clone(),
        privileges: privileges.clone(),
    }
}

fn change_revoke_default(key: &DefaultPrivKey, privileges: &BTreeSet<Privilege>) -> Change {
    Change::RevokeDefaultPrivilege {
        owner: key.owner.clone(),
        schema: key.schema.clone(),
        on_type: key.on_type,
        grantee: key.grantee.clone(),
        privileges: privileges.clone(),
    }
}

// ---------------------------------------------------------------------------
// Membership diffing
// ---------------------------------------------------------------------------

fn diff_memberships(
    current: &RoleGraph,
    desired: &RoleGraph,
    add_out: &mut Vec<Change>,
    remove_out: &mut Vec<Change>,
) {
    // We compare memberships by (role, member) as the key.
    // If inherit/admin flags changed, we remove and re-add.

    // Build lookup maps: (role, member) → MembershipEdge
    let current_map: std::collections::BTreeMap<(&str, &str), &MembershipEdge> = current
        .memberships
        .iter()
        .map(|edge| ((edge.role.as_str(), edge.member.as_str()), edge))
        .collect();
    let desired_map: std::collections::BTreeMap<(&str, &str), &MembershipEdge> = desired
        .memberships
        .iter()
        .map(|edge| ((edge.role.as_str(), edge.member.as_str()), edge))
        .collect();

    // Desired but not current → add
    // Desired and current but different flags → remove + add
    for (&(role, member), &desired_edge) in &desired_map {
        match current_map.get(&(role, member)) {
            None => {
                add_out.push(Change::AddMember {
                    role: desired_edge.role.clone(),
                    member: desired_edge.member.clone(),
                    inherit: desired_edge.inherit,
                    admin: desired_edge.admin,
                });
            }
            Some(current_edge) => {
                if current_edge.inherit != desired_edge.inherit
                    || current_edge.admin != desired_edge.admin
                {
                    // Flags changed — revoke and re-grant
                    remove_out.push(Change::RemoveMember {
                        role: current_edge.role.clone(),
                        member: current_edge.member.clone(),
                    });
                    add_out.push(Change::AddMember {
                        role: desired_edge.role.clone(),
                        member: desired_edge.member.clone(),
                        inherit: desired_edge.inherit,
                        admin: desired_edge.admin,
                    });
                }
            }
        }
    }

    // Current but not desired → remove
    for &(role, member) in current_map.keys() {
        if !desired_map.contains_key(&(role, member)) {
            remove_out.push(Change::RemoveMember {
                role: role.to_string(),
                member: member.to_string(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DefaultPrivState, GrantState, SchemaState, default_schema_owner_privileges,
    };

    /// Helper: build an empty graph.
    fn empty_graph() -> RoleGraph {
        RoleGraph::default()
    }

    fn managed_schema(owner: &str) -> SchemaState {
        SchemaState {
            owner: Some(owner.to_string()),
            owner_privileges: default_schema_owner_privileges(owner),
        }
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        let changes = diff(&empty_graph(), &empty_graph());
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_creates_new_roles() {
        let current = empty_graph();
        let mut desired = empty_graph();
        desired
            .roles
            .insert("new-role".to_string(), RoleState::default());

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::CreateRole { name, .. } if name == "new-role"));
    }

    #[test]
    fn diff_drops_removed_roles() {
        let mut current = empty_graph();
        current
            .roles
            .insert("old-role".to_string(), RoleState::default());
        let desired = empty_graph();

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::DropRole { name } if name == "old-role"));
    }

    #[test]
    fn diff_alters_changed_role_attributes() {
        let mut current = empty_graph();
        current
            .roles
            .insert("role1".to_string(), RoleState::default());

        let mut desired = empty_graph();
        desired.roles.insert(
            "role1".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AlterRole { name, attributes } => {
                assert_eq!(name, "role1");
                assert!(attributes.contains(&RoleAttribute::Login(true)));
            }
            other => panic!("expected AlterRole, got: {other:?}"),
        }
    }

    #[test]
    fn diff_creates_missing_schema() {
        let current = empty_graph();
        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("inventory_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            Change::CreateSchema { name, owner }
                if name == "inventory" && owner.as_deref() == Some("inventory_owner")
        ));
    }

    #[test]
    fn diff_alters_schema_owner_when_different() {
        let mut current = empty_graph();
        current
            .schemas
            .insert("inventory".to_string(), managed_schema("old_owner"));

        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("new_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            Change::AlterSchemaOwner { name, owner }
                if name == "inventory" && owner == "new_owner"
        ));
    }

    #[test]
    fn diff_does_not_alter_schema_owner_when_unmanaged() {
        let mut current = empty_graph();
        current
            .schemas
            .insert("inventory".to_string(), managed_schema("old_owner"));

        let mut desired = empty_graph();
        desired.schemas.insert(
            "inventory".to_string(),
            SchemaState {
                owner: None,
                owner_privileges: BTreeSet::new(),
            },
        );

        let changes = diff(&current, &desired);
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_restores_missing_owner_schema_privileges() {
        let mut current = empty_graph();
        current.schemas.insert(
            "inventory".to_string(),
            SchemaState {
                owner: Some("inventory_owner".to_string()),
                owner_privileges: BTreeSet::from([Privilege::Usage]),
            },
        );

        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("inventory_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            Change::EnsureSchemaOwnerPrivileges {
                name,
                owner,
                privileges,
            } if name == "inventory"
                && owner == "inventory_owner"
                && privileges == &BTreeSet::from([Privilege::Create])
        ));
    }

    #[test]
    fn diff_restores_owner_schema_privileges_after_transfer() {
        let mut current = empty_graph();
        current.schemas.insert(
            "inventory".to_string(),
            SchemaState {
                owner: Some("old_owner".to_string()),
                owner_privileges: BTreeSet::from([Privilege::Usage]),
            },
        );

        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("new_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2);
        assert!(matches!(
            &changes[0],
            Change::AlterSchemaOwner { name, owner }
                if name == "inventory" && owner == "new_owner"
        ));
        assert!(matches!(
            &changes[1],
            Change::EnsureSchemaOwnerPrivileges {
                name,
                owner,
                privileges,
            } if name == "inventory"
                && owner == "new_owner"
                && privileges == &BTreeSet::from([Privilege::Create])
        ));
    }

    #[test]
    fn diff_grants_new_privileges() {
        let current = empty_graph();
        let mut desired = empty_graph();
        let key = GrantKey {
            role: "r1".to_string(),
            object_type: ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        };
        desired.grants.insert(
            key,
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::Grant {
                role, privileges, ..
            } => {
                assert_eq!(role, "r1");
                assert!(privileges.contains(&Privilege::Select));
                assert!(privileges.contains(&Privilege::Insert));
            }
            other => panic!("expected Grant, got: {other:?}"),
        }
    }

    #[test]
    fn diff_revokes_removed_privileges() {
        let mut current = empty_graph();
        let key = GrantKey {
            role: "r1".to_string(),
            object_type: ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        };
        current.grants.insert(
            key.clone(),
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );

        let mut desired = empty_graph();
        desired.grants.insert(
            key,
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::Revoke {
                role, privileges, ..
            } => {
                assert_eq!(role, "r1");
                assert!(privileges.contains(&Privilege::Insert));
                assert!(!privileges.contains(&Privilege::Select));
            }
            other => panic!("expected Revoke, got: {other:?}"),
        }
    }

    #[test]
    fn diff_revokes_entire_grant_target_when_absent_from_desired() {
        let mut current = empty_graph();
        let key = GrantKey {
            role: "r1".to_string(),
            object_type: ObjectType::Schema,
            schema: None,
            name: Some("myschema".to_string()),
        };
        current.grants.insert(
            key,
            GrantState {
                privileges: BTreeSet::from([Privilege::Usage]),
            },
        );
        let desired = empty_graph();

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::Revoke { role, .. } if role == "r1"));
    }

    #[test]
    fn diff_adds_memberships() {
        let current = empty_graph();
        let mut desired = empty_graph();
        desired.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        });

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AddMember {
                role,
                member,
                inherit,
                admin,
            } => {
                assert_eq!(role, "editors");
                assert_eq!(member, "user@example.com");
                assert!(*inherit);
                assert!(!admin);
            }
            other => panic!("expected AddMember, got: {other:?}"),
        }
    }

    #[test]
    fn diff_removes_memberships() {
        let mut current = empty_graph();
        current.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "old@example.com".to_string(),
            inherit: true,
            admin: false,
        });
        let desired = empty_graph();

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], Change::RemoveMember { role, member } if role == "editors" && member == "old@example.com")
        );
    }

    #[test]
    fn diff_re_grants_membership_when_flags_change() {
        let mut current = empty_graph();
        current.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        });

        let mut desired = empty_graph();
        desired.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: true, // changed!
        });

        let changes = diff(&current, &desired);
        // Should produce remove + add
        assert_eq!(changes.len(), 2);
        assert!(matches!(
            &changes[0],
            Change::RemoveMember { role, member }
                if role == "editors" && member == "user@example.com"
        ));
        assert!(matches!(
            &changes[1],
            Change::AddMember {
                role,
                member,
                admin: true,
                ..
            } if role == "editors" && member == "user@example.com"
        ));
    }

    #[test]
    fn diff_default_privileges_add_and_revoke() {
        let mut current = empty_graph();
        let key = DefaultPrivKey {
            owner: "app_owner".to_string(),
            schema: "inventory".to_string(),
            on_type: ObjectType::Table,
            grantee: "inventory-editor".to_string(),
        };
        current.default_privileges.insert(
            key.clone(),
            DefaultPrivState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Delete]),
            },
        );

        let mut desired = empty_graph();
        desired.default_privileges.insert(
            key,
            DefaultPrivState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );

        let changes = diff(&current, &desired);
        // Should add INSERT and revoke DELETE
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| matches!(
            c,
            Change::SetDefaultPrivilege { privileges, .. } if privileges.contains(&Privilege::Insert)
        )));
        assert!(changes.iter().any(|c| matches!(
            c,
            Change::RevokeDefaultPrivilege { privileges, .. } if privileges.contains(&Privilege::Delete)
        )));
    }

    #[test]
    fn diff_ordering_creates_before_drops() {
        let mut current = empty_graph();
        current
            .roles
            .insert("old-role".to_string(), RoleState::default());

        let mut desired = empty_graph();
        desired
            .roles
            .insert("new-role".to_string(), RoleState::default());

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2);

        // Creates should come before drops
        let create_idx = changes
            .iter()
            .position(|c| matches!(c, Change::CreateRole { .. }))
            .unwrap();
        let schema_idx = changes
            .iter()
            .position(|c| matches!(c, Change::CreateSchema { .. }))
            .unwrap_or(create_idx);
        let drop_idx = changes
            .iter()
            .position(|c| matches!(c, Change::DropRole { .. }))
            .unwrap();
        assert!(create_idx <= schema_idx);
        assert!(schema_idx < drop_idx);
    }

    #[test]
    fn diff_identical_graphs_produce_no_changes() {
        let mut graph = empty_graph();
        graph
            .roles
            .insert("role1".to_string(), RoleState::default());
        graph.grants.insert(
            GrantKey {
                role: "role1".to_string(),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        graph.memberships.insert(MembershipEdge {
            role: "role1".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        });

        let changes = diff(&graph, &graph);
        assert!(
            changes.is_empty(),
            "identical graphs should produce no changes"
        );
    }

    /// Integration test: round-trip from manifest → expand → model → diff
    #[test]
    fn manifest_to_diff_integration() {
        use crate::manifest::{expand_manifest, parse_manifest};
        use crate::model::RoleGraph;

        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table

schemas:
  - name: inventory
    owner: inventory_owner
    profiles: [editor]

memberships:
  - role: inventory-editor
    members:
      - name: "user@example.com"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let desired =
            RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap();

        // Current state is empty — everything should be created
        let current = RoleGraph::default();
        let changes = diff(&current, &desired);

        // Should have: 1 CreateRole, 1 CreateSchema, 2 Grants, 1 SetDefaultPrivilege, 1 AddMember
        let create_count = changes
            .iter()
            .filter(|c| matches!(c, Change::CreateRole { .. }))
            .count();
        let create_schema_count = changes
            .iter()
            .filter(|c| matches!(c, Change::CreateSchema { .. }))
            .count();
        let grant_count = changes
            .iter()
            .filter(|c| matches!(c, Change::Grant { .. }))
            .count();
        let dp_count = changes
            .iter()
            .filter(|c| matches!(c, Change::SetDefaultPrivilege { .. }))
            .count();
        let member_count = changes
            .iter()
            .filter(|c| matches!(c, Change::AddMember { .. }))
            .count();

        assert_eq!(create_count, 1);
        assert_eq!(create_schema_count, 1);
        assert_eq!(grant_count, 2); // schema USAGE + table *
        assert_eq!(dp_count, 1);
        assert_eq!(member_count, 1);

        // Diffing desired against itself should produce no changes
        let no_changes = diff(&desired, &desired);
        assert!(no_changes.is_empty());
    }

    // -----------------------------------------------------------------------
    // filter_changes — ReconciliationMode tests
    // -----------------------------------------------------------------------

    /// Build a representative change list covering every Change variant.
    fn all_change_variants() -> Vec<Change> {
        vec![
            Change::CreateRole {
                name: "new-role".to_string(),
                state: RoleState::default(),
            },
            Change::CreateSchema {
                name: "inventory".to_string(),
                owner: Some("inventory_owner".to_string()),
            },
            Change::AlterSchemaOwner {
                name: "catalog".to_string(),
                owner: "catalog_owner".to_string(),
            },
            Change::EnsureSchemaOwnerPrivileges {
                name: "catalog".to_string(),
                owner: "catalog_owner".to_string(),
                privileges: BTreeSet::from([Privilege::Create, Privilege::Usage]),
            },
            Change::AlterRole {
                name: "altered-role".to_string(),
                attributes: vec![RoleAttribute::Login(true)],
            },
            Change::SetComment {
                name: "commented-role".to_string(),
                comment: Some("hello".to_string()),
            },
            Change::Grant {
                role: "r1".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::Revoke {
                role: "r1".to_string(),
                privileges: BTreeSet::from([Privilege::Insert]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::SetDefaultPrivilege {
                owner: "owner".to_string(),
                schema: "public".to_string(),
                on_type: ObjectType::Table,
                grantee: "r1".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            Change::RevokeDefaultPrivilege {
                owner: "owner".to_string(),
                schema: "public".to_string(),
                on_type: ObjectType::Table,
                grantee: "r1".to_string(),
                privileges: BTreeSet::from([Privilege::Delete]),
            },
            Change::AddMember {
                role: "editors".to_string(),
                member: "user@example.com".to_string(),
                inherit: true,
                admin: false,
            },
            Change::RemoveMember {
                role: "editors".to_string(),
                member: "old@example.com".to_string(),
            },
            Change::TerminateSessions {
                role: "retired-role".to_string(),
            },
            Change::ReassignOwned {
                from_role: "retired-role".to_string(),
                to_role: "successor".to_string(),
            },
            Change::DropOwned {
                role: "retired-role".to_string(),
            },
            Change::DropRole {
                name: "retired-role".to_string(),
            },
        ]
    }

    #[test]
    fn filter_authoritative_keeps_all_changes() {
        let changes = all_change_variants();
        let original_len = changes.len();
        let filtered = filter_changes(changes, ReconciliationMode::Authoritative);
        assert_eq!(filtered.len(), original_len);
    }

    #[test]
    fn filter_additive_keeps_only_constructive_changes() {
        let filtered = filter_changes(all_change_variants(), ReconciliationMode::Additive);

        // Should keep: CreateRole, CreateSchema, Grant, SetDefaultPrivilege, AddMember
        assert_eq!(filtered.len(), 5);

        // Verify no destructive changes remain
        for change in &filtered {
            assert!(
                !matches!(
                    change,
                    Change::AlterSchemaOwner { .. }
                        | Change::EnsureSchemaOwnerPrivileges { .. }
                        | Change::AlterRole { .. }
                        | Change::SetComment { .. }
                        | Change::Revoke { .. }
                        | Change::RevokeDefaultPrivilege { .. }
                        | Change::RemoveMember { .. }
                        | Change::DropRole { .. }
                        | Change::DropOwned { .. }
                        | Change::ReassignOwned { .. }
                        | Change::TerminateSessions { .. }
                ),
                "additive mode should not contain destructive change: {change:?}"
            );
        }

        // Verify constructive changes are present
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::CreateRole { .. }))
        );
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::CreateSchema { .. }))
        );
        assert!(
            filtered
                .iter()
                .all(|c| !matches!(c, Change::AlterRole { .. } | Change::SetComment { .. }))
        );
        assert!(filtered.iter().any(|c| matches!(c, Change::Grant { .. })));
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::SetDefaultPrivilege { .. }))
        );
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::AddMember { .. }))
        );
    }

    #[test]
    fn filter_additive_skips_owner_bound_follow_ups_when_transfer_is_skipped() {
        let changes = vec![
            Change::AlterSchemaOwner {
                name: "inventory".to_string(),
                owner: "new_owner".to_string(),
            },
            Change::EnsureSchemaOwnerPrivileges {
                name: "inventory".to_string(),
                owner: "new_owner".to_string(),
                privileges: BTreeSet::from([Privilege::Create, Privilege::Usage]),
            },
            Change::SetDefaultPrivilege {
                owner: "new_owner".to_string(),
                schema: "inventory".to_string(),
                on_type: ObjectType::Table,
                grantee: "inventory-editor".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            Change::Grant {
                role: "inventory-editor".to_string(),
                privileges: BTreeSet::from([Privilege::Usage]),
                object_type: ObjectType::Schema,
                schema: None,
                name: Some("inventory".to_string()),
            },
        ];

        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert_eq!(filtered.len(), 1);
        assert!(matches!(&filtered[0], Change::Grant { role, .. } if role == "inventory-editor"));
    }

    #[test]
    fn filter_adopt_keeps_revokes_but_not_drops() {
        let filtered = filter_changes(all_change_variants(), ReconciliationMode::Adopt);

        // Should keep everything except: DropRole, DropOwned, ReassignOwned, TerminateSessions
        assert_eq!(filtered.len(), 12);

        // Verify no role-drop/retirement changes remain
        for change in &filtered {
            assert!(
                !matches!(
                    change,
                    Change::DropRole { .. }
                        | Change::DropOwned { .. }
                        | Change::ReassignOwned { .. }
                        | Change::TerminateSessions { .. }
                ),
                "adopt mode should not contain drop/retirement change: {change:?}"
            );
        }

        // Verify revokes ARE still present (unlike additive)
        assert!(filtered.iter().any(|c| matches!(c, Change::Revoke { .. })));
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::RevokeDefaultPrivilege { .. }))
        );
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::RemoveMember { .. }))
        );
    }

    #[test]
    fn filter_additive_with_empty_input() {
        let filtered = filter_changes(vec![], ReconciliationMode::Additive);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_additive_only_destructive_changes_yields_empty() {
        let changes = vec![
            Change::Revoke {
                role: "r1".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::DropRole {
                name: "old-role".to_string(),
            },
        ];
        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_adopt_preserves_ordering() {
        let changes = vec![
            Change::CreateRole {
                name: "new-role".to_string(),
                state: RoleState::default(),
            },
            Change::Grant {
                role: "new-role".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::Revoke {
                role: "existing-role".to_string(),
                privileges: BTreeSet::from([Privilege::Insert]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::DropRole {
                name: "old-role".to_string(),
            },
        ];

        let filtered = filter_changes(changes, ReconciliationMode::Adopt);
        assert_eq!(filtered.len(), 3);
        assert!(matches!(&filtered[0], Change::CreateRole { name, .. } if name == "new-role"));
        assert!(matches!(&filtered[1], Change::Grant { .. }));
        assert!(matches!(&filtered[2], Change::Revoke { .. }));
    }

    #[test]
    fn reconciliation_mode_display() {
        assert_eq!(
            ReconciliationMode::Authoritative.to_string(),
            "authoritative"
        );
        assert_eq!(ReconciliationMode::Additive.to_string(), "additive");
        assert_eq!(ReconciliationMode::Adopt.to_string(), "adopt");
    }

    #[test]
    fn reconciliation_mode_default_is_authoritative() {
        assert_eq!(
            ReconciliationMode::default(),
            ReconciliationMode::Authoritative
        );
    }

    // -----------------------------------------------------------------------
    // apply_role_retirements tests
    // -----------------------------------------------------------------------

    #[test]
    fn apply_role_retirements_inserts_cleanup_before_drop() {
        let changes = vec![
            Change::Grant {
                role: "analytics".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::DropRole {
                name: "old-app".to_string(),
            },
        ];

        let planned = apply_role_retirements(
            changes,
            &[crate::manifest::RoleRetirement {
                role: "old-app".to_string(),
                reassign_owned_to: Some("successor".to_string()),
                drop_owned: true,
                terminate_sessions: true,
            }],
        );

        assert!(matches!(planned[0], Change::Grant { .. }));
        assert!(matches!(
            planned[1],
            Change::TerminateSessions { ref role } if role == "old-app"
        ));
        assert!(matches!(
            planned[2],
            Change::ReassignOwned {
                ref from_role,
                ref to_role
            } if from_role == "old-app" && to_role == "successor"
        ));
        assert!(matches!(
            planned[3],
            Change::DropOwned { ref role } if role == "old-app"
        ));
        assert!(matches!(
            planned[4],
            Change::DropRole { ref name } if name == "old-app"
        ));
    }

    #[test]
    fn inject_password_for_new_role() {
        let changes = vec![Change::CreateRole {
            name: "app-svc".to_string(),
            state: RoleState::default(),
        }];

        let mut passwords = std::collections::BTreeMap::new();
        passwords.insert("app-svc".to_string(), "secret123".to_string());

        let result = inject_password_changes(changes, &passwords);
        assert_eq!(result.len(), 2);
        assert!(matches!(&result[0], Change::CreateRole { name, .. } if name == "app-svc"));
        assert!(
            matches!(&result[1], Change::SetPassword { name, password } if name == "app-svc" && password.starts_with("SCRAM-SHA-256$"))
        );
    }

    #[test]
    fn inject_password_for_existing_role() {
        // No CreateRole — role already exists. Only grants change.
        let changes = vec![Change::Grant {
            role: "app-svc".to_string(),
            privileges: BTreeSet::from([crate::manifest::Privilege::Select]),
            object_type: crate::manifest::ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        }];

        let mut passwords = std::collections::BTreeMap::new();
        passwords.insert("app-svc".to_string(), "secret123".to_string());

        let result = inject_password_changes(changes, &passwords);
        assert_eq!(result.len(), 2);
        assert!(matches!(&result[0], Change::Grant { .. }));
        assert!(
            matches!(&result[1], Change::SetPassword { name, password } if name == "app-svc" && password.starts_with("SCRAM-SHA-256$"))
        );
    }

    #[test]
    fn inject_password_empty_passwords_is_noop() {
        let changes = vec![Change::CreateRole {
            name: "app-svc".to_string(),
            state: RoleState::default(),
        }];

        let passwords = std::collections::BTreeMap::new();
        let result = inject_password_changes(changes.clone(), &passwords);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn resolve_passwords_missing_env_var() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "app-svc".to_string(),
            login: Some(true),
            password: Some(crate::manifest::PasswordSource {
                from_env: "PGROLES_TEST_MISSING_VAR_9a8b7c6d".to_string(),
            }),
            password_valid_until: None,
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        // Ensure the env var does not exist.
        // SAFETY: test-only, unique var name avoids conflicts with parallel tests.
        unsafe { std::env::remove_var("PGROLES_TEST_MISSING_VAR_9a8b7c6d") };

        let result = resolve_passwords(&roles);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PasswordResolutionError::MissingEnvVar { ref role, ref env_var }
                if role == "app-svc" && env_var == "PGROLES_TEST_MISSING_VAR_9a8b7c6d"),
            "expected MissingEnvVar, got: {err:?}"
        );
    }

    #[test]
    fn resolve_passwords_empty_env_var() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "app-svc".to_string(),
            login: Some(true),
            password: Some(crate::manifest::PasswordSource {
                from_env: "PGROLES_TEST_EMPTY_VAR_1a2b3c4d".to_string(),
            }),
            password_valid_until: None,
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        // Set the env var to an empty string.
        // SAFETY: test-only, unique var name avoids conflicts with parallel tests.
        unsafe { std::env::set_var("PGROLES_TEST_EMPTY_VAR_1a2b3c4d", "") };

        let result = resolve_passwords(&roles);

        // Clean up.
        unsafe { std::env::remove_var("PGROLES_TEST_EMPTY_VAR_1a2b3c4d") };

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PasswordResolutionError::EmptyPassword { ref role, ref env_var }
                if role == "app-svc" && env_var == "PGROLES_TEST_EMPTY_VAR_1a2b3c4d"),
            "expected EmptyPassword, got: {err:?}"
        );
    }

    #[test]
    fn resolve_passwords_happy_path() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "app-svc".to_string(),
            login: Some(true),
            password: Some(crate::manifest::PasswordSource {
                from_env: "PGROLES_TEST_RESOLVE_VAR_5e6f7g8h".to_string(),
            }),
            password_valid_until: None,
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        // SAFETY: test-only, unique var name avoids conflicts with parallel tests.
        unsafe { std::env::set_var("PGROLES_TEST_RESOLVE_VAR_5e6f7g8h", "my_secret_pw") };

        let result = resolve_passwords(&roles);

        unsafe { std::env::remove_var("PGROLES_TEST_RESOLVE_VAR_5e6f7g8h") };

        let resolved = result.expect("should succeed");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["app-svc"], "my_secret_pw");
    }

    #[test]
    fn resolve_passwords_skips_roles_without_password() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "no-password".to_string(),
            login: Some(true),
            password: None,
            password_valid_until: None,
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        let result = resolve_passwords(&roles);
        let resolved = result.expect("should succeed");
        assert!(resolved.is_empty());
    }

    #[test]
    fn inject_password_multiple_roles() {
        let changes = vec![
            Change::CreateRole {
                name: "role-a".to_string(),
                state: RoleState::default(),
            },
            Change::CreateRole {
                name: "role-b".to_string(),
                state: RoleState::default(),
            },
            Change::Grant {
                role: "role-c".to_string(),
                privileges: BTreeSet::from([crate::manifest::Privilege::Select]),
                object_type: crate::manifest::ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
        ];

        let mut passwords = std::collections::BTreeMap::new();
        passwords.insert("role-a".to_string(), "pw-a".to_string());
        passwords.insert("role-b".to_string(), "pw-b".to_string());
        passwords.insert("role-c".to_string(), "pw-c".to_string());

        let result = inject_password_changes(changes, &passwords);

        // role-a: CreateRole, SetPassword (inline)
        // role-b: CreateRole, SetPassword (inline)
        // role-c: Grant (existing role — SetPassword appended at end)
        assert_eq!(result.len(), 6, "expected 6 changes, got: {result:?}");
        assert!(matches!(&result[0], Change::CreateRole { name, .. } if name == "role-a"));
        assert!(matches!(&result[1], Change::SetPassword { name, .. } if name == "role-a"));
        assert!(matches!(&result[2], Change::CreateRole { name, .. } if name == "role-b"));
        assert!(matches!(&result[3], Change::SetPassword { name, .. } if name == "role-b"));
        assert!(matches!(&result[4], Change::Grant { .. }));
        assert!(matches!(&result[5], Change::SetPassword { name, .. } if name == "role-c"));
    }

    #[test]
    fn diff_detects_valid_until_change() {
        let mut current = empty_graph();
        current.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );

        let mut desired = empty_graph();
        desired.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                password_valid_until: Some("2025-12-31T00:00:00Z".to_string()),
                ..RoleState::default()
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AlterRole { name, attributes } => {
                assert_eq!(name, "r1");
                assert!(attributes.contains(&RoleAttribute::ValidUntil(Some(
                    "2025-12-31T00:00:00Z".to_string()
                ))));
            }
            other => panic!("expected AlterRole, got: {other:?}"),
        }
    }

    #[test]
    fn diff_detects_valid_until_removal() {
        let mut current = empty_graph();
        current.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                password_valid_until: Some("2025-12-31T00:00:00Z".to_string()),
                ..RoleState::default()
            },
        );

        let mut desired = empty_graph();
        desired.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AlterRole { name, attributes } => {
                assert_eq!(name, "r1");
                assert!(attributes.contains(&RoleAttribute::ValidUntil(None)));
            }
            other => panic!("expected AlterRole, got: {other:?}"),
        }
    }
}
