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
use crate::model::{DefaultPrivKey, GrantKey, MembershipEdge, RoleAttribute, RoleGraph, RoleState};

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

    /// Drop a role.
    DropRole { name: String },
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
    changes.extend(grants);
    changes.extend(set_defaults);
    changes.extend(remove_members);
    changes.extend(add_members);
    changes.extend(revoke_defaults);
    changes.extend(revokes);
    changes.extend(drops);
    changes
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
    use crate::model::{DefaultPrivState, GrantState};

    /// Helper: build an empty graph.
    fn empty_graph() -> RoleGraph {
        RoleGraph::default()
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
        let drop_idx = changes
            .iter()
            .position(|c| matches!(c, Change::DropRole { .. }))
            .unwrap();
        assert!(create_idx < drop_idx);
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
        on: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table

schemas:
  - name: inventory
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

        // Should have: 1 CreateRole, 2 Grants, 1 SetDefaultPrivilege, 1 AddMember
        let create_count = changes
            .iter()
            .filter(|c| matches!(c, Change::CreateRole { .. }))
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
        assert_eq!(grant_count, 2); // schema USAGE + table *
        assert_eq!(dp_count, 1);
        assert_eq!(member_count, 1);

        // Diffing desired against itself should produce no changes
        let no_changes = diff(&desired, &desired);
        assert!(no_changes.is_empty());
    }

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
}
