use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::diff::Change;
use crate::manifest::{ObjectType, SchemaBindingFacet};
use crate::model::{DefaultPrivKey, GrantKey};

#[derive(Debug, Clone, Default)]
pub struct OwnershipIndex {
    pub roles: BTreeMap<String, String>,
    pub schema_facets: BTreeMap<SchemaFacetKey, String>,
    pub grants: BTreeMap<GrantKey, String>,
    pub default_privileges: BTreeMap<DefaultPrivKey, String>,
    pub memberships: BTreeMap<MembershipKey, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaFacetKey {
    pub schema: String,
    pub facet: SchemaBindingFacet,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MembershipKey {
    pub role: String,
    pub member: String,
}

#[derive(Debug, Clone, Default)]
pub struct ManagedScope {
    pub roles: BTreeSet<String>,
    pub schemas: BTreeMap<String, ManagedSchemaScope>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedSchemaScope {
    pub owner: bool,
    pub bindings: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ManagedChangeSurface {
    pub roles: BTreeSet<String>,
    pub owner_schemas: BTreeSet<String>,
    pub binding_schemas: BTreeSet<String>,
    pub explicit_grants: BTreeSet<GrantKey>,
    pub explicit_default_privileges: BTreeSet<DefaultPrivKey>,
    pub explicit_memberships: BTreeSet<MembershipKey>,
}

#[derive(Debug, Error)]
pub enum ManagedChangeError {
    #[error("change falls outside managed bundle scope: {change}")]
    OutOfScope { change: String },
}

impl OwnershipIndex {
    pub fn managed_scope(&self) -> ManagedScope {
        let mut scope = ManagedScope {
            roles: self.roles.keys().cloned().collect(),
            schemas: BTreeMap::new(),
        };

        for key in self.schema_facets.keys() {
            let entry = scope.schemas.entry(key.schema.clone()).or_default();
            match key.facet {
                SchemaBindingFacet::Owner => entry.owner = true,
                SchemaBindingFacet::Bindings => entry.bindings = true,
            }
        }

        scope
    }

    pub fn managed_change_surface(&self) -> ManagedChangeSurface {
        let mut surface = ManagedChangeSurface {
            roles: self.roles.keys().cloned().collect(),
            explicit_grants: self.grants.keys().cloned().collect(),
            explicit_default_privileges: self.default_privileges.keys().cloned().collect(),
            explicit_memberships: self.memberships.keys().cloned().collect(),
            ..ManagedChangeSurface::default()
        };

        for key in self.schema_facets.keys() {
            match key.facet {
                SchemaBindingFacet::Owner => {
                    surface.owner_schemas.insert(key.schema.clone());
                }
                SchemaBindingFacet::Bindings => {
                    surface.binding_schemas.insert(key.schema.clone());
                }
            }
        }

        surface
    }
}

pub fn validate_changes_against_managed_surface(
    changes: &[Change],
    surface: &ManagedChangeSurface,
) -> Result<(), ManagedChangeError> {
    for change in changes {
        if !surface.allows_change(change) {
            return Err(ManagedChangeError::OutOfScope {
                change: describe_change(change),
            });
        }
    }

    Ok(())
}

impl ManagedChangeSurface {
    pub fn needs_database_privilege_inspection(&self) -> bool {
        !self.roles.is_empty()
    }

    fn allows_change(&self, change: &Change) -> bool {
        match change {
            Change::CreateRole { name, .. }
            | Change::AlterRole { name, .. }
            | Change::SetComment { name, .. }
            | Change::SetPassword { name, .. }
            | Change::DropRole { name } => self.roles.contains(name),
            Change::TerminateSessions { role } | Change::DropOwned { role } => {
                self.roles.contains(role)
            }
            Change::ReassignOwned { from_role, to_role } => {
                self.roles.contains(from_role) && !to_role.is_empty()
            }
            Change::CreateSchema { name, .. } => {
                self.owner_schemas.contains(name) || self.binding_schemas.contains(name)
            }
            Change::AlterSchemaOwner { name, owner } => {
                self.owner_schemas.contains(name) && !owner.is_empty()
            }
            Change::EnsureSchemaOwnerPrivileges { name, owner, .. } => {
                self.owner_schemas.contains(name) && !owner.is_empty()
            }
            Change::Grant {
                role,
                object_type,
                schema,
                name,
                ..
            }
            | Change::Revoke {
                role,
                object_type,
                schema,
                name,
                ..
            } => self.allows_grant_change(&GrantKey {
                role: role.clone(),
                object_type: *object_type,
                schema: schema.clone(),
                name: name.clone(),
            }),
            Change::SetDefaultPrivilege {
                owner,
                schema,
                on_type,
                grantee,
                ..
            }
            | Change::RevokeDefaultPrivilege {
                owner,
                schema,
                on_type,
                grantee,
                ..
            } => self.allows_default_privilege_change(&DefaultPrivKey {
                owner: owner.clone(),
                schema: schema.clone(),
                on_type: *on_type,
                grantee: grantee.clone(),
            }),
            Change::AddMember { role, member, .. } | Change::RemoveMember { role, member } => {
                self.roles.contains(role)
                    || self.explicit_memberships.contains(&MembershipKey {
                        role: role.clone(),
                        member: member.clone(),
                    })
            }
        }
    }

    fn allows_grant_change(&self, key: &GrantKey) -> bool {
        if self.explicit_grants.contains(key) {
            return true;
        }

        if is_binding_schema_object(key.object_type)
            && grant_schema_name(key)
                .as_deref()
                .is_some_and(|schema| self.binding_schemas.contains(schema))
        {
            return true;
        }

        key.object_type == ObjectType::Database && self.roles.contains(&key.role)
    }

    fn allows_default_privilege_change(&self, key: &DefaultPrivKey) -> bool {
        self.explicit_default_privileges.contains(key) || self.binding_schemas.contains(&key.schema)
    }
}

fn is_binding_schema_object(object_type: ObjectType) -> bool {
    !matches!(object_type, ObjectType::Database)
}

pub(crate) fn grant_schema_name(key: &GrantKey) -> Option<String> {
    match key.object_type {
        ObjectType::Schema => key.name.clone(),
        ObjectType::Database => None,
        _ => key.schema.clone(),
    }
}

pub(crate) fn describe_change(change: &Change) -> String {
    match change {
        Change::CreateRole { name, .. } => format!("create role \"{name}\""),
        Change::AlterRole { name, .. } => format!("alter role \"{name}\""),
        Change::SetComment { name, .. } => format!("set comment on role \"{name}\""),
        Change::SetPassword { name, .. } => format!("set password for role \"{name}\""),
        Change::DropRole { name } => format!("drop role \"{name}\""),
        Change::CreateSchema { name, .. } => format!("create schema \"{name}\""),
        Change::AlterSchemaOwner { name, owner } => {
            format!("alter schema \"{name}\" owner to \"{owner}\"")
        }
        Change::EnsureSchemaOwnerPrivileges { name, owner, .. } => {
            format!("ensure owner privileges on schema \"{name}\" for \"{owner}\"")
        }
        Change::Grant {
            role,
            object_type,
            schema,
            name,
            ..
        } => format_grant_action(
            "grant",
            role,
            *object_type,
            schema.as_deref(),
            name.as_deref(),
        ),
        Change::Revoke {
            role,
            object_type,
            schema,
            name,
            ..
        } => format_grant_action(
            "revoke",
            role,
            *object_type,
            schema.as_deref(),
            name.as_deref(),
        ),
        Change::SetDefaultPrivilege {
            owner,
            schema,
            on_type,
            grantee,
            ..
        } => format!(
            "set default privilege for owner \"{owner}\" schema \"{schema}\" on {on_type} to \"{grantee}\""
        ),
        Change::RevokeDefaultPrivilege {
            owner,
            schema,
            on_type,
            grantee,
            ..
        } => format!(
            "revoke default privilege for owner \"{owner}\" schema \"{schema}\" on {on_type} from \"{grantee}\""
        ),
        Change::AddMember { role, member, .. } => {
            format!("add membership \"{role}\" -> \"{member}\"")
        }
        Change::RemoveMember { role, member } => {
            format!("remove membership \"{role}\" -> \"{member}\"")
        }
        Change::TerminateSessions { role } => format!("terminate sessions for role \"{role}\""),
        Change::ReassignOwned { from_role, to_role } => {
            format!("reassign owned from \"{from_role}\" to \"{to_role}\"")
        }
        Change::DropOwned { role } => format!("drop owned by role \"{role}\""),
    }
}

fn format_grant_action(
    action: &str,
    role: &str,
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
) -> String {
    let target = match (schema, name) {
        (Some(schema), Some(name)) => format!("{schema}.{name}"),
        (Some(schema), None) => schema.to_string(),
        (None, Some(name)) => name.to_string(),
        (None, None) => "<unnamed>".to_string(),
    };
    format!("{action} for role \"{role}\" on {object_type} \"{target}\"")
}
