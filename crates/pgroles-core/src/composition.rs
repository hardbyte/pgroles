use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::manifest::{
    AuthProvider, DefaultPrivilege, ExpandedManifest, Grant, ManifestError, Membership,
    PolicyManifest, Profile, RoleDefinition, RoleRetirement, SchemaBinding, SchemaBindingFacet,
    default_role_pattern, expand_manifest,
};
use crate::model::{DefaultPrivKey, GrantKey, RoleGraph};
use crate::ownership::{
    ManagedChangeSurface, ManagedScope, MembershipKey, OwnershipIndex, SchemaFacetKey,
};
use crate::report::BundleReportContext;

#[derive(Debug, Error)]
pub enum CompositionError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("policy bundle must declare at least one source")]
    MissingSources,

    #[error("policy document \"{document}\" defines role \"{role}\" outside its declared scope")]
    RoleOutOfScope { document: String, role: String },

    #[error(
        "policy document \"{document}\" manages schema \"{schema}\" owner outside its declared scope"
    )]
    SchemaOwnerOutOfScope { document: String, schema: String },

    #[error(
        "policy document \"{document}\" manages schema \"{schema}\" bindings outside its declared scope"
    )]
    SchemaBindingsOutOfScope { document: String, schema: String },

    #[error("policy documents \"{first}\" and \"{second}\" both manage role \"{role}\"")]
    DuplicateManagedRole {
        role: String,
        first: String,
        second: String,
    },

    #[error(
        "policy documents \"{first}\" and \"{second}\" both manage schema facet \"{schema}.{facet}\""
    )]
    DuplicateManagedSchemaFacet {
        schema: String,
        facet: String,
        first: String,
        second: String,
    },

    #[error("policy documents \"{first}\" and \"{second}\" both manage grant {target}")]
    DuplicateManagedGrant {
        target: String,
        first: String,
        second: String,
    },

    #[error("policy documents \"{first}\" and \"{second}\" both manage default privilege {target}")]
    DuplicateManagedDefaultPrivilege {
        target: String,
        first: String,
        second: String,
    },

    #[error(
        "policy documents \"{first}\" and \"{second}\" both manage membership \"{role}\" -> \"{member}\""
    )]
    DuplicateManagedMembership {
        role: String,
        member: String,
        first: String,
        second: String,
    },

    #[error("policy document \"{document}\" failed validation: {error}")]
    InvalidDocument {
        document: String,
        error: ManifestError,
    },

    #[error("composed policy failed validation: {0}")]
    InvalidComposedManifest(ManifestError),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyBundle {
    #[serde(default)]
    pub shared: SharedPolicy,

    #[serde(default)]
    pub sources: Vec<BundleSource>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_owner: Option<String>,

    #[serde(default)]
    pub auth_providers: Vec<AuthProvider>,

    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleSource {
    pub file: String,
}

#[derive(Debug, Clone)]
pub struct PolicyDocument {
    pub source: String,
    pub fragment: PolicyFragment,
}

impl PolicyDocument {
    pub fn label(&self) -> &str {
        self.fragment
            .policy
            .name
            .as_deref()
            .unwrap_or(self.source.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyFragment {
    #[serde(default)]
    pub policy: FragmentMetadata,

    #[serde(default)]
    pub scope: FragmentScope,

    #[serde(default)]
    pub schemas: Vec<SchemaBinding>,

    #[serde(default)]
    pub roles: Vec<RoleDefinition>,

    #[serde(default)]
    pub grants: Vec<Grant>,

    #[serde(default)]
    pub default_privileges: Vec<DefaultPrivilege>,

    #[serde(default)]
    pub memberships: Vec<Membership>,

    #[serde(default)]
    pub retirements: Vec<RoleRetirement>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FragmentMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FragmentScope {
    #[serde(default)]
    pub roles: Vec<String>,

    #[serde(default)]
    pub schemas: Vec<ScopedSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedSchema {
    pub name: String,

    #[serde(default)]
    pub facets: Vec<SchemaBindingFacet>,
}

#[derive(Debug, Clone)]
pub struct ComposedPolicy {
    pub manifest: PolicyManifest,
    pub expanded: ExpandedManifest,
    pub desired: RoleGraph,
    pub ownership: OwnershipIndex,
    pub managed_scope: ManagedScope,
    pub managed_change_surface: ManagedChangeSurface,
}

impl ComposedPolicy {
    pub fn report_context(&self) -> BundleReportContext<'_> {
        BundleReportContext {
            ownership: &self.ownership,
            managed_scope: &self.managed_scope,
        }
    }
}

pub fn parse_policy_bundle(yaml: &str) -> Result<PolicyBundle, CompositionError> {
    Ok(serde_yaml::from_str(yaml)?)
}

pub fn parse_policy_fragment(yaml: &str) -> Result<PolicyFragment, CompositionError> {
    Ok(serde_yaml::from_str(yaml)?)
}

pub fn compose_bundle(
    bundle: &PolicyBundle,
    documents: &[PolicyDocument],
) -> Result<ComposedPolicy, CompositionError> {
    if bundle.sources.is_empty() || documents.is_empty() {
        return Err(CompositionError::MissingSources);
    }

    let mut ownership = OwnershipIndex::default();
    let mut merged_schemas: BTreeMap<String, SchemaBinding> = BTreeMap::new();
    let mut manifest = PolicyManifest {
        default_owner: bundle.shared.default_owner.clone(),
        auth_providers: bundle.shared.auth_providers.clone(),
        profiles: bundle.shared.profiles.clone(),
        schemas: Vec::new(),
        roles: Vec::new(),
        grants: Vec::new(),
        default_privileges: Vec::new(),
        memberships: Vec::new(),
        retirements: Vec::new(),
    };

    for document in documents {
        validate_document_scope(bundle, document)?;

        let document_manifest = document_manifest(bundle, &document.fragment);
        let expanded = expand_manifest(&document_manifest).map_err(|error| {
            CompositionError::InvalidDocument {
                document: document.label().to_string(),
                error,
            }
        })?;
        let desired =
            RoleGraph::from_expanded(&expanded, document_manifest.default_owner.as_deref())
                .map_err(|error| CompositionError::InvalidDocument {
                    document: document.label().to_string(),
                    error,
                })?;

        register_document_ownership(&mut ownership, document, &expanded, &desired)?;
        merge_document_manifest(&mut manifest, &mut merged_schemas, &document.fragment);
    }

    manifest.schemas = merged_schemas.into_values().collect();

    let expanded = expand_manifest(&manifest).map_err(CompositionError::InvalidComposedManifest)?;
    let desired = RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref())
        .map_err(CompositionError::InvalidComposedManifest)?;
    let managed_scope = ownership.managed_scope();
    let managed_change_surface = ownership.managed_change_surface();

    Ok(ComposedPolicy {
        manifest,
        expanded,
        desired,
        ownership,
        managed_scope,
        managed_change_surface,
    })
}

fn document_manifest(bundle: &PolicyBundle, fragment: &PolicyFragment) -> PolicyManifest {
    PolicyManifest {
        default_owner: bundle.shared.default_owner.clone(),
        auth_providers: bundle.shared.auth_providers.clone(),
        profiles: bundle.shared.profiles.clone(),
        schemas: fragment.schemas.clone(),
        roles: fragment.roles.clone(),
        grants: fragment.grants.clone(),
        default_privileges: fragment.default_privileges.clone(),
        memberships: fragment.memberships.clone(),
        retirements: fragment.retirements.clone(),
    }
}

fn validate_document_scope(
    bundle: &PolicyBundle,
    document: &PolicyDocument,
) -> Result<(), CompositionError> {
    let owned_roles: BTreeSet<&str> = document
        .fragment
        .scope
        .roles
        .iter()
        .map(String::as_str)
        .collect();
    let schema_scope = schema_scope_map(&document.fragment.scope);
    let document_name = document.label().to_string();

    for role in &document.fragment.roles {
        if !owned_roles.contains(role.name.as_str()) {
            return Err(CompositionError::RoleOutOfScope {
                document: document_name.clone(),
                role: role.name.clone(),
            });
        }
    }

    for retirement in &document.fragment.retirements {
        if !owned_roles.contains(retirement.role.as_str()) {
            return Err(CompositionError::RoleOutOfScope {
                document: document_name.clone(),
                role: retirement.role.clone(),
            });
        }
    }

    for schema in &document.fragment.schemas {
        let manages_bindings =
            !schema.profiles.is_empty() || schema.role_pattern != default_role_pattern();
        if manages_bindings
            && !has_schema_facet(&schema_scope, &schema.name, SchemaBindingFacet::Bindings)
        {
            return Err(CompositionError::SchemaBindingsOutOfScope {
                document: document_name.clone(),
                schema: schema.name.clone(),
            });
        }

        let manages_owner = schema.owner.is_some() || bundle.shared.default_owner.is_some();
        if manages_owner
            && !has_schema_facet(&schema_scope, &schema.name, SchemaBindingFacet::Owner)
        {
            return Err(CompositionError::SchemaOwnerOutOfScope {
                document: document_name.clone(),
                schema: schema.name.clone(),
            });
        }
    }

    for grant in &document.fragment.grants {
        if let Some(schema) = schema_name_for_grant(grant)
            && !has_schema_facet(&schema_scope, schema, SchemaBindingFacet::Bindings)
        {
            return Err(CompositionError::SchemaBindingsOutOfScope {
                document: document_name.clone(),
                schema: schema.to_string(),
            });
        }
    }

    for default_privilege in &document.fragment.default_privileges {
        if !has_schema_facet(
            &schema_scope,
            &default_privilege.schema,
            SchemaBindingFacet::Bindings,
        ) {
            return Err(CompositionError::SchemaBindingsOutOfScope {
                document: document_name.clone(),
                schema: default_privilege.schema.clone(),
            });
        }
    }

    Ok(())
}

fn schema_scope_map(scope: &FragmentScope) -> BTreeMap<String, BTreeSet<SchemaBindingFacet>> {
    let mut result = BTreeMap::new();

    for schema in &scope.schemas {
        let entry = result
            .entry(schema.name.clone())
            .or_insert_with(BTreeSet::new);
        for facet in &schema.facets {
            entry.insert(*facet);
        }
    }

    result
}

fn has_schema_facet(
    scope: &BTreeMap<String, BTreeSet<SchemaBindingFacet>>,
    schema: &str,
    facet: SchemaBindingFacet,
) -> bool {
    scope
        .get(schema)
        .is_some_and(|facets| facets.contains(&facet))
}

fn schema_name_for_grant(grant: &Grant) -> Option<&str> {
    match grant.object.object_type {
        crate::manifest::ObjectType::Database => None,
        crate::manifest::ObjectType::Schema => grant.object.name.as_deref(),
        _ => grant.object.schema.as_deref(),
    }
}

fn register_document_ownership(
    ownership: &mut OwnershipIndex,
    document: &PolicyDocument,
    expanded: &ExpandedManifest,
    desired: &RoleGraph,
) -> Result<(), CompositionError> {
    let label = document.label().to_string();

    for role in &expanded.roles {
        register_role_owner(ownership, &role.name, &label)?;
    }

    for retirement in &document.fragment.retirements {
        register_role_owner(ownership, &retirement.role, &label)?;
    }

    for schema in &document.fragment.scope.schemas {
        for facet in &schema.facets {
            register_schema_facet_owner(ownership, &schema.name, *facet, &label)?;
        }
    }

    for grant in desired.grants.keys() {
        register_grant_owner(ownership, grant, &label)?;
    }

    for default_privilege in desired.default_privileges.keys() {
        register_default_privilege_owner(ownership, default_privilege, &label)?;
    }

    for membership in &desired.memberships {
        register_membership_owner(
            ownership,
            &MembershipKey {
                role: membership.role.clone(),
                member: membership.member.clone(),
            },
            &label,
        )?;
    }

    Ok(())
}

fn register_role_owner(
    ownership: &mut OwnershipIndex,
    role: &str,
    owner: &str,
) -> Result<(), CompositionError> {
    if let Some(existing) = ownership.roles.insert(role.to_string(), owner.to_string()) {
        return Err(CompositionError::DuplicateManagedRole {
            role: role.to_string(),
            first: existing,
            second: owner.to_string(),
        });
    }

    Ok(())
}

fn register_schema_facet_owner(
    ownership: &mut OwnershipIndex,
    schema: &str,
    facet: SchemaBindingFacet,
    owner: &str,
) -> Result<(), CompositionError> {
    let key = SchemaFacetKey {
        schema: schema.to_string(),
        facet,
    };

    if let Some(existing) = ownership
        .schema_facets
        .insert(key.clone(), owner.to_string())
    {
        return Err(CompositionError::DuplicateManagedSchemaFacet {
            schema: schema.to_string(),
            facet: facet.to_string(),
            first: existing,
            second: owner.to_string(),
        });
    }

    Ok(())
}

fn register_grant_owner(
    ownership: &mut OwnershipIndex,
    key: &GrantKey,
    owner: &str,
) -> Result<(), CompositionError> {
    if let Some(existing) = ownership.grants.insert(key.clone(), owner.to_string()) {
        return Err(CompositionError::DuplicateManagedGrant {
            target: format_grant_key(key),
            first: existing,
            second: owner.to_string(),
        });
    }

    Ok(())
}

fn register_default_privilege_owner(
    ownership: &mut OwnershipIndex,
    key: &DefaultPrivKey,
    owner: &str,
) -> Result<(), CompositionError> {
    if let Some(existing) = ownership
        .default_privileges
        .insert(key.clone(), owner.to_string())
    {
        return Err(CompositionError::DuplicateManagedDefaultPrivilege {
            target: format_default_privilege_key(key),
            first: existing,
            second: owner.to_string(),
        });
    }

    Ok(())
}

fn register_membership_owner(
    ownership: &mut OwnershipIndex,
    key: &MembershipKey,
    owner: &str,
) -> Result<(), CompositionError> {
    if let Some(existing) = ownership.memberships.insert(key.clone(), owner.to_string()) {
        return Err(CompositionError::DuplicateManagedMembership {
            role: key.role.clone(),
            member: key.member.clone(),
            first: existing,
            second: owner.to_string(),
        });
    }

    Ok(())
}

fn format_grant_key(key: &GrantKey) -> String {
    let target = match (&key.schema, &key.name) {
        (Some(schema), Some(name)) => format!("{schema}.{name}"),
        (Some(schema), None) => schema.clone(),
        (None, Some(name)) => name.clone(),
        (None, None) => "<unnamed>".to_string(),
    };

    format!(
        "for role \"{}\" on {} \"{}\"",
        key.role, key.object_type, target
    )
}

fn format_default_privilege_key(key: &DefaultPrivKey) -> String {
    format!(
        "owner \"{}\" schema \"{}\" on {} to \"{}\"",
        key.owner, key.schema, key.on_type, key.grantee
    )
}

fn merge_document_manifest(
    manifest: &mut PolicyManifest,
    merged_schemas: &mut BTreeMap<String, SchemaBinding>,
    fragment: &PolicyFragment,
) {
    manifest.roles.extend(fragment.roles.clone());
    manifest.grants.extend(fragment.grants.clone());
    manifest
        .default_privileges
        .extend(fragment.default_privileges.clone());
    manifest.memberships.extend(fragment.memberships.clone());
    manifest.retirements.extend(fragment.retirements.clone());

    for schema in &fragment.schemas {
        let entry = merged_schemas
            .entry(schema.name.clone())
            .or_insert_with(|| SchemaBinding {
                name: schema.name.clone(),
                profiles: Vec::new(),
                role_pattern: default_role_pattern(),
                owner: None,
            });

        if schema.owner.is_some() {
            entry.owner = schema.owner.clone();
        }

        if !schema.profiles.is_empty() {
            entry.profiles = schema.profiles.clone();
        }

        if schema.role_pattern != default_role_pattern() {
            entry.role_pattern = schema.role_pattern.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::Change;
    use crate::manifest::{ObjectType, Privilege};
    use crate::ownership::{
        ManagedChangeError, ManagedChangeSurface, ManagedSchemaScope, OwnershipIndex,
        validate_changes_against_managed_surface,
    };

    fn bundle_with_editor_profile() -> PolicyBundle {
        let bundle = r#"
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
sources:
  - file: platform.yaml
  - file: app.yaml
"#;
        parse_policy_bundle(bundle).expect("bundle should parse")
    }

    #[test]
    fn compose_bundle_merges_schema_owner_and_bindings() {
        let bundle = bundle_with_editor_profile();
        let platform = PolicyDocument {
            source: "platform.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]
roles:
  - name: app_owner
    login: false
schemas:
  - name: inventory
    owner: app_owner
"#,
            )
            .expect("platform fragment should parse"),
        };
        let app = PolicyDocument {
            source: "app.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [editor]
"#,
            )
            .expect("app fragment should parse"),
        };

        let composed = compose_bundle(&bundle, &[platform, app]).expect("bundle should compose");

        assert_eq!(composed.expanded.schemas.len(), 1);
        assert_eq!(
            composed.expanded.schemas[0].owner.as_deref(),
            Some("app_owner")
        );
        assert!(composed.desired.roles.contains_key("inventory-editor"));
        assert!(composed.ownership.roles.contains_key("inventory-editor"));
        assert_eq!(
            composed.managed_scope.schemas.get("inventory"),
            Some(&ManagedSchemaScope {
                owner: true,
                bindings: true
            })
        );
    }

    #[test]
    fn compose_bundle_rejects_role_outside_scope() {
        let bundle = PolicyBundle {
            shared: SharedPolicy::default(),
            sources: vec![BundleSource {
                file: "app.yaml".to_string(),
            }],
        };
        let document = PolicyDocument {
            source: "app.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
roles:
  - name: app
    login: true
"#,
            )
            .expect("fragment should parse"),
        };

        let error = compose_bundle(&bundle, &[document]).expect_err("scope validation should fail");
        assert!(matches!(
            error,
            CompositionError::RoleOutOfScope { role, .. } if role == "app"
        ));
    }

    #[test]
    fn compose_bundle_rejects_duplicate_generated_roles() {
        let bundle = PolicyBundle {
            shared: SharedPolicy {
                profiles: BTreeMap::from([(
                    "viewer".to_string(),
                    Profile {
                        login: None,
                        inherit: None,
                        grants: vec![],
                        default_privileges: vec![],
                    },
                )]),
                ..SharedPolicy::default()
            },
            sources: vec![
                BundleSource {
                    file: "a.yaml".to_string(),
                },
                BundleSource {
                    file: "b.yaml".to_string(),
                },
            ],
        };
        let first = PolicyDocument {
            source: "a.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: first
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [viewer]
"#,
            )
            .expect("first fragment should parse"),
        };
        let second = PolicyDocument {
            source: "b.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: second
scope:
  roles: [inventory-viewer]
roles:
  - name: inventory-viewer
    login: true
"#,
            )
            .expect("second fragment should parse"),
        };

        let error =
            compose_bundle(&bundle, &[first, second]).expect_err("generated role should conflict");
        assert!(matches!(
            error,
            CompositionError::DuplicateManagedRole { role, .. } if role == "inventory-viewer"
        ));
    }

    #[test]
    fn compose_bundle_rejects_duplicate_grants() {
        let bundle = PolicyBundle {
            shared: SharedPolicy::default(),
            sources: vec![
                BundleSource {
                    file: "a.yaml".to_string(),
                },
                BundleSource {
                    file: "b.yaml".to_string(),
                },
            ],
        };
        let first = PolicyDocument {
            source: "a.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: first
scope:
  roles: [app]
roles:
  - name: app
grants:
  - role: app
    privileges: [CONNECT]
    object: { type: database, name: appdb }
"#,
            )
            .expect("first fragment should parse"),
        };
        let second = PolicyDocument {
            source: "b.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: second
grants:
  - role: app
    privileges: [CREATE]
    object: { type: database, name: appdb }
"#,
            )
            .expect("second fragment should parse"),
        };

        let error =
            compose_bundle(&bundle, &[first, second]).expect_err("grant ownership should conflict");
        assert!(matches!(
            error,
            CompositionError::DuplicateManagedGrant { first, second, .. }
                if first == "first" && second == "second"
        ));
    }

    #[test]
    fn register_default_privilege_owner_rejects_duplicates() {
        let mut ownership = OwnershipIndex::default();
        let key = DefaultPrivKey {
            owner: "app_owner".to_string(),
            schema: "inventory".to_string(),
            on_type: crate::manifest::ObjectType::Table,
            grantee: "app".to_string(),
        };

        register_default_privilege_owner(&mut ownership, &key, "first")
            .expect("first owner should register");
        let error = register_default_privilege_owner(&mut ownership, &key, "second")
            .expect_err("default privilege ownership should conflict");
        assert!(matches!(
            error,
            CompositionError::DuplicateManagedDefaultPrivilege { first, second, .. }
                if first == "first" && second == "second"
        ));
    }

    #[test]
    fn compose_bundle_rejects_duplicate_membership_selectors() {
        let bundle = PolicyBundle {
            shared: SharedPolicy::default(),
            sources: vec![
                BundleSource {
                    file: "a.yaml".to_string(),
                },
                BundleSource {
                    file: "b.yaml".to_string(),
                },
            ],
        };
        let first = PolicyDocument {
            source: "a.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: first
memberships:
  - role: editor
    members:
      - name: app
"#,
            )
            .expect("first fragment should parse"),
        };
        let second = PolicyDocument {
            source: "b.yaml".to_string(),
            fragment: parse_policy_fragment(
                r#"
policy:
  name: second
memberships:
  - role: editor
    members:
      - name: app
        admin: true
"#,
            )
            .expect("second fragment should parse"),
        };

        let error = compose_bundle(&bundle, &[first, second])
            .expect_err("membership ownership should conflict");
        assert!(matches!(
            error,
            CompositionError::DuplicateManagedMembership { role, member, .. }
                if role == "editor" && member == "app"
        ));
    }

    #[test]
    fn managed_surface_allows_revoke_of_removed_database_grant_for_managed_role() {
        let surface = ManagedChangeSurface {
            roles: BTreeSet::from(["app".to_string()]),
            ..ManagedChangeSurface::default()
        };

        let result = validate_changes_against_managed_surface(
            &[Change::Revoke {
                role: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Connect]),
                object_type: ObjectType::Database,
                schema: None,
                name: Some("appdb".to_string()),
            }],
            &surface,
        );

        assert!(result.is_ok(), "managed role should own database revokes");
    }

    #[test]
    fn managed_surface_rejects_unmanaged_membership_removal() {
        let surface = ManagedChangeSurface::default();

        let error = validate_changes_against_managed_surface(
            &[Change::RemoveMember {
                role: "editor".to_string(),
                member: "app".to_string(),
            }],
            &surface,
        )
        .expect_err("unmanaged membership removal should be rejected");

        assert!(matches!(
            error,
            ManagedChangeError::OutOfScope { change } if change.contains("remove membership")
        ));
    }

    #[test]
    fn schema_scope_facet_display_matches_yaml_values() {
        assert_eq!(SchemaBindingFacet::Owner.to_string(), "owner");
        assert_eq!(SchemaBindingFacet::Bindings.to_string(), "bindings");
        assert_eq!(Privilege::Usage.to_string(), "USAGE");
    }
}
