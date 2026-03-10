use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("duplicate role name: \"{0}\"")]
    DuplicateRole(String),

    #[error("profile \"{0}\" referenced by schema \"{1}\" is not defined")]
    UndefinedProfile(String, String),

    #[error("role_pattern must contain {{profile}} placeholder, got: \"{0}\"")]
    InvalidRolePattern(String),

    #[error("top-level default privilege for schema \"{schema}\" must specify grant.role")]
    MissingDefaultPrivilegeRole { schema: String },

    #[error("duplicate retirement entry for role: \"{0}\"")]
    DuplicateRetirement(String),

    #[error("retirement entry for role \"{0}\" conflicts with a desired role of the same name")]
    RetirementRoleStillDesired(String),

    #[error("retirement entry for role \"{role}\" cannot reassign ownership to itself")]
    RetirementSelfReassign { role: String },

    #[error("manifest has {} validation error(s)", .0.len())]
    ValidationErrors(Vec<ManifestError>),

    #[error("privilege {privilege} is not valid for {object_type} in {context}")]
    InvalidPrivilegeForObject {
        privilege: Privilege,
        object_type: ObjectType,
        context: String,
    },

    #[error(
        "default privileges do not support object type {object_type} in schema \"{schema}\" \
         (only tables, sequences, functions, types, and schemas are supported)"
    )]
    UnsupportedDefaultPrivilegeObjectType {
        object_type: ObjectType,
        schema: String,
    },

    #[error("database grant for role \"{role}\" must not specify a schema (got \"{schema}\")")]
    DatabaseGrantWithSchema { role: String, schema: String },

    #[error("wildcard name \"*\" is not supported for {object_type} in {context}")]
    UnsupportedWildcardObjectType {
        object_type: ObjectType,
        context: String,
    },

    #[error("role name must not be empty")]
    EmptyRoleName,

    #[error("connection_limit for role \"{role}\" must be >= -1, got {value}")]
    InvalidConnectionLimit { role: String, value: i32 },
}

// ---------------------------------------------------------------------------
// Semantic validation helpers
// ---------------------------------------------------------------------------

/// Valid privileges per object type, derived from PostgreSQL's `acl.h`
/// `ACL_ALL_RIGHTS_*` macros.
///
/// Source: <https://github.com/postgres/postgres/blob/master/src/include/utils/acl.h>
///
/// Note: PG17 added MAINTAIN for relations — we omit it since pgroles targets PG14+.
fn valid_privileges_for(object_type: ObjectType) -> &'static [Privilege] {
    use Privilege::*;
    match object_type {
        // ACL_ALL_RIGHTS_RELATION
        ObjectType::Table => &[
            Select, Insert, Update, Delete, Truncate, References, Trigger,
        ],
        // Views: same as tables minus TRUNCATE
        ObjectType::View => &[Select, Insert, Update, Delete, References, Trigger],
        // Materialized views: SELECT only (refresh is DDL, not a privilege)
        ObjectType::MaterializedView => &[Select],
        // ACL_ALL_RIGHTS_SEQUENCE
        ObjectType::Sequence => &[Select, Update, Usage],
        // ACL_ALL_RIGHTS_FUNCTION
        ObjectType::Function => &[Execute],
        // ACL_ALL_RIGHTS_NAMESPACE
        ObjectType::Schema => &[Create, Usage],
        // ACL_ALL_RIGHTS_DATABASE
        ObjectType::Database => &[Create, Connect, Temporary],
        // ACL_ALL_RIGHTS_TYPE
        ObjectType::Type => &[Usage],
    }
}

/// PostgreSQL supports `ALTER DEFAULT PRIVILEGES` only for these object types.
/// Schema support requires PG15+.
fn supports_default_privileges(object_type: ObjectType) -> bool {
    matches!(
        object_type,
        ObjectType::Table
            | ObjectType::Sequence
            | ObjectType::Function
            | ObjectType::Type
            | ObjectType::Schema
    )
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// PostgreSQL object types that can have privileges granted on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    Table,
    View,
    #[serde(alias = "materialized_view")]
    MaterializedView,
    Sequence,
    Function,
    Schema,
    Database,
    Type,
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectType::Table => write!(f, "table"),
            ObjectType::View => write!(f, "view"),
            ObjectType::MaterializedView => write!(f, "materialized_view"),
            ObjectType::Sequence => write!(f, "sequence"),
            ObjectType::Function => write!(f, "function"),
            ObjectType::Schema => write!(f, "schema"),
            ObjectType::Database => write!(f, "database"),
            ObjectType::Type => write!(f, "type"),
        }
    }
}

/// PostgreSQL privilege types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Privilege {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
    Execute,
    Usage,
    Create,
    Connect,
    Temporary,
}

impl std::fmt::Display for Privilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Privilege::Select => write!(f, "SELECT"),
            Privilege::Insert => write!(f, "INSERT"),
            Privilege::Update => write!(f, "UPDATE"),
            Privilege::Delete => write!(f, "DELETE"),
            Privilege::Truncate => write!(f, "TRUNCATE"),
            Privilege::References => write!(f, "REFERENCES"),
            Privilege::Trigger => write!(f, "TRIGGER"),
            Privilege::Execute => write!(f, "EXECUTE"),
            Privilege::Usage => write!(f, "USAGE"),
            Privilege::Create => write!(f, "CREATE"),
            Privilege::Connect => write!(f, "CONNECT"),
            Privilege::Temporary => write!(f, "TEMPORARY"),
        }
    }
}

// ---------------------------------------------------------------------------
// YAML manifest types
// ---------------------------------------------------------------------------

/// Top-level policy manifest — the YAML file that users write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifest {
    /// Default owner for ALTER DEFAULT PRIVILEGES (e.g. "app_owner").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_owner: Option<String>,

    /// Cloud auth provider configurations for IAM-mapped role awareness.
    #[serde(default)]
    pub auth_providers: Vec<AuthProvider>,

    /// Reusable privilege profiles.
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,

    /// Schema bindings that expand profiles into concrete roles/grants.
    #[serde(default)]
    pub schemas: Vec<SchemaBinding>,

    /// One-off role definitions (not from profiles).
    #[serde(default)]
    pub roles: Vec<RoleDefinition>,

    /// One-off grants (not from profiles).
    #[serde(default)]
    pub grants: Vec<Grant>,

    /// One-off default privileges (not from profiles).
    #[serde(default)]
    pub default_privileges: Vec<DefaultPrivilege>,

    /// Membership edges (opt-in).
    #[serde(default)]
    pub memberships: Vec<Membership>,

    /// Explicit role-retirement workflows for roles that should be removed.
    #[serde(default)]
    pub retirements: Vec<RoleRetirement>,
}

/// Cloud authentication provider configuration.
///
/// Declares awareness of cloud IAM-mapped roles so pgroles can correctly
/// reference auto-created role names in grants and memberships.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthProvider {
    /// Google Cloud SQL IAM authentication.
    /// Service accounts map to PG roles like `user@project.iam`.
    CloudSqlIam {
        /// GCP project ID (for documentation/validation).
        #[serde(default)]
        project: Option<String>,
    },
    /// Google AlloyDB IAM authentication.
    /// IAM users and groups map to PostgreSQL roles managed by AlloyDB.
    #[serde(rename = "alloydb_iam")]
    AlloyDbIam {
        /// GCP project ID (for documentation/validation).
        #[serde(default)]
        project: Option<String>,
        /// AlloyDB cluster name (for documentation/validation).
        #[serde(default)]
        cluster: Option<String>,
    },
    /// AWS RDS IAM authentication.
    /// IAM users authenticate via token; the PG role must have `rds_iam` granted.
    RdsIam {
        /// AWS region (for documentation/validation).
        #[serde(default)]
        region: Option<String>,
    },
    /// Azure Entra ID (AAD) authentication for Azure Database for PostgreSQL.
    AzureAd {
        /// Azure tenant ID (for documentation/validation).
        #[serde(default)]
        tenant_id: Option<String>,
    },
    /// Supabase-managed PostgreSQL authentication.
    Supabase {
        /// Supabase project ref (for documentation/validation).
        #[serde(default)]
        project_ref: Option<String>,
    },
    /// PlanetScale PostgreSQL authentication metadata.
    PlanetScale {
        /// PlanetScale organization (for documentation/validation).
        #[serde(default)]
        organization: Option<String>,
    },
}

/// A reusable privilege profile — defines what grants a role should have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub login: Option<bool>,

    #[serde(default)]
    pub grants: Vec<ProfileGrant>,

    #[serde(default)]
    pub default_privileges: Vec<DefaultPrivilegeGrant>,
}

/// A grant template within a profile (schema is filled in during expansion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileGrant {
    pub privileges: Vec<Privilege>,
    pub on: ProfileObjectTarget,
}

/// Object target within a profile — schema is omitted (filled during expansion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileObjectTarget {
    #[serde(rename = "type")]
    pub object_type: ObjectType,
    /// Object name, or "*" for all objects of this type. Omit for schema-level grants.
    #[serde(default)]
    pub name: Option<String>,
}

/// A schema binding — associates a schema with one or more profiles.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SchemaBinding {
    pub name: String,

    pub profiles: Vec<String>,

    /// Role naming pattern. Supports `{schema}` and `{profile}` placeholders.
    /// Defaults to `"{schema}-{profile}"`.
    #[serde(default = "default_role_pattern")]
    pub role_pattern: String,

    /// Override default_owner for this schema's default privileges.
    #[serde(default)]
    pub owner: Option<String>,
}

fn default_role_pattern() -> String {
    "{schema}-{profile}".to_string()
}

/// A concrete role definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superuser: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub createdb: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub createrole: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherit: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypassrls: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_limit: Option<i32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A concrete grant on a specific object or wildcard.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Grant {
    pub role: String,
    pub privileges: Vec<Privilege>,
    pub on: ObjectTarget,
}

/// Target object for a grant.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ObjectTarget {
    #[serde(rename = "type")]
    pub object_type: ObjectType,

    /// Schema name. Required for most object types except database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Object name, or "*" for all objects. Omit for schema-level grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Default privilege configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DefaultPrivilege {
    /// The role that owns newly created objects. If omitted, uses manifest's default_owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    pub schema: String,

    pub grant: Vec<DefaultPrivilegeGrant>,
}

/// A single default privilege grant entry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DefaultPrivilegeGrant {
    /// The role receiving the default privilege. Only used in top-level default_privileges
    /// (in profiles, the role is determined by expansion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    pub privileges: Vec<Privilege>,
    pub on_type: ObjectType,
}

/// A membership declaration — which members belong to a role.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Membership {
    pub role: String,
    pub members: Vec<MemberSpec>,
}

/// A single member of a role.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemberSpec {
    pub name: String,

    #[serde(default = "default_true")]
    pub inherit: bool,

    #[serde(default)]
    pub admin: bool,
}

fn default_true() -> bool {
    true
}

/// Declarative workflow for retiring an existing role.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoleRetirement {
    /// The role to retire and ultimately drop.
    pub role: String,

    /// Optional successor role for `REASSIGN OWNED BY ... TO ...`.
    #[serde(default)]
    pub reassign_owned_to: Option<String>,

    /// Whether to run `DROP OWNED BY` before dropping the role.
    #[serde(default)]
    pub drop_owned: bool,

    /// Whether to terminate other active sessions for the role before drop.
    #[serde(default)]
    pub terminate_sessions: bool,
}

// ---------------------------------------------------------------------------
// Expanded manifest — the result of profile expansion
// ---------------------------------------------------------------------------

/// The fully expanded policy — all profiles resolved into concrete roles, grants,
/// default privileges, and memberships. Ready to be converted into a `RoleGraph`.
#[derive(Debug, Clone)]
pub struct ExpandedManifest {
    pub roles: Vec<RoleDefinition>,
    pub grants: Vec<Grant>,
    pub default_privileges: Vec<DefaultPrivilege>,
    pub memberships: Vec<Membership>,
}

// ---------------------------------------------------------------------------
// Expansion logic
// ---------------------------------------------------------------------------

/// Parse a YAML string into a `PolicyManifest`.
pub fn parse_manifest(yaml: &str) -> Result<PolicyManifest, ManifestError> {
    let manifest: PolicyManifest = serde_yaml::from_str(yaml)?;
    Ok(manifest)
}

/// Expand a `PolicyManifest` by resolving all `profiles × schemas` into concrete
/// roles, grants, and default privileges. Merges with one-off definitions.
/// Validates no duplicate role names.
pub fn expand_manifest(manifest: &PolicyManifest) -> Result<ExpandedManifest, ManifestError> {
    let mut roles: Vec<RoleDefinition> = Vec::new();
    let mut grants: Vec<Grant> = Vec::new();
    let mut default_privileges: Vec<DefaultPrivilege> = Vec::new();

    // Expand each schema × profile combination
    for schema_binding in &manifest.schemas {
        for profile_name in &schema_binding.profiles {
            let profile = manifest.profiles.get(profile_name).ok_or_else(|| {
                ManifestError::UndefinedProfile(profile_name.clone(), schema_binding.name.clone())
            })?;

            // Validate pattern contains {profile}
            if !schema_binding.role_pattern.contains("{profile}") {
                return Err(ManifestError::InvalidRolePattern(
                    schema_binding.role_pattern.clone(),
                ));
            }

            // Generate role name from pattern
            let role_name = schema_binding
                .role_pattern
                .replace("{schema}", &schema_binding.name)
                .replace("{profile}", profile_name);

            // Create role definition
            roles.push(RoleDefinition {
                name: role_name.clone(),
                login: profile.login,
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: Some(format!(
                    "Generated from profile '{profile_name}' for schema '{}'",
                    schema_binding.name
                )),
            });

            // Expand profile grants — fill in schema
            for profile_grant in &profile.grants {
                let object_target = match profile_grant.on.object_type {
                    ObjectType::Schema => ObjectTarget {
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some(schema_binding.name.clone()),
                    },
                    _ => ObjectTarget {
                        object_type: profile_grant.on.object_type,
                        schema: Some(schema_binding.name.clone()),
                        name: profile_grant.on.name.clone(),
                    },
                };

                grants.push(Grant {
                    role: role_name.clone(),
                    privileges: profile_grant.privileges.clone(),
                    on: object_target,
                });
            }

            // Expand profile default privileges
            if !profile.default_privileges.is_empty() {
                let owner = schema_binding
                    .owner
                    .clone()
                    .or(manifest.default_owner.clone());

                let expanded_grants: Vec<DefaultPrivilegeGrant> = profile
                    .default_privileges
                    .iter()
                    .map(|dp| DefaultPrivilegeGrant {
                        role: Some(role_name.clone()),
                        privileges: dp.privileges.clone(),
                        on_type: dp.on_type,
                    })
                    .collect();

                default_privileges.push(DefaultPrivilege {
                    owner,
                    schema: schema_binding.name.clone(),
                    grant: expanded_grants,
                });
            }
        }
    }

    // Top-level default privileges must always identify the grantee role.
    for default_priv in &manifest.default_privileges {
        for grant in &default_priv.grant {
            if grant.role.is_none() {
                return Err(ManifestError::MissingDefaultPrivilegeRole {
                    schema: default_priv.schema.clone(),
                });
            }
        }
    }

    // Merge one-off definitions
    roles.extend(manifest.roles.clone());
    grants.extend(manifest.grants.clone());
    default_privileges.extend(manifest.default_privileges.clone());
    let memberships = manifest.memberships.clone();

    // Validate no duplicate role names
    let mut seen_roles: HashSet<String> = HashSet::new();
    for role in &roles {
        if seen_roles.contains(&role.name) {
            return Err(ManifestError::DuplicateRole(role.name.clone()));
        }
        seen_roles.insert(role.name.clone());
    }

    let desired_role_names: HashSet<String> = roles.iter().map(|role| role.name.clone()).collect();
    let mut seen_retirements: HashSet<String> = HashSet::new();
    for retirement in &manifest.retirements {
        if seen_retirements.contains(&retirement.role) {
            return Err(ManifestError::DuplicateRetirement(retirement.role.clone()));
        }
        if desired_role_names.contains(&retirement.role) {
            return Err(ManifestError::RetirementRoleStillDesired(
                retirement.role.clone(),
            ));
        }
        if retirement.reassign_owned_to.as_deref() == Some(retirement.role.as_str()) {
            return Err(ManifestError::RetirementSelfReassign {
                role: retirement.role.clone(),
            });
        }
        seen_retirements.insert(retirement.role.clone());
    }

    Ok(ExpandedManifest {
        roles,
        grants,
        default_privileges,
        memberships,
    })
}

// ---------------------------------------------------------------------------
// Semantic validation (post-expansion, accumulates all errors)
// ---------------------------------------------------------------------------

/// Validate semantic rules that PostgreSQL would reject at runtime.
///
/// Unlike `expand_manifest()` which fails fast on structural errors, this
/// function accumulates all independent semantic errors so users can fix
/// everything in one pass.
pub fn validate_semantics(manifest: &ExpandedManifest) -> Result<(), ManifestError> {
    let mut errors: Vec<ManifestError> = Vec::new();

    // -- Validate grants -------------------------------------------------------
    for grant in &manifest.grants {
        let context = format!("grant for role \"{}\"", grant.role);

        if grant.role.is_empty() {
            errors.push(ManifestError::EmptyRoleName);
        }

        // Database grant must not have a schema field.
        if grant.on.object_type == ObjectType::Database
            && let Some(schema) = &grant.on.schema
        {
            errors.push(ManifestError::DatabaseGrantWithSchema {
                role: grant.role.clone(),
                schema: schema.clone(),
            });
        }

        // Wildcard on unsupported object types.
        if grant.on.name.as_deref() == Some("*") {
            match grant.on.object_type {
                ObjectType::Schema | ObjectType::Database | ObjectType::Type => {
                    errors.push(ManifestError::UnsupportedWildcardObjectType {
                        object_type: grant.on.object_type,
                        context: context.clone(),
                    });
                }
                _ => {}
            }
        }

        // Privilege/object type combinations.
        let valid = valid_privileges_for(grant.on.object_type);
        for priv_item in &grant.privileges {
            if !valid.contains(priv_item) {
                errors.push(ManifestError::InvalidPrivilegeForObject {
                    privilege: *priv_item,
                    object_type: grant.on.object_type,
                    context: context.clone(),
                });
            }
        }
    }

    // -- Validate default privileges -------------------------------------------
    for dp in &manifest.default_privileges {
        for dp_grant in &dp.grant {
            let context = format!(
                "default privilege in schema \"{}\"{}",
                dp.schema,
                dp_grant
                    .role
                    .as_ref()
                    .map(|r| format!(" for role \"{r}\""))
                    .unwrap_or_default()
            );

            // Unsupported object type for default privileges.
            if !supports_default_privileges(dp_grant.on_type) {
                errors.push(ManifestError::UnsupportedDefaultPrivilegeObjectType {
                    object_type: dp_grant.on_type,
                    schema: dp.schema.clone(),
                });
            }

            // Privilege/object type combinations.
            let valid = valid_privileges_for(dp_grant.on_type);
            for priv_item in &dp_grant.privileges {
                if !valid.contains(priv_item) {
                    errors.push(ManifestError::InvalidPrivilegeForObject {
                        privilege: *priv_item,
                        object_type: dp_grant.on_type,
                        context: context.clone(),
                    });
                }
            }
        }
    }

    // -- Validate role definitions ---------------------------------------------
    for role in &manifest.roles {
        if role.name.is_empty() {
            errors.push(ManifestError::EmptyRoleName);
        }
        if let Some(limit) = role.connection_limit
            && limit < -1
        {
            errors.push(ManifestError::InvalidConnectionLimit {
                role: role.name.clone(),
                value: limit,
            });
        }
    }

    // -- Return ----------------------------------------------------------------
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(ManifestError::ValidationErrors(errors)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_role() {
        let yaml = r#"
roles:
  - name: test-role
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.roles[0].name, "test-role");
        assert!(manifest.roles[0].login.is_none());
    }

    #[test]
    fn parse_full_policy() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    login: false
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        on: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        on: { type: sequence, name: "*" }
      - privileges: [EXECUTE]
        on: { type: function, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        on_type: table
      - privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - privileges: [EXECUTE]
        on_type: function

schemas:
  - name: inventory
    profiles: [editor]
  - name: catalog
    profiles: [editor]

roles:
  - name: analytics-readonly
    login: true

memberships:
  - role: inventory-editor
    members:
      - name: "alice@example.com"
        inherit: true
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.profiles.len(), 1);
        assert_eq!(manifest.schemas.len(), 2);
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.memberships.len(), 1);
        assert_eq!(manifest.default_owner, Some("app_owner".to_string()));
    }

    #[test]
    fn reject_invalid_yaml() {
        let yaml = "not: [valid: yaml: {{";
        assert!(parse_manifest(yaml).is_err());
    }

    #[test]
    fn expand_profiles_basic() {
        let yaml = r#"
profiles:
  editor:
    login: false
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT]
        on: { type: table, name: "*" }

schemas:
  - name: myschema
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 1);
        assert_eq!(expanded.roles[0].name, "myschema-editor");
        assert_eq!(expanded.roles[0].login, Some(false));

        // Schema usage grant + table grant
        assert_eq!(expanded.grants.len(), 2);
        assert_eq!(expanded.grants[0].role, "myschema-editor");
        assert_eq!(expanded.grants[0].on.object_type, ObjectType::Schema);
        assert_eq!(expanded.grants[0].on.name, Some("myschema".to_string()));

        assert_eq!(expanded.grants[1].on.object_type, ObjectType::Table);
        assert_eq!(expanded.grants[1].on.schema, Some("myschema".to_string()));
        assert_eq!(expanded.grants[1].on.name, Some("*".to_string()));
    }

    #[test]
    fn expand_profiles_multi_schema() {
        let yaml = r#"
profiles:
  editor:
    grants:
      - privileges: [SELECT]
        on: { type: table, name: "*" }
  viewer:
    grants:
      - privileges: [SELECT]
        on: { type: table, name: "*" }

schemas:
  - name: alpha
    profiles: [editor, viewer]
  - name: beta
    profiles: [editor, viewer]
  - name: gamma
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        // 2 + 2 + 1 = 5 roles
        assert_eq!(expanded.roles.len(), 5);
        let role_names: Vec<&str> = expanded.roles.iter().map(|r| r.name.as_str()).collect();
        assert!(role_names.contains(&"alpha-editor"));
        assert!(role_names.contains(&"alpha-viewer"));
        assert!(role_names.contains(&"beta-editor"));
        assert!(role_names.contains(&"beta-viewer"));
        assert!(role_names.contains(&"gamma-editor"));
    }

    #[test]
    fn expand_custom_role_pattern() {
        let yaml = r#"
profiles:
  viewer:
    grants:
      - privileges: [SELECT]
        on: { type: table, name: "*" }

schemas:
  - name: legacy_data
    profiles: [viewer]
    role_pattern: "legacy-{profile}"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 1);
        assert_eq!(expanded.roles[0].name, "legacy-viewer");
    }

    #[test]
    fn expand_rejects_duplicate_role_name() {
        let yaml = r#"
profiles:
  editor:
    grants: []

schemas:
  - name: inventory
    profiles: [editor]

roles:
  - name: inventory-editor
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate role name")
        );
    }

    #[test]
    fn expand_rejects_undefined_profile() {
        let yaml = r#"
profiles: {}

schemas:
  - name: inventory
    profiles: [nonexistent]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not defined"));
    }

    #[test]
    fn expand_rejects_invalid_pattern() {
        let yaml = r#"
profiles:
  editor:
    grants: []

schemas:
  - name: inventory
    profiles: [editor]
    role_pattern: "static-name"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("{profile} placeholder")
        );
    }

    #[test]
    fn expand_rejects_top_level_default_privilege_without_role() {
        let yaml = r#"
default_privileges:
  - schema: public
    grant:
      - privileges: [SELECT]
        on_type: table
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must specify grant.role")
        );
    }

    #[test]
    fn expand_default_privileges_with_owner_override() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants: []
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    profiles: [editor]
  - name: legacy
    profiles: [editor]
    owner: legacy_admin
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.default_privileges.len(), 2);

        // inventory uses default_owner
        assert_eq!(
            expanded.default_privileges[0].owner,
            Some("app_owner".to_string())
        );
        assert_eq!(expanded.default_privileges[0].schema, "inventory");

        // legacy uses override
        assert_eq!(
            expanded.default_privileges[1].owner,
            Some("legacy_admin".to_string())
        );
        assert_eq!(expanded.default_privileges[1].schema, "legacy");
    }

    #[test]
    fn expand_merges_oneoff_roles_and_grants() {
        let yaml = r#"
profiles:
  editor:
    grants:
      - privileges: [SELECT]
        on: { type: table, name: "*" }

schemas:
  - name: inventory
    profiles: [editor]

roles:
  - name: analytics
    login: true

grants:
  - role: analytics
    privileges: [SELECT]
    on:
      type: table
      schema: inventory
      name: "*"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 2);
        assert_eq!(expanded.grants.len(), 2); // 1 from profile + 1 one-off
    }

    #[test]
    fn parse_membership_with_email_roles() {
        let yaml = r#"
memberships:
  - role: inventory-editor
    members:
      - name: "alice@example.com"
        inherit: true
      - name: "engineering@example.com"
        admin: true
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.memberships.len(), 1);
        assert_eq!(manifest.memberships[0].members.len(), 2);
        assert_eq!(manifest.memberships[0].members[0].name, "alice@example.com");
        assert!(manifest.memberships[0].members[0].inherit);
        assert!(manifest.memberships[0].members[1].admin);
    }

    #[test]
    fn member_spec_defaults() {
        let yaml = r#"
memberships:
  - role: some-role
    members:
      - name: user1
"#;
        let manifest = parse_manifest(yaml).unwrap();
        // inherit defaults to true, admin defaults to false
        assert!(manifest.memberships[0].members[0].inherit);
        assert!(!manifest.memberships[0].members[0].admin);
    }

    #[test]
    fn expand_rejects_duplicate_retirements() {
        let yaml = r#"
retirements:
  - role: old-app
  - role: old-app
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(matches!(
            result,
            Err(ManifestError::DuplicateRetirement(role)) if role == "old-app"
        ));
    }

    #[test]
    fn expand_rejects_retirement_for_desired_role() {
        let yaml = r#"
roles:
  - name: old-app

retirements:
  - role: old-app
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(matches!(
            result,
            Err(ManifestError::RetirementRoleStillDesired(role)) if role == "old-app"
        ));
    }

    #[test]
    fn expand_rejects_self_reassign_retirement() {
        let yaml = r#"
retirements:
  - role: old-app
    reassign_owned_to: old-app
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(matches!(
            result,
            Err(ManifestError::RetirementSelfReassign { role }) if role == "old-app"
        ));
    }

    #[test]
    fn parse_auth_providers() {
        let yaml = r#"
auth_providers:
  - type: cloud_sql_iam
    project: my-gcp-project
  - type: alloydb_iam
    project: my-gcp-project
    cluster: analytics-prod
  - type: rds_iam
    region: us-east-1
  - type: azure_ad
    tenant_id: "abc-123"
  - type: supabase
    project_ref: myprojref
  - type: planet_scale
    organization: my-org

roles:
  - name: app-service
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.auth_providers.len(), 6);
        assert!(matches!(
            &manifest.auth_providers[0],
            AuthProvider::CloudSqlIam { project: Some(p) } if p == "my-gcp-project"
        ));
        assert!(matches!(
            &manifest.auth_providers[1],
            AuthProvider::AlloyDbIam {
                project: Some(p),
                cluster: Some(c)
            } if p == "my-gcp-project" && c == "analytics-prod"
        ));
        assert!(matches!(
            &manifest.auth_providers[2],
            AuthProvider::RdsIam { region: Some(r) } if r == "us-east-1"
        ));
        assert!(matches!(
            &manifest.auth_providers[3],
            AuthProvider::AzureAd { tenant_id: Some(t) } if t == "abc-123"
        ));
        assert!(matches!(
            &manifest.auth_providers[4],
            AuthProvider::Supabase { project_ref: Some(r) } if r == "myprojref"
        ));
        assert!(matches!(
            &manifest.auth_providers[5],
            AuthProvider::PlanetScale { organization: Some(o) } if o == "my-org"
        ));
    }

    #[test]
    fn parse_manifest_without_auth_providers() {
        let yaml = r#"
roles:
  - name: test-role
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert!(manifest.auth_providers.is_empty());
    }

    // -----------------------------------------------------------------------
    // Semantic validation tests
    // -----------------------------------------------------------------------

    /// Helper: parse, expand, then validate semantics.
    fn expand_and_validate(yaml: &str) -> Result<ExpandedManifest, ManifestError> {
        let manifest = parse_manifest(yaml)?;
        let expanded = expand_manifest(&manifest)?;
        validate_semantics(&expanded)?;
        Ok(expanded)
    }

    #[test]
    fn reject_execute_on_table() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [EXECUTE]
    on: { type: table, schema: public, name: "*" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("EXECUTE"));
        assert!(err.contains("table"));
    }

    #[test]
    fn reject_select_on_function() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [SELECT]
    on: { type: function, schema: public, name: "my_func()" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SELECT"));
        assert!(err.contains("function"));
    }

    #[test]
    fn reject_truncate_on_view() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [TRUNCATE]
    on: { type: view, schema: public, name: "my_view" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("TRUNCATE"));
        assert!(err.contains("view"));
    }

    #[test]
    fn reject_insert_on_materialized_view() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [INSERT]
    on: { type: materialized_view, schema: public, name: "my_matview" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("INSERT"));
        assert!(err.contains("materialized_view"));
    }

    #[test]
    fn reject_connect_on_schema() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [CONNECT]
    on: { type: schema, name: "public" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("CONNECT"));
        assert!(err.contains("schema"));
    }

    #[test]
    fn reject_invalid_privilege_in_profile_grant() {
        let yaml = r#"
profiles:
  bad:
    grants:
      - privileges: [EXECUTE]
        on: { type: table, name: "*" }
schemas:
  - name: myschema
    profiles: [bad]
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("EXECUTE"));
        assert!(err.contains("table"));
    }

    #[test]
    fn reject_invalid_privilege_in_default_privilege() {
        let yaml = r#"
roles:
  - name: app
default_privileges:
  - schema: public
    grant:
      - role: app
        privileges: [DELETE]
        on_type: sequence
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DELETE"));
        assert!(err.contains("sequence"));
    }

    #[test]
    fn reject_default_privilege_on_view() {
        let yaml = r#"
roles:
  - name: app
default_privileges:
  - schema: public
    grant:
      - role: app
        privileges: [SELECT]
        on_type: view
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("view"));
        assert!(err.contains("default privileges do not support"));
    }

    #[test]
    fn reject_default_privilege_on_database() {
        let yaml = r#"
roles:
  - name: app
default_privileges:
  - schema: public
    grant:
      - role: app
        privileges: [CONNECT]
        on_type: database
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("database"));
    }

    #[test]
    fn reject_database_grant_with_schema() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [CONNECT]
    on: { type: database, schema: public, name: "mydb" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must not specify a schema"));
    }

    #[test]
    fn reject_wildcard_on_type() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [USAGE]
    on: { type: type, schema: public, name: "*" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("wildcard"));
        assert!(err.contains("type"));
    }

    #[test]
    fn reject_empty_role_name() {
        let yaml = r#"
roles:
  - name: ""
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn reject_connection_limit_below_minus_one() {
        let yaml = r#"
roles:
  - name: app
    connection_limit: -2
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("connection_limit"));
        assert!(err.contains("-2"));
    }

    #[test]
    fn accept_valid_privilege_combos() {
        let yaml = r#"
roles:
  - name: app
    login: true
    connection_limit: 10

grants:
  - role: app
    privileges: [SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER]
    on: { type: table, schema: public, name: "*" }
  - role: app
    privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
    on: { type: view, schema: public, name: "my_view" }
  - role: app
    privileges: [SELECT]
    on: { type: materialized_view, schema: public, name: "my_matview" }
  - role: app
    privileges: [SELECT, UPDATE, USAGE]
    on: { type: sequence, schema: public, name: "*" }
  - role: app
    privileges: [EXECUTE]
    on: { type: function, schema: public, name: "*" }
  - role: app
    privileges: [CREATE, USAGE]
    on: { type: schema, name: "public" }
  - role: app
    privileges: [CREATE, CONNECT, TEMPORARY]
    on: { type: database, name: "mydb" }
  - role: app
    privileges: [USAGE]
    on: { type: type, schema: public, name: "my_type" }

default_privileges:
  - schema: public
    grant:
      - role: app
        privileges: [SELECT]
        on_type: table
      - role: app
        privileges: [USAGE]
        on_type: sequence
      - role: app
        privileges: [EXECUTE]
        on_type: function
      - role: app
        privileges: [USAGE]
        on_type: type
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn multiple_errors_accumulated() {
        let yaml = r#"
roles:
  - name: app
    connection_limit: -5
grants:
  - role: app
    privileges: [EXECUTE]
    on: { type: table, schema: public, name: "*" }
  - role: app
    privileges: [SELECT]
    on: { type: function, schema: public, name: "*" }
default_privileges:
  - schema: public
    grant:
      - role: app
        privileges: [SELECT]
        on_type: view
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should be a ValidationErrors with multiple errors
        match err {
            ManifestError::ValidationErrors(errors) => {
                // At least 3 errors: EXECUTE on table, SELECT on function, view default priv,
                // connection_limit -5
                assert!(
                    errors.len() >= 3,
                    "expected at least 3 errors, got {}",
                    errors.len()
                );
            }
            _ => panic!("expected ValidationErrors, got: {err}"),
        }
    }

    #[test]
    fn accept_connection_limit_minus_one() {
        let yaml = r#"
roles:
  - name: app
    connection_limit: -1
"#;
        assert!(expand_and_validate(yaml).is_ok());
    }

    #[test]
    fn accept_connection_limit_zero() {
        let yaml = r#"
roles:
  - name: app
    connection_limit: 0
"#;
        assert!(expand_and_validate(yaml).is_ok());
    }

    #[test]
    fn reject_default_privilege_on_materialized_view() {
        let yaml = r#"
roles:
  - name: app
default_privileges:
  - schema: public
    grant:
      - role: app
        privileges: [SELECT]
        on_type: materialized_view
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("materialized_view"));
    }

    #[test]
    fn reject_wildcard_on_schema() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [USAGE]
    on: { type: schema, name: "*" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("wildcard"));
    }

    #[test]
    fn reject_wildcard_on_database() {
        let yaml = r#"
roles:
  - name: app
grants:
  - role: app
    privileges: [CONNECT]
    on: { type: database, name: "*" }
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("wildcard"));
    }

    #[test]
    fn reject_invalid_privilege_in_profile_default_privilege() {
        let yaml = r#"
profiles:
  bad:
    default_privileges:
      - privileges: [DELETE]
        on_type: sequence
schemas:
  - name: myschema
    profiles: [bad]
"#;
        let result = expand_and_validate(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DELETE"));
        assert!(err.contains("sequence"));
    }
}
