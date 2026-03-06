//! Custom Resource Definition for `PostgresPolicy`.
//!
//! Defines the `pgroles.io/v1alpha1` CRD that the operator watches.
//! The spec mirrors the CLI manifest schema with additional fields for
//! database connection and reconciliation scheduling.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use pgroles_core::manifest::{
    DefaultPrivilege, Grant, Membership, ObjectType, Privilege, RoleRetirement, SchemaBinding,
};

// ---------------------------------------------------------------------------
// CRD spec
// ---------------------------------------------------------------------------

/// Spec for a `PostgresPolicy` custom resource.
///
/// Defines the desired state of PostgreSQL roles, grants, default privileges,
/// and memberships for a single database connection.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "PostgresPolicy",
    namespaced,
    status = "PostgresPolicyStatus",
    shortname = "pgr",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct PostgresPolicySpec {
    /// Database connection configuration.
    pub connection: ConnectionSpec,

    /// Reconciliation interval (e.g. "5m", "1h"). Defaults to "5m".
    #[serde(default = "default_interval")]
    pub interval: String,

    /// Suspend reconciliation when true. Defaults to false.
    #[serde(default)]
    pub suspend: bool,

    /// Default owner for ALTER DEFAULT PRIVILEGES (e.g. "app_owner").
    #[serde(default)]
    pub default_owner: Option<String>,

    /// Reusable privilege profiles.
    #[serde(default)]
    pub profiles: std::collections::HashMap<String, ProfileSpec>,

    /// Schema bindings that expand profiles into concrete roles/grants.
    #[serde(default)]
    pub schemas: Vec<SchemaBinding>,

    /// One-off role definitions.
    #[serde(default)]
    pub roles: Vec<RoleSpec>,

    /// One-off grants.
    #[serde(default)]
    pub grants: Vec<Grant>,

    /// One-off default privileges.
    #[serde(default)]
    pub default_privileges: Vec<DefaultPrivilege>,

    /// Membership edges.
    #[serde(default)]
    pub memberships: Vec<Membership>,

    /// Explicit role-retirement workflows for roles that should be removed.
    #[serde(default)]
    pub retirements: Vec<RoleRetirement>,
}

fn default_interval() -> String {
    "5m".to_string()
}

/// Database connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSpec {
    /// Reference to a Kubernetes Secret containing the connection string.
    /// The secret must have a key named `DATABASE_URL`.
    pub secret_ref: SecretReference,

    /// Override the key in the Secret to read. Defaults to `DATABASE_URL`.
    #[serde(default = "default_secret_key")]
    pub secret_key: String,
}

fn default_secret_key() -> String {
    "DATABASE_URL".to_string()
}

/// Reference to a Kubernetes Secret in the same namespace.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretReference {
    /// Name of the Secret.
    pub name: String,
}

/// A reusable privilege profile (CRD-compatible version).
///
/// This mirrors `pgroles_core::manifest::Profile` but derives `JsonSchema`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProfileSpec {
    #[serde(default)]
    pub login: Option<bool>,

    #[serde(default)]
    pub grants: Vec<ProfileGrantSpec>,

    #[serde(default)]
    pub default_privileges: Vec<DefaultPrivilegeGrantSpec>,
}

/// Grant template within a profile.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProfileGrantSpec {
    pub privileges: Vec<Privilege>,
    pub on: ProfileObjectTargetSpec,
}

/// Object target within a profile.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProfileObjectTargetSpec {
    #[serde(rename = "type")]
    pub object_type: ObjectType,
    #[serde(default)]
    pub name: Option<String>,
}

/// Default privilege grant within a profile.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DefaultPrivilegeGrantSpec {
    #[serde(default)]
    pub role: Option<String>,
    pub privileges: Vec<Privilege>,
    pub on_type: ObjectType,
}

/// A concrete role definition (CRD-compatible version).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoleSpec {
    pub name: String,
    #[serde(default)]
    pub login: Option<bool>,
    #[serde(default)]
    pub superuser: Option<bool>,
    #[serde(default)]
    pub createdb: Option<bool>,
    #[serde(default)]
    pub createrole: Option<bool>,
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub replication: Option<bool>,
    #[serde(default)]
    pub bypassrls: Option<bool>,
    #[serde(default)]
    pub connection_limit: Option<i32>,
    #[serde(default)]
    pub comment: Option<String>,
}

// ---------------------------------------------------------------------------
// CRD status
// ---------------------------------------------------------------------------

/// Status of a `PostgresPolicy` resource.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PostgresPolicyStatus {
    /// Standard Kubernetes conditions.
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,

    /// The `.metadata.generation` that was last successfully reconciled.
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// ISO 8601 timestamp of the last successful reconciliation.
    #[serde(default)]
    pub last_reconcile_time: Option<String>,

    /// Summary of changes applied in the last reconciliation.
    #[serde(default)]
    pub change_summary: Option<ChangeSummary>,
}

/// A condition on the `PostgresPolicy` resource.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyCondition {
    /// Type of condition: "Ready", "Reconciling", "Degraded".
    #[serde(rename = "type")]
    pub condition_type: String,

    /// Status: "True", "False", or "Unknown".
    pub status: String,

    /// Human-readable reason for the condition.
    #[serde(default)]
    pub reason: Option<String>,

    /// Human-readable message.
    #[serde(default)]
    pub message: Option<String>,

    /// Last time the condition transitioned.
    #[serde(default)]
    pub last_transition_time: Option<String>,
}

/// Summary of changes applied during reconciliation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ChangeSummary {
    pub roles_created: i32,
    pub roles_altered: i32,
    pub roles_dropped: i32,
    pub sessions_terminated: i32,
    pub grants_added: i32,
    pub grants_revoked: i32,
    pub default_privileges_set: i32,
    pub default_privileges_revoked: i32,
    pub members_added: i32,
    pub members_removed: i32,
    pub total: i32,
}

// ---------------------------------------------------------------------------
// Conversion: CRD spec → core manifest types
// ---------------------------------------------------------------------------

impl PostgresPolicySpec {
    /// Convert the CRD spec into a `PolicyManifest` for use with the core library.
    pub fn to_policy_manifest(&self) -> pgroles_core::manifest::PolicyManifest {
        use pgroles_core::manifest::{
            DefaultPrivilegeGrant, MemberSpec, PolicyManifest, Profile, ProfileGrant,
            ProfileObjectTarget, RoleDefinition,
        };

        let profiles = self
            .profiles
            .iter()
            .map(|(name, spec)| {
                let profile = Profile {
                    login: spec.login,
                    grants: spec
                        .grants
                        .iter()
                        .map(|g| ProfileGrant {
                            privileges: g.privileges.clone(),
                            on: ProfileObjectTarget {
                                object_type: g.on.object_type,
                                name: g.on.name.clone(),
                            },
                        })
                        .collect(),
                    default_privileges: spec
                        .default_privileges
                        .iter()
                        .map(|dp| DefaultPrivilegeGrant {
                            role: dp.role.clone(),
                            privileges: dp.privileges.clone(),
                            on_type: dp.on_type,
                        })
                        .collect(),
                };
                (name.clone(), profile)
            })
            .collect();

        let roles = self
            .roles
            .iter()
            .map(|r| RoleDefinition {
                name: r.name.clone(),
                login: r.login,
                superuser: r.superuser,
                createdb: r.createdb,
                createrole: r.createrole,
                inherit: r.inherit,
                replication: r.replication,
                bypassrls: r.bypassrls,
                connection_limit: r.connection_limit,
                comment: r.comment.clone(),
            })
            .collect();

        // Memberships need MemberSpec conversion — the core type should
        // already be compatible since we use it directly in the CRD spec.
        // But we need to ensure the serde aliases work. Let's rebuild to be safe.
        let memberships = self
            .memberships
            .iter()
            .map(|m| pgroles_core::manifest::Membership {
                role: m.role.clone(),
                members: m
                    .members
                    .iter()
                    .map(|ms| MemberSpec {
                        name: ms.name.clone(),
                        inherit: ms.inherit,
                        admin: ms.admin,
                    })
                    .collect(),
            })
            .collect();

        PolicyManifest {
            default_owner: self.default_owner.clone(),
            auth_providers: Vec::new(),
            profiles,
            schemas: self.schemas.clone(),
            roles,
            grants: self.grants.clone(),
            default_privileges: self.default_privileges.clone(),
            memberships,
            retirements: self.retirements.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

impl PostgresPolicyStatus {
    /// Set a condition, replacing any existing condition of the same type.
    pub fn set_condition(&mut self, condition: PolicyCondition) {
        if let Some(existing) = self
            .conditions
            .iter_mut()
            .find(|c| c.condition_type == condition.condition_type)
        {
            *existing = condition;
        } else {
            self.conditions.push(condition);
        }
    }
}

/// Create a timestamp string in ISO 8601 / RFC 3339 format.
pub fn now_rfc3339() -> String {
    // Use k8s-openapi's chrono re-export or manual formatting.
    // For simplicity, use the system time.
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    // Format as simplified ISO 8601
    let secs = now.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Convert days since epoch to date (simplified — good enough for status)
    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Helper to create a "Ready" condition.
pub fn ready_condition(status: bool, reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Ready".to_string(),
        status: if status { "True" } else { "False" }.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Reconciling" condition.
pub fn reconciling_condition(message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Reconciling".to_string(),
        status: "True".to_string(),
        reason: Some("Reconciling".to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Degraded" condition.
pub fn degraded_condition(reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Degraded".to_string(),
        status: "True".to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_generates_valid_schema() {
        let crd = PostgresPolicy::crd();
        let yaml = serde_yaml::to_string(&crd).expect("CRD should serialize to YAML");
        assert!(yaml.contains("pgroles.io"), "group should be pgroles.io");
        assert!(yaml.contains("v1alpha1"), "version should be v1alpha1");
        assert!(
            yaml.contains("PostgresPolicy"),
            "kind should be PostgresPolicy"
        );
    }

    #[test]
    fn spec_to_policy_manifest_roundtrip() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: SecretReference {
                    name: "pg-secret".to_string(),
                },
                secret_key: "DATABASE_URL".to_string(),
            },
            interval: "5m".to_string(),
            suspend: false,
            default_owner: Some("app_owner".to_string()),
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "analytics".to_string(),
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: Some("test role".to_string()),
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![RoleRetirement {
                role: "legacy-app".to_string(),
                reassign_owned_to: Some("app_owner".to_string()),
                drop_owned: true,
                terminate_sessions: true,
            }],
        };

        let manifest = spec.to_policy_manifest();
        assert_eq!(manifest.default_owner, Some("app_owner".to_string()));
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.roles[0].name, "analytics");
        assert_eq!(manifest.roles[0].login, Some(true));
        assert_eq!(manifest.roles[0].comment, Some("test role".to_string()));
        assert_eq!(manifest.retirements.len(), 1);
        assert_eq!(manifest.retirements[0].role, "legacy-app");
        assert_eq!(
            manifest.retirements[0].reassign_owned_to.as_deref(),
            Some("app_owner")
        );
        assert!(manifest.retirements[0].drop_owned);
        assert!(manifest.retirements[0].terminate_sessions);
    }

    #[test]
    fn status_set_condition_replaces_existing() {
        let mut status = PostgresPolicyStatus::default();

        status.set_condition(ready_condition(false, "Pending", "Initial"));
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].status, "False");

        status.set_condition(ready_condition(true, "Reconciled", "All good"));
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].status, "True");
        assert_eq!(status.conditions[0].reason.as_deref(), Some("Reconciled"));
    }

    #[test]
    fn status_set_condition_adds_new_type() {
        let mut status = PostgresPolicyStatus::default();

        status.set_condition(ready_condition(true, "OK", "ready"));
        status.set_condition(degraded_condition("Error", "something broke"));

        assert_eq!(status.conditions.len(), 2);
    }

    #[test]
    fn now_rfc3339_produces_valid_format() {
        let ts = now_rfc3339();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.len() == 20, "expected 20 chars, got {}: {ts}", ts.len());
        assert!(ts.ends_with('Z'), "should end with Z: {ts}");
        assert_eq!(&ts[4..5], "-", "should have dash at pos 4: {ts}");
        assert_eq!(&ts[10..11], "T", "should have T at pos 10: {ts}");
    }

    #[test]
    fn crd_spec_deserializes_from_yaml() {
        let yaml = r#"
connection:
  secretRef:
    name: pg-credentials
interval: "10m"
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
roles:
  - name: analytics
    login: true
grants:
  - role: analytics
    privileges: [CONNECT]
    on: { type: database, name: mydb }
memberships:
  - role: inventory-editor
    members:
      - name: analytics
retirements:
  - role: legacy-app
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
"#;
        let spec: PostgresPolicySpec = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(spec.interval, "10m");
        assert_eq!(spec.default_owner, Some("app_owner".to_string()));
        assert_eq!(spec.profiles.len(), 1);
        assert!(spec.profiles.contains_key("editor"));
        assert_eq!(spec.schemas.len(), 1);
        assert_eq!(spec.roles.len(), 1);
        assert_eq!(spec.grants.len(), 1);
        assert_eq!(spec.memberships.len(), 1);
        assert_eq!(spec.retirements.len(), 1);
        assert_eq!(spec.retirements[0].role, "legacy-app");
        assert!(spec.retirements[0].terminate_sessions);
    }
}
