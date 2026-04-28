//! Custom Resource Definition for `PostgresPolicy`.
//!
//! Defines the `pgroles.io/v1alpha1` CRD that the operator watches.
//! The spec mirrors the CLI manifest schema with additional fields for
//! database connection and reconciliation scheduling.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use pgroles_core::manifest::{
    DefaultPrivilege, Grant, Membership, ObjectType, Privilege, RoleRetirement, SchemaBinding,
};

/// Valid PostgreSQL SSL modes for connection params.
pub const VALID_SSL_MODES: &[&str] = &[
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
];

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
    category = "pgroles",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.mode"}"#,
    printcolumn = r#"{"name":"Recon","type":"string","jsonPath":".spec.reconciliation_mode","priority":1}"#,
    printcolumn = r#"{"name":"Drift","type":"string","jsonPath":".status.conditions[?(@.type==\"Drifted\")].status"}"#,
    printcolumn = r#"{"name":"Changes","type":"integer","jsonPath":".status.change_summary.total"}"#,
    printcolumn = r#"{"name":"Last Reconcile","type":"date","jsonPath":".status.last_successful_reconcile_time"}"#,
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

    /// Reconciliation mode: `apply` executes SQL, `plan` computes drift only.
    #[serde(default)]
    pub mode: PolicyMode,

    /// Convergence strategy: how aggressively to converge the database.
    ///
    /// - `authoritative` (default): full convergence — anything not in the
    ///   manifest is revoked/dropped.
    /// - `additive`: only grant, never revoke — safe for incremental adoption.
    /// - `adopt`: manage declared roles fully, but never drop undeclared roles.
    #[serde(default)]
    pub reconciliation_mode: CrdReconciliationMode,

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

    /// Approval mode for plans: `auto` or `manual`.
    /// When `manual`, plans require explicit approval before execution.
    /// When `auto`, plans are approved and applied immediately.
    /// When omitted, inferred from `mode`: `apply` → `auto`, `plan` → `manual`.
    /// This ensures backward compatibility for existing `mode: apply` users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalMode>,
}

fn default_interval() -> String {
    "5m".to_string()
}

/// Policy reconcile mode.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    #[default]
    Apply,
    Plan,
}

/// Convergence strategy for how aggressively to converge the database.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CrdReconciliationMode {
    /// Full convergence — the manifest is the entire truth.
    #[default]
    Authoritative,
    /// Only grant, never revoke — safe for incremental adoption.
    Additive,
    /// Manage declared roles fully, but never drop undeclared roles.
    Adopt,
}

/// Approval mode for plans generated by this policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum ApprovalMode {
    /// Plans require explicit approval annotation before execution.
    #[serde(rename = "manual")]
    Manual,
    /// Plans are approved and applied automatically.
    #[serde(rename = "auto")]
    Auto,
}

impl PostgresPolicySpec {
    /// Resolve the effective approval mode, inferring from `mode` when not set.
    /// `apply` → `Auto` (backward compat), `plan` → `Manual`.
    pub fn effective_approval(&self) -> ApprovalMode {
        match &self.approval {
            Some(mode) => mode.clone(),
            None => match self.mode {
                PolicyMode::Apply => ApprovalMode::Auto,
                PolicyMode::Plan => ApprovalMode::Manual,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Well-known annotations and labels
// ---------------------------------------------------------------------------

/// Annotation key used to approve a `PostgresPolicyPlan`.
pub const PLAN_APPROVED_ANNOTATION: &str = "pgroles.io/approved";

/// Annotation key used to reject a `PostgresPolicyPlan`.
pub const PLAN_REJECTED_ANNOTATION: &str = "pgroles.io/rejected";

/// Label key for the parent policy name on plan resources.
pub const LABEL_POLICY: &str = "pgroles.io/policy";

/// Label key for the managed database identity on plan resources.
pub const LABEL_DATABASE_IDENTITY: &str = "pgroles.io/database-identity";

impl From<CrdReconciliationMode> for pgroles_core::diff::ReconciliationMode {
    fn from(crd: CrdReconciliationMode) -> Self {
        match crd {
            CrdReconciliationMode::Authoritative => {
                pgroles_core::diff::ReconciliationMode::Authoritative
            }
            CrdReconciliationMode::Additive => pgroles_core::diff::ReconciliationMode::Additive,
            CrdReconciliationMode::Adopt => pgroles_core::diff::ReconciliationMode::Adopt,
        }
    }
}

/// Database connection configuration.
///
/// Supports two mutually exclusive modes:
///
/// **Mode 1 — Single URL** (backward-compatible):
/// ```yaml
/// connection:
///   secretRef: { name: my-secret }
///   secretKey: DATABASE_URL        # optional, defaults to DATABASE_URL
/// ```
///
/// **Mode 2 — Structured params** (for Zalando/CNPG/PGO secrets):
/// ```yaml
/// connection:
///   params:
///     host: my-cluster-postgres
///     port: 5432
///     dbname: mydb
///     usernameSecret: { name: zalando-creds, key: username }
///     passwordSecret: { name: zalando-creds, key: password }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSpec {
    /// Reference to a Kubernetes Secret containing a connection URL.
    /// Mutually exclusive with `params`.
    #[serde(default)]
    pub secret_ref: Option<SecretReference>,

    /// Key within the Secret to read. Defaults to `DATABASE_URL`.
    /// Only used with `secretRef`.
    #[serde(default)]
    pub secret_key: Option<String>,

    /// Structured connection parameters. Each field is either a plain string
    /// or a reference to a Secret key. Mutually exclusive with `secretRef`.
    #[serde(default)]
    pub params: Option<ConnectionParams>,
}

impl ConnectionSpec {
    /// Effective secret key for URL mode. Defaults to `DATABASE_URL`.
    pub fn effective_secret_key(&self) -> &str {
        self.secret_key.as_deref().unwrap_or("DATABASE_URL")
    }

    /// Collect all Secret names referenced by this connection spec.
    pub fn collect_secret_names(&self, names: &mut BTreeSet<String>) {
        if let Some(ref secret_ref) = self.secret_ref {
            names.insert(secret_ref.name.clone());
        }
        if let Some(ref params) = self.params {
            for sel in [
                &params.host_secret,
                &params.port_secret,
                &params.dbname_secret,
                &params.username_secret,
                &params.password_secret,
                &params.ssl_mode_secret,
            ]
            .into_iter()
            .flatten()
            {
                names.insert(sel.name.clone());
            }
        }
    }

    /// Deterministic identity key for this connection spec.
    ///
    /// - URL mode: `{secret_ref.name}/{secret_key}`
    /// - Params mode: canonical representation of the params
    ///
    /// Uses `\0` as field separator since null bytes cannot appear in K8s names
    /// or secret values, avoiding ambiguity from colons in literal values.
    /// Deterministic identity key for per-database locking and conflict detection.
    ///
    /// Identifies the target database (host + port + dbname) but NOT the
    /// credentials. Two policies targeting the same database with different
    /// users should still be considered as targeting the same database for
    /// locking and overlap checks.
    pub fn identity_key(&self) -> String {
        if let Some(ref secret_ref) = self.secret_ref {
            format!("{}/{}", secret_ref.name, self.effective_secret_key())
        } else if let Some(ref params) = self.params {
            let port_part = params
                .port
                .as_ref()
                .map(|p| format!("literal={p}"))
                .or_else(|| {
                    params
                        .port_secret
                        .as_ref()
                        .map(|s| format!("secret={}\0{}", s.name, s.key))
                })
                .unwrap_or_else(|| "5432".to_string());
            format!(
                "params\0{}\0{}\0{}",
                field_identity_repr(&params.host, &params.host_secret),
                field_identity_repr(&params.dbname, &params.dbname_secret),
                port_part,
            )
        } else {
            "invalid-connection".to_string()
        }
    }

    /// Cache key for pool lookup. Includes ALL connection params so that any
    /// configuration change (credentials, sslMode, host, etc.) invalidates
    /// the cached pool. This is strictly more specific than `identity_key`.
    pub fn cache_key(&self, namespace: &str) -> String {
        if let Some(ref params) = self.params {
            let user_part = field_identity_repr(&params.username, &params.username_secret);
            let pass_part = field_identity_repr(&params.password, &params.password_secret);
            let ssl_part = params
                .ssl_mode
                .as_ref()
                .map(|v| format!("literal={v}"))
                .or_else(|| {
                    params
                        .ssl_mode_secret
                        .as_ref()
                        .map(|s| format!("secret={}\0{}", s.name, s.key))
                })
                .unwrap_or_default();
            format!(
                "{namespace}/{}\0user={user_part}\0pass={pass_part}\0ssl={ssl_part}",
                self.identity_key()
            )
        } else {
            format!("{namespace}/{}", self.identity_key())
        }
    }
}

/// Deterministic string representation for a literal/secret field pair.
///
/// Uses a `literal=` / `secret=` prefix scheme so that a literal value
/// can never collide with a secret reference representation.
fn field_identity_repr(literal: &Option<String>, secret: &Option<SecretKeySelector>) -> String {
    if let Some(value) = literal {
        format!("literal={value}")
    } else if let Some(sel) = secret {
        format!("secret={}\0{}", sel.name, sel.key)
    } else {
        String::new()
    }
}

/// Structured connection parameters for building a PostgreSQL connection URL.
///
/// Each field supports either a literal value or a reference to a Kubernetes
/// Secret key. For each parameter, set either the literal field or the
/// corresponding `*Secret` field — not both.
///
/// ```yaml
/// # Zalando pattern — literals for non-sensitive, secrets for credentials
/// params:
///   host: my-cluster-postgres
///   port: 5432
///   dbname: mydb
///   sslMode: require
///   usernameSecret:
///     name: pg-creds
///     key: username
///   passwordSecret:
///     name: pg-creds
///     key: password
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionParams {
    /// PostgreSQL host as a literal value.
    #[serde(default)]
    pub host: Option<String>,
    /// PostgreSQL host from a Secret key.
    #[serde(default)]
    pub host_secret: Option<SecretKeySelector>,

    /// Port as a literal value. Defaults to 5432 if neither port nor portSecret is set.
    #[serde(default)]
    pub port: Option<u16>,
    /// Port from a Secret key.
    #[serde(default)]
    pub port_secret: Option<SecretKeySelector>,

    /// Database name as a literal value.
    #[serde(default)]
    pub dbname: Option<String>,
    /// Database name from a Secret key.
    #[serde(default)]
    pub dbname_secret: Option<SecretKeySelector>,

    /// Username as a literal value.
    #[serde(default)]
    pub username: Option<String>,
    /// Username from a Secret key.
    #[serde(default)]
    pub username_secret: Option<SecretKeySelector>,

    /// Password as a literal value (not recommended for production).
    #[serde(default)]
    pub password: Option<String>,
    /// Password from a Secret key (recommended).
    #[serde(default)]
    pub password_secret: Option<SecretKeySelector>,

    /// SSL mode as a literal value.
    #[serde(default)]
    pub ssl_mode: Option<String>,
    /// SSL mode from a Secret key.
    #[serde(default)]
    pub ssl_mode_secret: Option<SecretKeySelector>,
}

/// Reference to a specific key within a Kubernetes Secret.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretKeySelector {
    /// Name of the Secret.
    pub name: String,
    /// Key within the Secret.
    pub key: String,
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
    #[serde(alias = "on")]
    pub object: ProfileObjectTargetSpec,
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
    /// Password source for this role. Either a reference to an existing Secret
    /// or a request for the operator to generate one.
    #[serde(default)]
    pub password: Option<PasswordSpec>,
    /// Password expiration timestamp (ISO 8601, e.g. "2025-12-31T00:00:00Z").
    #[serde(default)]
    pub password_valid_until: Option<String>,
}

/// Password configuration: either reference an existing Secret or have the
/// operator generate a password and create a Secret.
///
/// Exactly one of `secretRef` or `generate` must be set.
///
/// ```yaml
/// # Read from existing Secret:
/// password:
///   secretRef: { name: role-passwords }
///   secretKey: password-user
///
/// # Operator generates and manages a Secret:
/// password:
///   generate:
///     length: 48
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasswordSpec {
    /// Reference to an existing Kubernetes Secret containing the password.
    /// Mutually exclusive with `generate`.
    #[serde(default)]
    pub secret_ref: Option<SecretReference>,
    /// Key within the referenced Secret. Defaults to the role name.
    /// Only used with `secretRef`.
    #[serde(default)]
    pub secret_key: Option<String>,
    /// Generate a random password and store it in a new Kubernetes Secret.
    /// Mutually exclusive with `secretRef`.
    #[serde(default)]
    pub generate: Option<GeneratePasswordSpec>,
}

impl PasswordSpec {
    /// Returns true if this is a reference to an existing Secret.
    pub fn is_secret_ref(&self) -> bool {
        self.secret_ref.is_some()
    }

    /// Returns true if this is a request to generate a password.
    pub fn is_generate(&self) -> bool {
        self.generate.is_some()
    }
}

/// Configuration for operator-generated passwords.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeneratePasswordSpec {
    /// Password length. Defaults to 32. Minimum 16, maximum 128.
    #[serde(default)]
    pub length: Option<u32>,
    /// Override the generated Secret name. Defaults to `{policy}-pgr-{role}`.
    #[serde(default)]
    pub secret_name: Option<String>,
    /// Key within the generated Secret. Defaults to `password`.
    #[serde(default)]
    pub secret_key: Option<String>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum PasswordValidationError {
    #[error("role \"{role}\" has a password but login is not enabled")]
    PasswordWithoutLogin { role: String },

    #[error("role \"{role}\" password must set exactly one of secretRef or generate")]
    InvalidPasswordMode { role: String },

    #[error("role \"{role}\" password.generate.length must be between {min} and {max}")]
    InvalidGeneratedLength { role: String, min: u32, max: u32 },

    #[error(
        "role \"{role}\" password.generate.secretName \"{name}\" is not a valid Kubernetes Secret name"
    )]
    InvalidGeneratedSecretName { role: String, name: String },

    #[error("role \"{role}\" password {field} \"{key}\" is not a valid Kubernetes Secret data key")]
    InvalidSecretKey {
        role: String,
        field: &'static str,
        key: String,
    },

    #[error(
        "role \"{role}\" password.generate.secretKey \"{key}\" is reserved for the SCRAM verifier"
    )]
    ReservedGeneratedSecretKey { role: String, key: String },
}

/// Errors from connection spec validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConnectionValidationError {
    #[error("connection: exactly one of secretRef or params must be set, but both were provided")]
    BothModesSet,

    #[error("connection: exactly one of secretRef or params must be set, but neither was provided")]
    NeitherModeSet,

    #[error("connection.params.{field}: secret {detail}")]
    EmptySecretKeyRef { field: String, detail: String },

    #[error(
        "connection.params.sslMode: \"{value}\" is not valid (expected one of: disable, allow, prefer, require, verify-ca, verify-full)"
    )]
    InvalidSslMode { value: String },

    #[error("connection.params.{field}: literal value must not be empty or whitespace-only")]
    EmptyLiteral { field: String },

    #[error("connection.params: exactly one of {field} or {field}Secret must be set")]
    NeitherFieldSet { field: String },

    #[error(
        "connection.params: only one of {field} or {field}Secret may be set, but both were provided"
    )]
    BothFieldsSet { field: String },
}

/// Validate a Kubernetes Secret name per RFC 1123 DNS subdomain rules:
/// lowercase alpha start, alphanumeric end, body allows lowercase alpha,
/// digits, `-`, and `.`.
fn is_valid_secret_name(name: &str) -> bool {
    if name.is_empty() || name.len() > crate::password::MAX_SECRET_NAME_LENGTH {
        return false;
    }
    let bytes = name.as_bytes();
    // RFC 1123: must start with a lowercase letter.
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'.')
}

fn is_valid_secret_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
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

    /// The `.metadata.generation` that was last attempted.
    #[serde(default)]
    pub last_attempted_generation: Option<i64>,

    /// ISO 8601 timestamp of the last successful reconciliation.
    #[serde(default)]
    pub last_successful_reconcile_time: Option<String>,

    /// Deprecated alias retained for compatibility with older status readers.
    #[serde(default)]
    pub last_reconcile_time: Option<String>,

    /// Summary of changes applied in the last reconciliation.
    #[serde(default)]
    pub change_summary: Option<ChangeSummary>,

    /// The reconciliation mode used for the last successful reconcile.
    #[serde(default)]
    pub last_reconcile_mode: Option<PolicyMode>,

    /// Planned SQL for the last successful plan-mode reconcile.
    #[serde(default)]
    pub planned_sql: Option<String>,

    /// Whether `planned_sql` was truncated to fit safely in status.
    #[serde(default)]
    pub planned_sql_truncated: bool,

    /// Canonical identity of the managed database target.
    #[serde(default)]
    pub managed_database_identity: Option<String>,

    /// Roles claimed by this policy's declared ownership scope.
    #[serde(default)]
    pub owned_roles: Vec<String>,

    /// Schemas claimed by this policy's declared ownership scope.
    #[serde(default)]
    pub owned_schemas: Vec<String>,

    /// Last reconcile error message, if any.
    #[serde(default)]
    pub last_error: Option<String>,

    /// Last applied password source version for each password-managed role.
    #[serde(default)]
    pub applied_password_source_versions: BTreeMap<String, String>,

    /// Consecutive transient operational failures used for exponential backoff.
    #[serde(default)]
    pub transient_failure_count: i32,

    /// Reference to the current/latest plan for this policy.
    #[serde(default)]
    pub current_plan_ref: Option<PlanReference>,
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

/// Reference to a `PostgresPolicyPlan` resource.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlanReference {
    pub name: String,
}

/// Summary of changes applied during reconciliation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ChangeSummary {
    #[serde(default)]
    pub roles_created: i32,
    #[serde(default)]
    pub roles_altered: i32,
    #[serde(default)]
    pub schemas_created: i32,
    #[serde(default)]
    pub schema_owners_altered: i32,
    #[serde(default)]
    pub roles_dropped: i32,
    #[serde(default)]
    pub sessions_terminated: i32,
    #[serde(default)]
    pub grants_added: i32,
    #[serde(default)]
    pub grants_revoked: i32,
    #[serde(default)]
    pub default_privileges_set: i32,
    #[serde(default)]
    pub default_privileges_revoked: i32,
    #[serde(default)]
    pub members_added: i32,
    #[serde(default)]
    pub members_removed: i32,
    #[serde(default)]
    pub passwords_set: i32,
    #[serde(default)]
    pub total: i32,
}

// ---------------------------------------------------------------------------
// PostgresPolicyPlan CRD
// ---------------------------------------------------------------------------

/// Spec for a `PostgresPolicyPlan` custom resource.
///
/// Represents a computed reconciliation plan for a `PostgresPolicy`. Plans are
/// created by the operator and may require explicit approval before execution.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "PostgresPolicyPlan",
    namespaced,
    status = "PostgresPolicyPlanStatus",
    shortname = "pgplan",
    category = "pgroles",
    printcolumn = r#"{"name":"Policy","type":"string","jsonPath":".spec.policyRef.name"}"#,
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.reconciliationMode"}"#,
    printcolumn = r#"{"name":"Approved","type":"string","jsonPath":".status.conditions[?(@.type==\"Approved\")].status"}"#,
    printcolumn = r#"{"name":"Changes","type":"integer","jsonPath":".status.changeSummary.total"}"#,
    printcolumn = r#"{"name":"SQL Stmts","type":"integer","jsonPath":".status.sqlStatements","priority":1}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"SQL","type":"string","jsonPath":".status.sqlRef.name","priority":1}"#,
    printcolumn = r#"{"name":"Hash","type":"string","jsonPath":".status.sqlHash","priority":1}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct PostgresPolicyPlanSpec {
    /// Reference to the policy that generated this plan.
    pub policy_ref: PolicyPlanRef,
    /// The policy's `.metadata.generation` at plan time.
    pub policy_generation: i64,
    /// Reconciliation mode used for this plan.
    pub reconciliation_mode: CrdReconciliationMode,
    /// Roles that this plan covers.
    #[serde(default)]
    pub owned_roles: Vec<String>,
    /// Schemas that this plan covers.
    #[serde(default)]
    pub owned_schemas: Vec<String>,
    /// Database identity string for disambiguation in multi-db setups.
    pub managed_database_identity: String,
}

/// Reference to the parent `PostgresPolicy` that generated a plan.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyPlanRef {
    pub name: String,
}

/// Status of a `PostgresPolicyPlan` resource.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PostgresPolicyPlanStatus {
    /// Phase: Pending, Approved, Applying, Applied, Failed, Superseded.
    #[serde(default)]
    pub phase: PlanPhase,
    /// Standard conditions: Computed, Approved, Applied.
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
    /// Summary of changes in this plan.
    #[serde(default)]
    pub change_summary: Option<ChangeSummary>,
    /// Reference to ConfigMap containing the full SQL (for large plans).
    #[serde(default)]
    pub sql_ref: Option<SqlRef>,
    /// Inline SQL for small plans (below a size threshold).
    #[serde(default)]
    pub sql_inline: Option<String>,
    /// Timestamp when the plan was computed.
    #[serde(default)]
    pub computed_at: Option<String>,
    /// Timestamp when the plan was applied (if applicable).
    #[serde(default)]
    pub applied_at: Option<String>,
    /// Error message if apply failed.
    #[serde(default)]
    pub last_error: Option<String>,
    /// SHA-256 hash of the planned SQL, used to detect duplicate plans.
    /// If a newly computed plan has the same hash as the current pending plan,
    /// the operator can skip creating a redundant plan.
    #[serde(default)]
    pub sql_hash: Option<String>,
    /// Timestamp when the plan entered Applying phase (for stuck detection).
    #[serde(default)]
    pub applying_since: Option<String>,
    /// Timestamp when the plan entered Failed phase (for dedup window).
    #[serde(default)]
    pub failed_at: Option<String>,
    /// Number of SQL statements in the plan (after wildcard expansion).
    /// May be significantly larger than `changeSummary.total` when wildcard
    /// grants expand to many per-object statements.
    #[serde(default)]
    pub sql_statements: Option<i64>,
}

/// Reference to a ConfigMap containing SQL for a plan.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SqlRef {
    pub name: String,
    pub key: String,
}

/// Phase of a `PostgresPolicyPlan`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum PlanPhase {
    #[default]
    Pending,
    Approved,
    Applying,
    Applied,
    Failed,
    Superseded,
    Rejected,
}

impl std::fmt::Display for PlanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanPhase::Pending => write!(f, "Pending"),
            PlanPhase::Approved => write!(f, "Approved"),
            PlanPhase::Applying => write!(f, "Applying"),
            PlanPhase::Applied => write!(f, "Applied"),
            PlanPhase::Failed => write!(f, "Failed"),
            PlanPhase::Superseded => write!(f, "Superseded"),
            PlanPhase::Rejected => write!(f, "Rejected"),
        }
    }
}

// ---------------------------------------------------------------------------
// Conflict detection
// ---------------------------------------------------------------------------

/// Canonical target identity for conflict detection between policies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DatabaseIdentity(String);

impl DatabaseIdentity {
    /// Create a database identity from the namespace and connection spec's identity key.
    pub fn from_connection(namespace: &str, connection: &ConnectionSpec) -> Self {
        Self(format!("{namespace}/{}", connection.identity_key()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Conservative ownership claims for a policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipClaims {
    pub roles: BTreeSet<String>,
    pub schemas: BTreeSet<String>,
}

impl OwnershipClaims {
    pub fn overlaps(&self, other: &Self) -> bool {
        !self.roles.is_disjoint(&other.roles) || !self.schemas.is_disjoint(&other.schemas)
    }

    pub fn overlap_summary(&self, other: &Self) -> String {
        let overlapping_roles: Vec<_> = self.roles.intersection(&other.roles).cloned().collect();
        let overlapping_schemas: Vec<_> =
            self.schemas.intersection(&other.schemas).cloned().collect();

        let mut parts = Vec::new();
        if !overlapping_roles.is_empty() {
            parts.push(format!("roles: {}", overlapping_roles.join(", ")));
        }
        if !overlapping_schemas.is_empty() {
            parts.push(format!("schemas: {}", overlapping_schemas.join(", ")));
        }

        parts.join("; ")
    }
}

// ---------------------------------------------------------------------------
// Secret name helpers
// ---------------------------------------------------------------------------

impl PostgresPolicySpec {
    pub fn validate_password_specs(
        &self,
        policy_name: &str,
    ) -> Result<(), PasswordValidationError> {
        for role in &self.roles {
            let Some(password) = &role.password else {
                continue;
            };

            if role.login != Some(true) {
                return Err(PasswordValidationError::PasswordWithoutLogin {
                    role: role.name.clone(),
                });
            }

            match (&password.secret_ref, &password.generate) {
                (Some(_), None) => {
                    let secret_key = password.secret_key.as_deref().unwrap_or(&role.name);
                    if !is_valid_secret_key(secret_key) {
                        return Err(PasswordValidationError::InvalidSecretKey {
                            role: role.name.clone(),
                            field: "secretKey",
                            key: secret_key.to_string(),
                        });
                    }
                }
                (None, Some(generate)) => {
                    if let Some(length) = generate.length
                        && !(crate::password::MIN_PASSWORD_LENGTH
                            ..=crate::password::MAX_PASSWORD_LENGTH)
                            .contains(&length)
                    {
                        return Err(PasswordValidationError::InvalidGeneratedLength {
                            role: role.name.clone(),
                            min: crate::password::MIN_PASSWORD_LENGTH,
                            max: crate::password::MAX_PASSWORD_LENGTH,
                        });
                    }

                    let secret_name =
                        crate::password::generated_secret_name(policy_name, &role.name, generate);
                    if !is_valid_secret_name(&secret_name) {
                        return Err(PasswordValidationError::InvalidGeneratedSecretName {
                            role: role.name.clone(),
                            name: secret_name,
                        });
                    }

                    let secret_key = crate::password::generated_secret_key(generate);
                    if !is_valid_secret_key(&secret_key) {
                        return Err(PasswordValidationError::InvalidSecretKey {
                            role: role.name.clone(),
                            field: "generate.secretKey",
                            key: secret_key,
                        });
                    }
                    if secret_key == crate::password::GENERATED_VERIFIER_KEY {
                        return Err(PasswordValidationError::ReservedGeneratedSecretKey {
                            role: role.name.clone(),
                            key: secret_key,
                        });
                    }
                }
                _ => {
                    return Err(PasswordValidationError::InvalidPasswordMode {
                        role: role.name.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate the connection spec.
    ///
    /// Ensures exactly one of `secretRef` or `params` is set, and that params
    /// mode has all required fields with valid values.
    pub fn validate_connection_spec(&self) -> Result<(), ConnectionValidationError> {
        let conn = &self.connection;
        match (&conn.secret_ref, &conn.params) {
            (Some(_), None) => {
                // URL mode — valid.
                Ok(())
            }
            (None, Some(params)) => {
                // Validate a required field pair: exactly one must be set.
                fn validate_required_field(
                    field: &str,
                    literal: &Option<String>,
                    secret: &Option<SecretKeySelector>,
                ) -> Result<(), ConnectionValidationError> {
                    match (literal, secret) {
                        (Some(_), Some(_)) => {
                            return Err(ConnectionValidationError::BothFieldsSet {
                                field: field.to_string(),
                            });
                        }
                        (None, None) => {
                            return Err(ConnectionValidationError::NeitherFieldSet {
                                field: field.to_string(),
                            });
                        }
                        (Some(s), None) => {
                            if s.trim().is_empty() {
                                return Err(ConnectionValidationError::EmptyLiteral {
                                    field: field.to_string(),
                                });
                            }
                        }
                        (None, Some(sel)) => {
                            validate_secret_selector(field, sel)?;
                        }
                    }
                    Ok(())
                }

                // Validate an optional field pair: at most one may be set.
                fn validate_optional_field(
                    field: &str,
                    literal: &Option<impl AsRef<str>>,
                    secret: &Option<SecretKeySelector>,
                ) -> Result<(), ConnectionValidationError> {
                    let has_literal = literal.is_some();
                    if has_literal && secret.is_some() {
                        return Err(ConnectionValidationError::BothFieldsSet {
                            field: field.to_string(),
                        });
                    }
                    if let Some(s) = literal
                        && s.as_ref().trim().is_empty()
                    {
                        return Err(ConnectionValidationError::EmptyLiteral {
                            field: field.to_string(),
                        });
                    }
                    if let Some(sel) = secret {
                        validate_secret_selector(field, sel)?;
                    }
                    Ok(())
                }

                fn validate_secret_selector(
                    field: &str,
                    sel: &SecretKeySelector,
                ) -> Result<(), ConnectionValidationError> {
                    if sel.name.trim().is_empty() {
                        return Err(ConnectionValidationError::EmptySecretKeyRef {
                            field: field.to_string(),
                            detail: "name must not be empty".to_string(),
                        });
                    }
                    if sel.key.trim().is_empty() {
                        return Err(ConnectionValidationError::EmptySecretKeyRef {
                            field: field.to_string(),
                            detail: "key must not be empty".to_string(),
                        });
                    }
                    Ok(())
                }

                // Required fields: host, dbname, username, password.
                validate_required_field("host", &params.host, &params.host_secret)?;
                validate_required_field("dbname", &params.dbname, &params.dbname_secret)?;
                validate_required_field("username", &params.username, &params.username_secret)?;
                validate_required_field("password", &params.password, &params.password_secret)?;

                // Optional fields: port, sslMode.
                // Port is u16 so we wrap it for the generic check.
                let port_str = params.port.map(|p| p.to_string());
                validate_optional_field("port", &port_str, &params.port_secret)?;

                validate_optional_field("sslMode", &params.ssl_mode, &params.ssl_mode_secret)?;

                // Validate sslMode value if it's a literal.
                if let Some(value) = &params.ssl_mode
                    && !VALID_SSL_MODES.contains(&value.as_str())
                {
                    return Err(ConnectionValidationError::InvalidSslMode {
                        value: value.clone(),
                    });
                }

                Ok(())
            }
            (Some(_), Some(_)) => Err(ConnectionValidationError::BothModesSet),
            (None, None) => Err(ConnectionValidationError::NeitherModeSet),
        }
    }

    /// All Kubernetes Secret names referenced by this spec.
    ///
    /// Includes the connection Secret, password `secretRef` Secrets, and
    /// generated password Secrets. Used by the controller to trigger
    /// reconciliation when any of these Secrets change (or are deleted).
    pub fn referenced_secret_names(&self, policy_name: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        // Connection secrets — either URL mode or structured params.
        self.connection.collect_secret_names(&mut names);
        for role in &self.roles {
            if let Some(pw) = &role.password {
                if let Some(secret_ref) = &pw.secret_ref {
                    names.insert(secret_ref.name.clone());
                }
                if let Some(gen_spec) = &pw.generate {
                    let secret_name =
                        crate::password::generated_secret_name(policy_name, &role.name, gen_spec);
                    names.insert(secret_name);
                }
            }
        }
        names
    }
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
                            object: ProfileObjectTarget {
                                object_type: g.object.object_type,
                                name: g.object.name.clone(),
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
                password: None, // K8s passwords are resolved separately via Secret refs
                password_valid_until: r.password_valid_until.clone(),
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

    /// Derive a conservative ownership claim set from the policy spec.
    ///
    /// This intentionally claims all declared/expanded roles and all referenced
    /// schemas so overlapping policies are rejected safely.
    pub fn ownership_claims(
        &self,
    ) -> Result<OwnershipClaims, pgroles_core::manifest::ManifestError> {
        let manifest = self.to_policy_manifest();
        let expanded = pgroles_core::manifest::expand_manifest(&manifest)?;

        let mut roles: BTreeSet<String> = expanded.roles.into_iter().map(|r| r.name).collect();
        let mut schemas: BTreeSet<String> = self.schemas.iter().map(|s| s.name.clone()).collect();

        roles.extend(manifest.retirements.into_iter().map(|r| r.role));
        roles.extend(manifest.grants.iter().map(|g| g.role.clone()));
        roles.extend(
            manifest
                .default_privileges
                .iter()
                .flat_map(|dp| dp.grant.iter().filter_map(|grant| grant.role.clone())),
        );
        roles.extend(manifest.memberships.iter().map(|m| m.role.clone()));
        roles.extend(
            manifest
                .memberships
                .iter()
                .flat_map(|m| m.members.iter().map(|member| member.name.clone())),
        );

        schemas.extend(
            manifest
                .grants
                .iter()
                .filter_map(|g| match g.object.object_type {
                    ObjectType::Database => None,
                    ObjectType::Schema => g.object.name.clone(),
                    _ => g.object.schema.clone(),
                }),
        );
        schemas.extend(
            manifest
                .default_privileges
                .iter()
                .map(|dp| dp.schema.clone()),
        );

        Ok(OwnershipClaims { roles, schemas })
    }
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

impl PostgresPolicyStatus {
    /// Set a condition, replacing any existing condition of the same type.
    ///
    /// If the condition's `status` value has not changed, the existing
    /// `last_transition_time` is preserved (per Kubernetes condition conventions).
    pub fn set_condition(&mut self, new: PolicyCondition) {
        if let Some(existing) = self
            .conditions
            .iter()
            .find(|c| c.condition_type == new.condition_type)
            && existing.status == new.status
        {
            // Status unchanged — preserve the existing transition time.
            let mut updated = new;
            updated.last_transition_time = existing.last_transition_time.clone();
            self.conditions
                .retain(|c| c.condition_type != updated.condition_type);
            self.conditions.push(updated);
            return;
        }
        // New condition or status changed — use the new timestamp.
        self.conditions
            .retain(|c| c.condition_type != new.condition_type);
        self.conditions.push(new);
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
pub fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
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

/// Helper to create a "Paused" condition.
pub fn paused_condition(message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Paused".to_string(),
        status: "True".to_string(),
        reason: Some("Suspended".to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Conflict" condition.
pub fn conflict_condition(reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Conflict".to_string(),
        status: "True".to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Drifted" condition.
pub fn drifted_condition(status: bool, reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Drifted".to_string(),
        status: if status { "True" } else { "False" }.to_string(),
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
        assert!(
            yaml.contains("\"mode\"") || yaml.contains(" mode:"),
            "schema should declare spec.mode"
        );
        assert!(
            yaml.contains("\"object\"") || yaml.contains(" object:"),
            "schema should declare grant object targets using object"
        );
    }

    #[test]
    fn spec_to_policy_manifest_roundtrip() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-secret".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
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
                password: None,
                password_valid_until: None,
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
            approval: None,
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
    fn paused_condition_has_expected_shape() {
        let paused = paused_condition("paused by spec");
        assert_eq!(paused.condition_type, "Paused");
        assert_eq!(paused.status, "True");
        assert_eq!(paused.reason.as_deref(), Some("Suspended"));
    }

    #[test]
    fn ownership_claims_include_expanded_roles_and_schemas() {
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "editor".to_string(),
            ProfileSpec {
                login: Some(false),
                grants: vec![],
                default_privileges: vec![],
            },
        );

        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-secret".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles,
            schemas: vec![SchemaBinding {
                name: "inventory".to_string(),
                profiles: vec!["editor".to_string()],
                role_pattern: "{schema}-{profile}".to_string(),
                owner: None,
            }],
            roles: vec![RoleSpec {
                name: "app-service".to_string(),
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: None,
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![RoleRetirement {
                role: "legacy-app".to_string(),
                reassign_owned_to: None,
                drop_owned: false,
                terminate_sessions: false,
            }],
            approval: None,
        };

        let claims = spec.ownership_claims().unwrap();
        assert!(claims.roles.contains("inventory-editor"));
        assert!(claims.roles.contains("app-service"));
        assert!(claims.roles.contains("legacy-app"));
        assert!(claims.schemas.contains("inventory"));
    }

    #[test]
    fn ownership_overlap_summary_reports_roles_and_schemas() {
        let mut left = OwnershipClaims::default();
        left.roles.insert("analytics".to_string());
        left.schemas.insert("reporting".to_string());

        let mut right = OwnershipClaims::default();
        right.roles.insert("analytics".to_string());
        right.schemas.insert("reporting".to_string());
        right.schemas.insert("other".to_string());

        assert!(left.overlaps(&right));
        let summary = left.overlap_summary(&right);
        assert!(summary.contains("roles: analytics"));
        assert!(summary.contains("schemas: reporting"));
    }

    #[test]
    fn database_identity_uses_namespace_and_identity_key() {
        let conn = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("DATABASE_URL".to_string()),
            params: None,
        };
        let identity = DatabaseIdentity::from_connection("prod", &conn);
        assert_eq!(identity.as_str(), "prod/db-creds/DATABASE_URL");
    }

    #[test]
    fn identity_key_same_database_different_users_are_equal() {
        // Two policies targeting the same database but with different users
        // should have the SAME identity key (for locking/conflict detection).
        let user_a = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("alice".into()),
                username_secret: None,
                password: Some("pass-a".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        };
        let user_b = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("bob".into()),
                username_secret: None,
                password: Some("pass-b".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        };

        assert_eq!(
            user_a.identity_key(),
            user_b.identity_key(),
            "same database with different users should have the same identity key"
        );
        // But cache keys should differ (different credentials = different pool).
        assert_ne!(
            user_a.cache_key("default"),
            user_b.cache_key("default"),
            "different credentials should produce different cache keys"
        );
    }

    #[test]
    fn cache_key_no_collision_between_literal_and_secret_username() {
        // A literal username containing "secret=" should not collide with a
        // real secret reference in the cache key.
        let literal_conn = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("secret=creds\0password".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        };
        let secret_conn = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: None,
                username_secret: Some(SecretKeySelector {
                    name: "creds".into(),
                    key: "password".into(),
                }),
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        };

        assert_ne!(
            literal_conn.cache_key("default"),
            secret_conn.cache_key("default"),
            "literal and secret ref should produce different cache keys"
        );
    }

    #[test]
    fn cache_key_includes_ssl_mode() {
        let conn_no_ssl = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        };
        let conn_with_ssl = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: Some("require".into()),
                ssl_mode_secret: None,
            }),
        };

        assert_ne!(
            conn_no_ssl.cache_key("ns"),
            conn_with_ssl.cache_key("ns"),
            "cache key should differ when sslMode is present"
        );
    }

    #[test]
    fn validate_connection_rejects_empty_literal_host() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        });

        let err = spec.validate_connection_spec().unwrap_err();
        assert!(
            matches!(err, ConnectionValidationError::EmptyLiteral { ref field } if field == "host"),
            "expected EmptyLiteral for host, got: {err}"
        );
    }

    #[test]
    fn validate_connection_rejects_whitespace_literal_dbname() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("  ".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        });

        let err = spec.validate_connection_spec().unwrap_err();
        assert!(
            matches!(err, ConnectionValidationError::EmptyLiteral { ref field } if field == "dbname"),
            "expected EmptyLiteral for dbname, got: {err}"
        );
    }

    /// Helper to build a minimal spec with the given connection and no roles/grants.
    fn spec_with_connection(connection: ConnectionSpec) -> PostgresPolicySpec {
        PostgresPolicySpec {
            connection,
            interval: "5m".into(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: Default::default(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        }
    }

    fn url_mode_connection() -> ConnectionSpec {
        ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "pg-creds".into(),
            }),
            secret_key: Some("DATABASE_URL".into()),
            params: None,
        }
    }

    fn params_mode_connection() -> ConnectionSpec {
        ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-postgres".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: None,
                username_secret: Some(SecretKeySelector {
                    name: "pg-creds".into(),
                    key: "username".into(),
                }),
                password: None,
                password_secret: Some(SecretKeySelector {
                    name: "pg-creds".into(),
                    key: "password".into(),
                }),
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        }
    }

    // -- Connection validation tests -----------------------------------------

    #[test]
    fn validate_connection_accepts_url_mode() {
        let spec = spec_with_connection(url_mode_connection());
        assert!(spec.validate_connection_spec().is_ok());
    }

    #[test]
    fn validate_connection_accepts_params_mode() {
        let spec = spec_with_connection(params_mode_connection());
        assert!(spec.validate_connection_spec().is_ok());
    }

    #[test]
    fn validate_connection_rejects_both_modes_set() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "pg-creds".into(),
            }),
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        });
        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::BothModesSet)
        ));
    }

    #[test]
    fn validate_connection_rejects_neither_mode_set() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: None,
        });
        assert!(spec.validate_connection_spec().is_err());
    }

    #[test]
    fn validate_connection_rejects_invalid_ssl_mode() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: Some("invalid-mode".into()),
                ssl_mode_secret: None,
            }),
        });
        assert!(spec.validate_connection_spec().is_err());
    }

    #[test]
    fn validate_connection_accepts_valid_ssl_modes() {
        for mode in &[
            "disable",
            "allow",
            "prefer",
            "require",
            "verify-ca",
            "verify-full",
        ] {
            let spec = spec_with_connection(ConnectionSpec {
                secret_ref: None,
                secret_key: None,
                params: Some(ConnectionParams {
                    host: Some("host".into()),
                    host_secret: None,
                    port: None,
                    port_secret: None,
                    dbname: Some("db".into()),
                    dbname_secret: None,
                    username: Some("user".into()),
                    username_secret: None,
                    password: Some("pass".into()),
                    password_secret: None,
                    ssl_mode: Some((*mode).into()),
                    ssl_mode_secret: None,
                }),
            });
            assert!(
                spec.validate_connection_spec().is_ok(),
                "sslMode '{mode}' should be accepted"
            );
        }
    }

    #[test]
    fn validate_connection_rejects_empty_secret_name() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: None,
                username_secret: Some(SecretKeySelector {
                    name: "".into(),
                    key: "username".into(),
                }),
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        });
        assert!(spec.validate_connection_spec().is_err());
    }

    #[test]
    fn validate_connection_rejects_both_literal_and_secret_for_same_field() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: Some(SecretKeySelector {
                    name: "s".into(),
                    key: "k".into(),
                }),
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        });
        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::BothFieldsSet { ref field }) if field == "host"
        ));
    }

    #[test]
    fn validate_connection_rejects_neither_literal_nor_secret_for_required_field() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: None,
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                ssl_mode: None,
                ssl_mode_secret: None,
            }),
        });
        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::NeitherFieldSet { ref field }) if field == "host"
        ));
    }

    // -- ConnectionSpec backward compatibility --------------------------------

    #[test]
    fn connection_spec_backward_compat_url_mode() {
        // The old format with required secretRef should still deserialize.
        let yaml = r#"
secretRef:
  name: pg-creds
secretKey: DATABASE_URL
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(conn.secret_ref.is_some());
        assert_eq!(conn.effective_secret_key(), "DATABASE_URL");
        assert!(conn.params.is_none());
    }

    #[test]
    fn connection_spec_backward_compat_default_secret_key() {
        let yaml = r#"
secretRef:
  name: pg-creds
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conn.effective_secret_key(), "DATABASE_URL");
    }

    #[test]
    fn connection_spec_params_mode_deserializes_keycloak_style() {
        let yaml = r#"
params:
  host: my-postgres
  port: 5432
  dbname: mydb
  usernameSecret:
    name: creds
    key: username
  passwordSecret:
    name: creds
    key: password
  sslMode: require
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(conn.secret_ref.is_none());
        let params = conn.params.unwrap();
        assert_eq!(params.host.as_deref(), Some("my-postgres"));
        assert_eq!(params.port, Some(5432));
        assert!(params.username_secret.is_some());
        assert_eq!(params.username_secret.as_ref().unwrap().name, "creds");
        assert_eq!(params.ssl_mode.as_deref(), Some("require"));
    }

    #[test]
    fn connection_spec_params_mode_all_secrets() {
        // CNPG/PGO pattern — everything from one secret.
        let yaml = r#"
params:
  hostSecret:
    name: cluster-app
    key: host
  portSecret:
    name: cluster-app
    key: port
  dbnameSecret:
    name: cluster-app
    key: dbname
  usernameSecret:
    name: cluster-app
    key: user
  passwordSecret:
    name: cluster-app
    key: password
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        let params = conn.params.unwrap();
        assert!(params.host.is_none());
        assert!(params.host_secret.is_some());
        assert_eq!(params.host_secret.as_ref().unwrap().name, "cluster-app");
        assert!(params.port.is_none());
        assert!(params.port_secret.is_some());
    }

    // -- referenced_secret_names with params mode ----------------------------

    #[test]
    fn referenced_secret_names_includes_params_secrets() {
        let spec = spec_with_connection(params_mode_connection());
        let names = spec.referenced_secret_names("test-policy");
        assert!(
            names.contains("pg-creds"),
            "should include the credential secret from params"
        );
    }

    #[test]
    fn referenced_secret_names_deduplicates_across_modes() {
        // Same secret name used in both connection and password secretRef.
        let mut spec = spec_with_connection(params_mode_connection());
        spec.roles = vec![RoleSpec {
            name: "app".into(),
            login: Some(true),
            password: Some(PasswordSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-creds".into(),
                }),
                secret_key: Some("app-password".into()),
                generate: None,
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
        let names = spec.referenced_secret_names("test-policy");
        // pg-creds appears in both connection params and password — should be deduped.
        assert_eq!(
            names.iter().filter(|n| *n == "pg-creds").count(),
            1,
            "BTreeSet should deduplicate"
        );
    }

    // -- ConnectionParams port default ---------------------------------------

    #[test]
    fn connection_params_port_defaults_to_none() {
        let yaml = r#"
params:
  host: my-host
  dbname: mydb
  username: user
  password: pass
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        let params = conn.params.unwrap();
        assert!(
            params.port.is_none(),
            "port should default to None (resolved as 5432 at runtime)"
        );
        assert!(
            params.port_secret.is_none(),
            "portSecret should also default to None"
        );
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
    fn ready_condition_true_has_expected_shape() {
        let cond = ready_condition(true, "Reconciled", "All changes applied");
        assert_eq!(cond.condition_type, "Ready");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("Reconciled"));
        assert_eq!(cond.message.as_deref(), Some("All changes applied"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn ready_condition_false_has_expected_shape() {
        let cond = ready_condition(false, "InvalidSpec", "bad manifest");
        assert_eq!(cond.condition_type, "Ready");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason.as_deref(), Some("InvalidSpec"));
        assert_eq!(cond.message.as_deref(), Some("bad manifest"));
    }

    #[test]
    fn degraded_condition_has_expected_shape() {
        let cond = degraded_condition("InvalidSpec", "expansion failed");
        assert_eq!(cond.condition_type, "Degraded");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("InvalidSpec"));
        assert_eq!(cond.message.as_deref(), Some("expansion failed"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn reconciling_condition_has_expected_shape() {
        let cond = reconciling_condition("Reconciliation in progress");
        assert_eq!(cond.condition_type, "Reconciling");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("Reconciling"));
        assert_eq!(cond.message.as_deref(), Some("Reconciliation in progress"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn conflict_condition_has_expected_shape() {
        let cond = conflict_condition("ConflictingPolicy", "overlaps with ns/other");
        assert_eq!(cond.condition_type, "Conflict");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("ConflictingPolicy"));
        assert_eq!(cond.message.as_deref(), Some("overlaps with ns/other"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn ownership_claims_no_overlap() {
        let mut left = OwnershipClaims::default();
        left.roles.insert("analytics".to_string());
        left.schemas.insert("reporting".to_string());

        let mut right = OwnershipClaims::default();
        right.roles.insert("billing".to_string());
        right.schemas.insert("payments".to_string());

        assert!(!left.overlaps(&right));
        let summary = left.overlap_summary(&right);
        assert!(summary.is_empty());
    }

    #[test]
    fn ownership_claims_partial_role_overlap() {
        let mut left = OwnershipClaims::default();
        left.roles.insert("analytics".to_string());
        left.roles.insert("reporting-viewer".to_string());

        let mut right = OwnershipClaims::default();
        right.roles.insert("analytics".to_string());
        right.roles.insert("other-role".to_string());

        assert!(left.overlaps(&right));
        let summary = left.overlap_summary(&right);
        assert!(summary.contains("roles: analytics"));
        assert!(!summary.contains("schemas"));
    }

    #[test]
    fn ownership_claims_empty_is_disjoint() {
        let left = OwnershipClaims::default();
        let right = OwnershipClaims::default();
        assert!(!left.overlaps(&right));
    }

    #[test]
    fn database_identity_equality() {
        let conn_a = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("DATABASE_URL".to_string()),
            params: None,
        };
        let a = DatabaseIdentity::from_connection("prod", &conn_a);
        let b = DatabaseIdentity::from_connection("prod", &conn_a);
        let c = DatabaseIdentity::from_connection("staging", &conn_a);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn database_identity_different_key() {
        let conn_a = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("DATABASE_URL".to_string()),
            params: None,
        };
        let conn_b = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("CUSTOM_URL".to_string()),
            params: None,
        };
        let a = DatabaseIdentity::from_connection("prod", &conn_a);
        let b = DatabaseIdentity::from_connection("prod", &conn_b);
        assert_ne!(a, b);
    }

    #[test]
    fn status_default_has_empty_conditions() {
        let status = PostgresPolicyStatus::default();
        assert!(status.conditions.is_empty());
        assert!(status.observed_generation.is_none());
        assert!(status.last_attempted_generation.is_none());
        assert!(status.last_successful_reconcile_time.is_none());
        assert!(status.change_summary.is_none());
        assert!(status.managed_database_identity.is_none());
        assert!(status.owned_roles.is_empty());
        assert!(status.owned_schemas.is_empty());
        assert!(status.last_error.is_none());
        assert!(status.applied_password_source_versions.is_empty());
    }

    #[test]
    fn status_degraded_workflow_sets_ready_false_and_degraded_true() {
        let mut status = PostgresPolicyStatus::default();

        // Simulate a failed reconciliation: Ready=False + Degraded=True
        status.set_condition(ready_condition(false, "InvalidSpec", "bad manifest"));
        status.set_condition(degraded_condition("InvalidSpec", "bad manifest"));
        status
            .conditions
            .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Paused");
        status.change_summary = None;
        status.last_error = Some("bad manifest".to_string());

        // Verify Ready=False
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("InvalidSpec"));

        // Verify Degraded=True
        let degraded = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Degraded")
            .expect("should have Degraded condition");
        assert_eq!(degraded.status, "True");
        assert_eq!(degraded.reason.as_deref(), Some("InvalidSpec"));

        // Verify last_error is set
        assert_eq!(status.last_error.as_deref(), Some("bad manifest"));
    }

    #[test]
    fn status_conflict_workflow() {
        let mut status = PostgresPolicyStatus::default();

        // Simulate a conflict
        let msg = "policy ownership overlaps with staging/other on database target prod/db/URL";
        status.set_condition(ready_condition(false, "ConflictingPolicy", msg));
        status.set_condition(conflict_condition("ConflictingPolicy", msg));
        status.set_condition(degraded_condition("ConflictingPolicy", msg));
        status
            .conditions
            .retain(|c| c.condition_type != "Reconciling");
        status.last_error = Some(msg.to_string());

        // Verify Conflict=True
        let conflict = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Conflict")
            .expect("should have Conflict condition");
        assert_eq!(conflict.status, "True");
        assert_eq!(conflict.reason.as_deref(), Some("ConflictingPolicy"));

        // Verify Ready=False
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "False");

        // Verify Degraded=True
        let degraded = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Degraded")
            .expect("should have Degraded condition");
        assert_eq!(degraded.status, "True");
    }

    #[test]
    fn status_successful_reconcile_records_generation_and_time() {
        let mut status = PostgresPolicyStatus::default();
        let generation = Some(3_i64);
        let summary = ChangeSummary {
            roles_created: 2,
            total: 2,
            ..Default::default()
        };

        // Simulate a successful reconciliation
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
        status.conditions.retain(|c| {
            c.condition_type != "Reconciling"
                && c.condition_type != "Degraded"
                && c.condition_type != "Conflict"
                && c.condition_type != "Paused"
        });
        status.observed_generation = generation;
        status.last_attempted_generation = generation;
        status.last_successful_reconcile_time = Some(now_rfc3339());
        status.last_reconcile_time = Some(now_rfc3339());
        status.change_summary = Some(summary);
        status.last_error = None;

        // Verify Ready=True
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "True");
        assert_eq!(ready.reason.as_deref(), Some("Reconciled"));

        // Verify generation recorded
        assert_eq!(status.observed_generation, Some(3));
        assert_eq!(status.last_attempted_generation, Some(3));

        // Verify timestamps set
        assert!(status.last_successful_reconcile_time.is_some());
        assert!(status.last_reconcile_time.is_some());

        // Verify summary
        let summary = status.change_summary.as_ref().unwrap();
        assert_eq!(summary.roles_created, 2);
        assert_eq!(summary.total, 2);

        // Verify no error
        assert!(status.last_error.is_none());

        // Verify no Degraded/Conflict/Paused/Reconciling conditions
        assert!(
            status
                .conditions
                .iter()
                .all(|c| c.condition_type != "Degraded"
                    && c.condition_type != "Conflict"
                    && c.condition_type != "Paused"
                    && c.condition_type != "Reconciling")
        );
    }

    #[test]
    fn status_suspended_workflow() {
        let mut status = PostgresPolicyStatus::default();
        let generation = Some(2_i64);

        // Simulate a suspended reconciliation
        status.set_condition(paused_condition("Reconciliation suspended by spec"));
        status.set_condition(ready_condition(
            false,
            "Suspended",
            "Reconciliation suspended by spec",
        ));
        status
            .conditions
            .retain(|c| c.condition_type != "Reconciling");
        status.last_attempted_generation = generation;
        status.last_error = None;

        // Verify Paused=True
        let paused = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Paused")
            .expect("should have Paused condition");
        assert_eq!(paused.status, "True");

        // Verify Ready=False with Suspended reason
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("Suspended"));

        // Verify no Reconciling condition
        assert!(
            !status
                .conditions
                .iter()
                .any(|c| c.condition_type == "Reconciling")
        );
    }

    #[test]
    fn status_transitions_from_degraded_to_ready() {
        let mut status = PostgresPolicyStatus::default();

        // First, set degraded state
        status.set_condition(ready_condition(false, "InvalidSpec", "error"));
        status.set_condition(degraded_condition("InvalidSpec", "error"));
        status.last_error = Some("error".to_string());

        assert_eq!(status.conditions.len(), 2);

        // Then, resolve to ready
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
        status.conditions.retain(|c| {
            c.condition_type != "Reconciling"
                && c.condition_type != "Degraded"
                && c.condition_type != "Conflict"
                && c.condition_type != "Paused"
        });
        status.last_error = None;

        // Verify Ready=True
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "True");

        // Verify Degraded removed
        assert!(
            !status
                .conditions
                .iter()
                .any(|c| c.condition_type == "Degraded")
        );

        // Verify only Ready condition remains
        assert_eq!(status.conditions.len(), 1);

        // Verify error cleared
        assert!(status.last_error.is_none());
    }

    #[test]
    fn change_summary_default_is_all_zero() {
        let summary = ChangeSummary::default();
        assert_eq!(summary.roles_created, 0);
        assert_eq!(summary.roles_altered, 0);
        assert_eq!(summary.roles_dropped, 0);
        assert_eq!(summary.sessions_terminated, 0);
        assert_eq!(summary.grants_added, 0);
        assert_eq!(summary.grants_revoked, 0);
        assert_eq!(summary.default_privileges_set, 0);
        assert_eq!(summary.default_privileges_revoked, 0);
        assert_eq!(summary.members_added, 0);
        assert_eq!(summary.members_removed, 0);
        assert_eq!(summary.total, 0);
    }

    #[test]
    fn status_serializes_to_json() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(true, "Reconciled", "done"));
        status.observed_generation = Some(5);
        status.managed_database_identity = Some("ns/secret/key".to_string());
        status.owned_roles = vec!["role-a".to_string(), "role-b".to_string()];
        status.owned_schemas = vec!["public".to_string()];
        status.change_summary = Some(ChangeSummary {
            roles_created: 1,
            total: 1,
            ..Default::default()
        });

        let json = serde_json::to_string(&status).expect("should serialize");
        assert!(json.contains("\"Reconciled\""));
        assert!(json.contains("\"observed_generation\":5"));
        assert!(json.contains("\"role-a\""));
        assert!(json.contains("\"ns/secret/key\""));
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
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
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
    object: { type: database, name: mydb }
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

    #[test]
    fn referenced_secret_names_includes_connection_secret() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        let names = spec.referenced_secret_names("test-policy");
        assert!(names.contains("pg-conn"));
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn referenced_secret_names_includes_password_secrets() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![
                RoleSpec {
                    name: "role-a".to_string(),
                    login: Some(true),
                    password: Some(PasswordSpec {
                        secret_ref: Some(SecretReference {
                            name: "role-passwords".to_string(),
                        }),
                        secret_key: Some("role-a".to_string()),
                        generate: None,
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
                },
                RoleSpec {
                    name: "role-b".to_string(),
                    login: Some(true),
                    password: Some(PasswordSpec {
                        secret_ref: Some(SecretReference {
                            name: "other-secret".to_string(),
                        }),
                        secret_key: None,
                        generate: None,
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
                },
                RoleSpec {
                    name: "role-c".to_string(),
                    login: None,
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
                },
            ],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        let names = spec.referenced_secret_names("test-policy");
        assert!(
            names.contains("pg-conn"),
            "should include connection secret"
        );
        assert!(
            names.contains("role-passwords"),
            "should include role-a password secret"
        );
        assert!(
            names.contains("other-secret"),
            "should include role-b password secret"
        );
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn validate_password_specs_rejects_password_without_login() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                login: Some(false),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: Some(PasswordSpec {
                    secret_ref: Some(SecretReference {
                        name: "role-passwords".to_string(),
                    }),
                    secret_key: None,
                    generate: None,
                }),
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::PasswordWithoutLogin { ref role }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_password_with_login_omitted() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                login: None, // omitted, not explicitly false
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: Some(PasswordSpec {
                    secret_ref: Some(SecretReference {
                        name: "role-passwords".to_string(),
                    }),
                    secret_key: None,
                    generate: None,
                }),
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::PasswordWithoutLogin { ref role }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_password_mode() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: Some(PasswordSpec {
                    secret_ref: Some(SecretReference {
                        name: "role-passwords".to_string(),
                    }),
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: None,
                        secret_key: None,
                    }),
                }),
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidPasswordMode { ref role }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_generated_length() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: Some(PasswordSpec {
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(8),
                        secret_name: None,
                        secret_key: None,
                    }),
                }),
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidGeneratedLength { ref role, .. }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_generated_secret_key() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: Some(PasswordSpec {
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: None,
                        secret_key: Some("bad/key".to_string()),
                    }),
                }),
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidSecretKey { ref role, field, .. })
                if role == "app-user" && field == "generate.secretKey"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_generated_secret_name() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: Some(PasswordSpec {
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: Some("Bad_Name".to_string()),
                        secret_key: None,
                    }),
                }),
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidGeneratedSecretName { ref role, .. }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_reserved_generated_secret_key() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: Some(PasswordSpec {
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: None,
                        secret_key: Some("verifier".to_string()),
                    }),
                }),
                password_valid_until: None,
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::ReservedGeneratedSecretKey { ref role, ref key })
                if role == "app-user" && key == "verifier"
        ));
    }

    #[test]
    fn plan_crd_generates_valid_schema() {
        let crd = PostgresPolicyPlan::crd();
        let yaml = serde_yaml::to_string(&crd).expect("CRD should serialize to YAML");
        assert!(yaml.contains("pgroles.io"), "group should be pgroles.io");
        assert!(yaml.contains("v1alpha1"), "version should be v1alpha1");
        assert!(
            yaml.contains("PostgresPolicyPlan"),
            "kind should be PostgresPolicyPlan"
        );
        assert!(yaml.contains("pgplan"), "should have shortname pgplan");
    }

    #[test]
    fn plan_phase_display() {
        assert_eq!(PlanPhase::Pending.to_string(), "Pending");
        assert_eq!(PlanPhase::Approved.to_string(), "Approved");
        assert_eq!(PlanPhase::Applying.to_string(), "Applying");
        assert_eq!(PlanPhase::Applied.to_string(), "Applied");
        assert_eq!(PlanPhase::Failed.to_string(), "Failed");
        assert_eq!(PlanPhase::Superseded.to_string(), "Superseded");
    }

    #[test]
    fn plan_phase_default_is_pending() {
        assert_eq!(PlanPhase::default(), PlanPhase::Pending);
    }

    #[test]
    fn effective_approval_infers_from_mode() {
        let base = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "test".into(),
                }),
                secret_key: Some("DATABASE_URL".into()),
                params: None,
            },
            interval: "5m".into(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::Authoritative,
            default_owner: None,
            profiles: Default::default(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        // apply mode with no explicit approval → Auto
        assert_eq!(base.effective_approval(), ApprovalMode::Auto);

        // plan mode with no explicit approval → Manual
        let plan = PostgresPolicySpec {
            mode: PolicyMode::Plan,
            ..base.clone()
        };
        assert_eq!(plan.effective_approval(), ApprovalMode::Manual);

        // explicit Manual overrides apply mode
        let explicit = PostgresPolicySpec {
            approval: Some(ApprovalMode::Manual),
            ..base.clone()
        };
        assert_eq!(explicit.effective_approval(), ApprovalMode::Manual);
    }

    #[test]
    fn approval_mode_serde_roundtrip() {
        // Deserialize
        let manual: ApprovalMode = serde_json::from_str("\"manual\"").unwrap();
        assert_eq!(manual, ApprovalMode::Manual);
        let auto: ApprovalMode = serde_json::from_str("\"auto\"").unwrap();
        assert_eq!(auto, ApprovalMode::Auto);

        // Serialize back
        let manual_json = serde_json::to_value(&ApprovalMode::Manual).unwrap();
        assert_eq!(manual_json, serde_json::Value::String("manual".to_string()));
        let auto_json = serde_json::to_value(&ApprovalMode::Auto).unwrap();
        assert_eq!(auto_json, serde_json::Value::String("auto".to_string()));
    }

    #[test]
    fn plan_status_default_is_empty() {
        let status = PostgresPolicyPlanStatus::default();
        assert_eq!(status.phase, PlanPhase::Pending);
        assert!(status.conditions.is_empty());
        assert!(status.change_summary.is_none());
        assert!(status.sql_ref.is_none());
        assert!(status.sql_inline.is_none());
        assert!(status.computed_at.is_none());
        assert!(status.applied_at.is_none());
        assert!(status.last_error.is_none());
    }

    #[test]
    fn spec_without_approval_field_deserializes_as_none() {
        let json = serde_json::json!({
            "connection": {
                "secretRef": { "name": "pg-secret" },
                "secretKey": "DATABASE_URL"
            },
            "interval": "5m",
            "suspend": false,
            "mode": "apply",
            "reconciliation_mode": "authoritative"
        });

        let spec: PostgresPolicySpec =
            serde_json::from_value(json).expect("should deserialize without approval field");
        assert!(
            spec.approval.is_none(),
            "approval should be None when omitted"
        );
        assert_eq!(
            spec.effective_approval(),
            ApprovalMode::Auto,
            "effective_approval should infer Auto from apply mode"
        );
    }

    #[test]
    fn status_without_current_plan_ref_deserializes_as_none() {
        let json = serde_json::json!({
            "conditions": [],
            "owned_roles": [],
            "owned_schemas": []
        });

        let status: PostgresPolicyStatus =
            serde_json::from_value(json).expect("should deserialize without current_plan_ref");
        assert!(
            status.current_plan_ref.is_none(),
            "current_plan_ref should be None when omitted"
        );
    }

    #[test]
    fn effective_approval_explicit_auto_overrides_plan_mode() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "test".into(),
                }),
                secret_key: Some("DATABASE_URL".into()),
                params: None,
            },
            interval: "5m".into(),
            suspend: false,
            mode: PolicyMode::Plan,
            reconciliation_mode: CrdReconciliationMode::Authoritative,
            default_owner: None,
            profiles: Default::default(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: Some(ApprovalMode::Auto),
        };

        assert_eq!(
            spec.effective_approval(),
            ApprovalMode::Auto,
            "explicit Auto should override Plan mode's default of Manual"
        );
    }

    #[test]
    fn plan_phase_rejected_display() {
        assert_eq!(PlanPhase::Rejected.to_string(), "Rejected");
    }

    #[test]
    fn plan_phase_all_variants_display() {
        let variants = [
            PlanPhase::Pending,
            PlanPhase::Approved,
            PlanPhase::Applying,
            PlanPhase::Applied,
            PlanPhase::Failed,
            PlanPhase::Superseded,
            PlanPhase::Rejected,
        ];
        for variant in &variants {
            let display = variant.to_string();
            assert!(
                !display.is_empty(),
                "PlanPhase::{variant:?} should have non-empty Display output"
            );
        }
    }

    #[test]
    fn plan_status_defaults() {
        let status = PostgresPolicyPlanStatus::default();
        assert_eq!(status.phase, PlanPhase::Pending);
        assert!(status.conditions.is_empty());
        assert!(status.sql_ref.is_none());
        assert!(status.sql_hash.is_none());
        assert!(status.sql_inline.is_none());
        assert!(status.change_summary.is_none());
        assert!(status.computed_at.is_none());
        assert!(status.applied_at.is_none());
        assert!(status.last_error.is_none());
    }

    #[test]
    fn plan_spec_camel_case_serialization() {
        let spec = PostgresPolicyPlanSpec {
            policy_ref: PolicyPlanRef {
                name: "my-policy".into(),
            },
            policy_generation: 3,
            reconciliation_mode: CrdReconciliationMode::Authoritative,
            owned_roles: vec!["role-a".into()],
            owned_schemas: vec!["public".into()],
            managed_database_identity: "ns/secret/key".into(),
        };

        let json = serde_json::to_value(&spec).expect("should serialize to JSON");
        let obj = json.as_object().expect("should be a JSON object");

        assert!(
            obj.contains_key("policyRef"),
            "should use camelCase: policyRef"
        );
        assert!(
            obj.contains_key("policyGeneration"),
            "should use camelCase: policyGeneration"
        );
        assert!(
            obj.contains_key("reconciliationMode"),
            "should use camelCase: reconciliationMode"
        );
        assert!(
            obj.contains_key("ownedRoles"),
            "should use camelCase: ownedRoles"
        );
        assert!(
            obj.contains_key("ownedSchemas"),
            "should use camelCase: ownedSchemas"
        );
        assert!(
            obj.contains_key("managedDatabaseIdentity"),
            "should use camelCase: managedDatabaseIdentity"
        );
    }
}
