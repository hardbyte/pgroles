//! Reconciliation logic for `PostgresPolicy` custom resources.
//!
//! Implements the core reconcile loop: read desired state from the CR,
//! inspect current state from the database, compute diff, and apply changes.
//!
//! Reconciliation is serialized per database target to prevent overlapping
//! inspect/diff/apply cycles:
//!
//! 1. **In-process lock** — [`OperatorContext::try_lock_database`] prevents
//!    concurrent reconciles within the same operator replica.
//! 2. **PostgreSQL advisory lock** — [`crate::advisory::try_acquire`] prevents
//!    concurrent operations across multiple operator replicas.

use std::sync::Arc;
use std::time::Duration;

use crate::events::{PlanEventType, publish_plan_event, publish_status_events};
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event as FinalizerEvent};
use tracing::info;

use crate::context::{ContextError, OperatorContext};
use crate::crd::{
    ChangeSummary, DatabaseIdentity, PolicyMode, PostgresPolicy, PostgresPolicyPlan,
    PostgresPolicyStatus, conflict_condition, degraded_condition, drifted_condition,
    paused_condition, ready_condition, reconciling_condition,
};

/// Finalizer name for PostgresPolicy resources.
const FINALIZER: &str = "pgroles.io/finalizer";

/// Default requeue interval when no interval is specified on the CR.
const DEFAULT_REQUEUE_SECS: u64 = 300; // 5 minutes

/// Base requeue delay when lock contention is detected.
const LOCK_CONTENTION_BASE_SECS: u64 = 10;

/// Maximum jitter added to the base requeue delay on lock contention.
const LOCK_CONTENTION_JITTER_SECS: u64 = 20;

/// Base requeue delay when transient operational failures occur.
const TRANSIENT_BACKOFF_BASE_SECS: u64 = 5;

/// Maximum requeue delay for transient operational failures.
const TRANSIENT_BACKOFF_MAX_SECS: u64 = 300;

/// SQLSTATE returned by PostgreSQL for insufficient privileges.
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";
const SQLSTATE_INVALID_SCHEMA_NAME: &str = "3F000";
const SQLSTATE_UNDEFINED_TABLE: &str = "42P01";
const SQLSTATE_UNDEFINED_FUNCTION: &str = "42883";
const SQLSTATE_UNDEFINED_OBJECT: &str = "42704";

/// Maximum amount of rendered planned SQL stored in status.
const MAX_PLANNED_SQL_STATUS_BYTES: usize = 16 * 1024;

enum ReconcileOutcome {
    Reconciled,
    Planned,
    Suspended,
    Conflict,
    LockContention,
}

impl ReconcileOutcome {
    fn result(&self) -> &'static str {
        match self {
            ReconcileOutcome::Reconciled => "success",
            ReconcileOutcome::Planned => "planned",
            ReconcileOutcome::Suspended => "suspended",
            ReconcileOutcome::Conflict => "conflict",
            ReconcileOutcome::LockContention => "contention",
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            ReconcileOutcome::Reconciled => "Reconciled",
            ReconcileOutcome::Planned => "Planned",
            ReconcileOutcome::Suspended => "Suspended",
            ReconcileOutcome::Conflict => "ConflictingPolicy",
            ReconcileOutcome::LockContention => "LockContention",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryClass {
    Slow,
    LockContention,
    Transient,
}

/// Errors that can occur during reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("context error: {0}")]
    Context(#[from] Box<ContextError>),

    #[error("manifest expansion error: {0}")]
    ManifestExpansion(#[from] pgroles_core::manifest::ManifestError),

    #[error("database inspection error: {0}")]
    Inspect(#[from] pgroles_inspect::InspectError),

    #[error("SQL execution error: {0}")]
    SqlExec(#[from] sqlx::Error),

    #[error("{0}")]
    UnsafeRoleDrops(String),

    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("resource has no namespace")]
    NoNamespace,

    #[error("invalid interval \"{0}\": {1}")]
    InvalidInterval(String, String),

    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    #[error(
        "policy references objects that do not exist in target database: {0}. Either create \
         the missing objects, remove them from the policy, or verify the policy is pointing at \
         the intended database."
    )]
    MissingDatabaseObjects(String),

    #[error("{0}")]
    ConflictingPolicy(String),

    #[error("lock contention on database \"{0}\": {1}")]
    LockContention(String, String),

    #[error("Secret \"{secret}\" key \"{key}\" for role \"{role}\" password is empty")]
    EmptyPasswordSecret {
        role: String,
        secret: String,
        key: String,
    },

    #[error("password generation error: {0}")]
    PasswordGeneration(#[from] Box<crate::password::PasswordError>),

    #[error("plan SQL storage error: {0}")]
    PlanSqlStorage(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPassword {
    cleartext: String,
    source_version: String,
}

/// Parse a duration string like "5m", "1h", "30s", "2h30m".
fn parse_interval(interval: &str) -> Result<Duration, ReconcileError> {
    let interval = interval.trim();
    if interval.is_empty() {
        return Ok(Duration::from_secs(DEFAULT_REQUEUE_SECS));
    }

    let mut total_secs: u64 = 0;
    let mut current_num = String::new();

    for ch in interval.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let num: u64 = current_num.parse().map_err(|_| {
                ReconcileError::InvalidInterval(
                    interval.to_string(),
                    format!("invalid number before '{ch}'"),
                )
            })?;
            current_num.clear();

            match ch {
                'h' => total_secs += num * 3600,
                'm' => total_secs += num * 60,
                's' => total_secs += num,
                _ => {
                    return Err(ReconcileError::InvalidInterval(
                        interval.to_string(),
                        format!("unknown unit '{ch}'"),
                    ));
                }
            }
        }
    }

    // If there's a trailing number with no unit, treat as seconds.
    if !current_num.is_empty() {
        let num: u64 = current_num.parse().map_err(|_| {
            ReconcileError::InvalidInterval(interval.to_string(), "trailing number".to_string())
        })?;
        total_secs += num;
    }

    if total_secs == 0 {
        return Ok(Duration::from_secs(DEFAULT_REQUEUE_SECS));
    }

    Ok(Duration::from_secs(total_secs))
}

/// Top-level reconcile entry point called by the kube-rs controller runtime.
///
/// Uses the finalizer pattern for cleanup on deletion.
pub async fn reconcile(
    resource: Arc<PostgresPolicy>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, finalizer::Error<ReconcileError>> {
    let api: Api<PostgresPolicy> = Api::namespaced(
        ctx.kube_client.clone(),
        resource.namespace().as_deref().unwrap_or("default"),
    );

    finalizer::finalizer(&api, FINALIZER, resource, |event| async {
        match event {
            FinalizerEvent::Apply(resource) => reconcile_apply(&resource, &ctx).await,
            FinalizerEvent::Cleanup(resource) => reconcile_cleanup(&resource, &ctx).await,
        }
    })
    .await
}

/// Error handler — called when reconcile returns an error.
pub fn error_policy(
    resource: Arc<PostgresPolicy>,
    error: &finalizer::Error<ReconcileError>,
    _ctx: Arc<OperatorContext>,
) -> Action {
    retry_action(&resource, error)
}

fn retry_action(resource: &PostgresPolicy, error: &finalizer::Error<ReconcileError>) -> Action {
    match retry_class(error) {
        RetryClass::LockContention => {
            if let finalizer::Error::ApplyFailed(ReconcileError::LockContention(db, reason)) = error
            {
                tracing::info!(database = %db, reason = %reason, "requeuing due to lock contention");
            }
            requeue_with_jitter()
        }
        RetryClass::Slow => {
            let delay = slow_retry_delay(resource);
            tracing::info!(
                delay_secs = delay.as_secs(),
                error = %error,
                "requeuing on normal interval for non-transient failure"
            );
            Action::requeue(delay)
        }
        RetryClass::Transient => {
            let attempts = next_transient_failure_count(resource);
            let delay = transient_backoff_delay(attempts);
            tracing::warn!(
                attempts,
                delay_secs = delay.as_secs(),
                error = %error,
                "requeuing with exponential backoff after transient failure"
            );
            Action::requeue(delay)
        }
    }
}

/// Compute a requeue delay with jitter for lock contention back-off.
fn requeue_with_jitter() -> Action {
    let delay = jitter_delay();
    tracing::debug!(delay_secs = delay.as_secs(), "requeue with jitter");
    Action::requeue(delay)
}

/// Compute a jittered delay for lock contention back-off.
///
/// Returns a [`Duration`] in the range
/// `[LOCK_CONTENTION_BASE_SECS, LOCK_CONTENTION_BASE_SECS + LOCK_CONTENTION_JITTER_SECS]`.
fn jitter_delay() -> Duration {
    // Simple jitter: base + pseudo-random portion of the jitter window.
    // We combine subsecond nanos with a hash of the thread ID for better
    // entropy when multiple reconciles hit contention simultaneously.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let thread_entropy = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        hasher.finish() as u32
    };
    let jitter_secs = ((nanos ^ thread_entropy) as u64) % (LOCK_CONTENTION_JITTER_SECS + 1);
    Duration::from_secs(LOCK_CONTENTION_BASE_SECS + jitter_secs)
}

fn transient_backoff_delay(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(10);
    let base_delay = TRANSIENT_BACKOFF_BASE_SECS
        .saturating_mul(1_u64 << exponent)
        .min(TRANSIENT_BACKOFF_MAX_SECS);
    let remaining_headroom = TRANSIENT_BACKOFF_MAX_SECS.saturating_sub(base_delay);
    let jitter_window = remaining_headroom.min((base_delay / 2).max(1));
    let jitter_secs = if jitter_window == 0 {
        0
    } else {
        pseudo_random_window(jitter_window)
    };
    Duration::from_secs((base_delay + jitter_secs).min(TRANSIENT_BACKOFF_MAX_SECS))
}

fn pseudo_random_window(window_secs: u64) -> u64 {
    if window_secs == 0 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let thread_entropy = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        hasher.finish() as u32
    };
    ((nanos ^ thread_entropy) as u64) % (window_secs + 1)
}

fn retry_class(error: &finalizer::Error<ReconcileError>) -> RetryClass {
    match error {
        finalizer::Error::ApplyFailed(reconcile_error) => {
            retry_class_for_reconcile_error(reconcile_error)
        }
        finalizer::Error::CleanupFailed(_)
        | finalizer::Error::AddFinalizer(_)
        | finalizer::Error::RemoveFinalizer(_)
        | finalizer::Error::UnnamedObject
        | finalizer::Error::InvalidFinalizer => RetryClass::Transient,
    }
}

fn retry_class_for_reconcile_error(error: &ReconcileError) -> RetryClass {
    match error {
        ReconcileError::LockContention(_, _) => RetryClass::LockContention,
        ReconcileError::ManifestExpansion(_)
        | ReconcileError::InvalidInterval(_, _)
        | ReconcileError::InvalidSpec(_)
        | ReconcileError::MissingDatabaseObjects(_)
        | ReconcileError::ConflictingPolicy(_)
        | ReconcileError::UnsafeRoleDrops(_)
        | ReconcileError::EmptyPasswordSecret { .. }
        | ReconcileError::NoNamespace
        | ReconcileError::PlanSqlStorage(_) => RetryClass::Slow,
        ReconcileError::PasswordGeneration(err) => {
            if err.is_transient() {
                RetryClass::Transient
            } else {
                RetryClass::Slow
            }
        }
        ReconcileError::Context(context) => match context.as_ref() {
            ContextError::SecretMissing { .. } => RetryClass::Slow,
            ContextError::SecretFetch { .. } => {
                if context.is_secret_fetch_non_transient() {
                    RetryClass::Slow
                } else {
                    RetryClass::Transient
                }
            }
            ContextError::DatabaseConnect { .. } => RetryClass::Transient,
            ContextError::EmptyResolvedValue { .. }
            | ContextError::InvalidResolvedSslMode { .. } => RetryClass::Slow,
        },
        ReconcileError::Inspect(error) => {
            if inspect_error_is_non_transient(error) {
                RetryClass::Slow
            } else {
                RetryClass::Transient
            }
        }
        ReconcileError::SqlExec(error) => {
            if sqlx_error_is_non_transient(error) {
                RetryClass::Slow
            } else {
                RetryClass::Transient
            }
        }
        ReconcileError::Kube(_) => RetryClass::Transient,
    }
}

fn inspect_error_is_non_transient(error: &pgroles_inspect::InspectError) -> bool {
    match error {
        pgroles_inspect::InspectError::Database(error) => sqlx_error_is_non_transient(error),
    }
}

/// Classification of a database-level SQL error for retry and status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlErrorKind {
    /// Insufficient privileges (SQLSTATE 42501) — RBAC-style failure,
    /// won't fix itself.
    InsufficientPrivileges,
    /// A referenced schema, relation, function, or object does not exist
    /// (SQLSTATE 3F000, 42P01, 42883, 42704). Typically a policy/environment
    /// mismatch that needs operator action.
    MissingDatabaseObject,
    /// Everything else — retry with exponential backoff.
    Transient,
}

fn classify_sqlx_error(error: &sqlx::Error) -> SqlErrorKind {
    match error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .as_deref()
    {
        Some(SQLSTATE_INSUFFICIENT_PRIVILEGE) => SqlErrorKind::InsufficientPrivileges,
        Some(SQLSTATE_INVALID_SCHEMA_NAME)
        | Some(SQLSTATE_UNDEFINED_TABLE)
        | Some(SQLSTATE_UNDEFINED_FUNCTION)
        | Some(SQLSTATE_UNDEFINED_OBJECT) => SqlErrorKind::MissingDatabaseObject,
        _ => SqlErrorKind::Transient,
    }
}

fn sqlx_error_is_non_transient(error: &sqlx::Error) -> bool {
    !matches!(classify_sqlx_error(error), SqlErrorKind::Transient)
}

fn next_transient_failure_count(resource: &PostgresPolicy) -> u32 {
    resource
        .status
        .as_ref()
        .map(|status| status.transient_failure_count.max(0) as u32)
        .unwrap_or(0)
        .saturating_add(1)
}

fn slow_retry_delay(resource: &PostgresPolicy) -> Duration {
    parse_interval(&resource.spec.interval)
        .unwrap_or_else(|_| Duration::from_secs(DEFAULT_REQUEUE_SECS))
}

/// Collect every schema name referenced by an expanded manifest.
///
/// Covers schema-type grants (where the schema is in `object.name`), grants on
/// objects within a schema (where the schema is in `object.schema`), and
/// default privileges (which always carry a schema).
fn referenced_schema_names(
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> std::collections::BTreeSet<String> {
    let mut names: std::collections::BTreeSet<String> = expanded
        .schemas
        .iter()
        .map(|schema| schema.name.clone())
        .collect();
    for grant in &expanded.grants {
        if grant.object.object_type == pgroles_core::manifest::ObjectType::Schema
            && let Some(name) = &grant.object.name
        {
            names.insert(name.clone());
        }
        if let Some(schema) = &grant.object.schema {
            names.insert(schema.clone());
        }
    }
    for dp in &expanded.default_privileges {
        names.insert(dp.schema.clone());
    }
    names
}

fn declared_schema_names(
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> std::collections::BTreeSet<String> {
    expanded
        .schemas
        .iter()
        .map(|schema| schema.name.clone())
        .collect()
}

/// Pre-flight check: ensure every schema referenced by the policy exists in
/// the target database. Returns [`ReconcileError::MissingDatabaseObjects`]
/// listing the missing schemas if any are absent.
/// Returns true for PostgreSQL system schemas that always exist but are
/// excluded from [`pgroles_inspect::fetch_existing_schemas`].
fn is_system_schema(name: &str) -> bool {
    name.starts_with("pg_") || name == "information_schema"
}

/// Pre-flight check: ensure every schema referenced by the policy exists in
/// the target database. Returns [`ReconcileError::MissingDatabaseObjects`]
/// listing the missing schemas if any are absent.
///
/// System schemas (`pg_*`, `information_schema`) are excluded from the check
/// since they always exist but are filtered out of the inspect query.
async fn validate_referenced_schemas_exist(
    pool: &sqlx::PgPool,
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> Result<(), ReconcileError> {
    let referenced = externally_required_schema_names(expanded);
    if referenced.is_empty() {
        return Ok(());
    }
    let existing = pgroles_inspect::fetch_existing_schemas(pool).await?;
    let missing: Vec<String> = referenced
        .into_iter()
        .filter(|name| !existing.contains(name))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        let formatted = missing
            .iter()
            .map(|name| format!("schema \"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        Err(ReconcileError::MissingDatabaseObjects(formatted))
    }
}

fn externally_required_schema_names(
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> std::collections::BTreeSet<String> {
    let declared = declared_schema_names(expanded);
    referenced_schema_names(expanded)
        .into_iter()
        .filter(|name| !is_system_schema(name) && !declared.contains(name))
        .collect()
}

/// Apply reconciliation — the main "ensure desired state" logic.
///
/// Acquires the in-process per-database lock before doing any work. If the
/// lock is already held, the reconciliation is requeued with jitter.
async fn reconcile_apply(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
) -> Result<Action, ReconcileError> {
    let reconcile_guard = ctx.observability.start_reconcile();

    // Derive database identity early so we can acquire the in-process lock.
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;
    let identity = DatabaseIdentity::from_connection(&namespace, &resource.spec.connection);

    // Acquire in-process lock for this database target.
    let _db_lock = match ctx.try_lock_database(identity.as_str()).await {
        Some(guard) => guard,
        None => {
            ctx.observability.record_lock_contention();
            reconcile_guard.record_result(
                ReconcileOutcome::LockContention.result(),
                ReconcileOutcome::LockContention.reason(),
            );
            return Err(ReconcileError::LockContention(
                identity.as_str().to_string(),
                "in-process lock held by another reconcile".to_string(),
            ));
        }
    };

    match reconcile_apply_inner(resource, ctx, &identity).await {
        Ok((action, outcome)) => {
            reconcile_guard.record_result(outcome.result(), outcome.reason());
            Ok(action)
        }
        Err(ReconcileError::LockContention(db, reason)) => {
            // Lock contention is expected during normal multi-replica operation.
            // Re-raise without setting Degraded status to avoid false alarms.
            ctx.observability.record_lock_contention();
            reconcile_guard.record_result(
                ReconcileOutcome::LockContention.result(),
                ReconcileOutcome::LockContention.reason(),
            );
            tracing::info!(database = %db, %reason, "lock contention — will requeue");
            Err(ReconcileError::LockContention(db, reason))
        }
        Err(err) => {
            let error_message = err.to_string();
            let error_reason = err.reason();
            let is_transient_failure =
                retry_class_for_reconcile_error(&err) == RetryClass::Transient;
            match error_reason {
                "DatabaseConnectionFailed" => {
                    ctx.observability.record_database_connection_failure()
                }
                "InvalidSpec" => ctx.observability.record_invalid_spec(),
                "ConflictingPolicy" => ctx.observability.record_policy_conflict(),
                "ApplyFailed" | "MissingDatabaseObject" => {
                    ctx.observability.record_apply_result("error")
                }
                _ => {}
            }
            reconcile_guard.record_result("error", error_reason);
            if let Err(status_err) = update_status(ctx, resource, |status| {
                status.set_condition(ready_condition(false, error_reason, &error_message));
                status.set_condition(degraded_condition(error_reason, &error_message));
                status.conditions.retain(|c| {
                    c.condition_type != "Reconciling"
                        && c.condition_type != "Paused"
                        && c.condition_type != "Drifted"
                });
                status.change_summary = None;
                status.planned_sql = None;
                status.planned_sql_truncated = false;
                status.last_error = Some(error_message.clone());
                if is_transient_failure {
                    status.transient_failure_count += 1;
                } else {
                    status.transient_failure_count = 0;
                }
            })
            .await
            {
                tracing::warn!(%status_err, "failed to update degraded status");
            }
            Err(err)
        }
    }
}

async fn reconcile_apply_inner(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
    identity: &DatabaseIdentity,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = resource.name_any();
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;

    let spec = &resource.spec;
    let requeue_interval = parse_interval(&spec.interval)?;
    let generation = resource.metadata.generation;

    // If suspended, just requeue without doing anything.
    if spec.suspend {
        update_status(ctx, resource, |status| {
            status.set_condition(paused_condition("Reconciliation suspended by spec"));
            status.set_condition(ready_condition(
                false,
                "Suspended",
                "Reconciliation suspended by spec",
            ));
            status
                .conditions
                .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Drifted");
            status.last_attempted_generation = generation;
            status.last_error = None;
            status.planned_sql = None;
            status.planned_sql_truncated = false;
            status.transient_failure_count = 0;
        })
        .await?;
        info!(name, namespace, "reconciliation suspended, requeuing");
        return Ok((
            Action::requeue(requeue_interval),
            ReconcileOutcome::Suspended,
        ));
    }

    info!(name, namespace, "starting reconciliation");

    // Update status to "Reconciling".
    // Note: do NOT clear last_error here — it should persist until a successful
    // reconcile clears it. Clearing on every retry cycle would race with the
    // error handler that sets it.
    update_status(ctx, resource, |status| {
        status.set_condition(reconciling_condition("Reconciliation in progress"));
        status
            .conditions
            .retain(|c| c.condition_type != "Paused" && c.condition_type != "Drifted");
        status.last_attempted_generation = generation;
    })
    .await?;

    spec.validate_connection_spec()
        .map_err(|err| ReconcileError::InvalidSpec(err.to_string()))?;
    spec.validate_password_specs(&name)
        .map_err(|err| ReconcileError::InvalidSpec(err.to_string()))?;

    let ownership = spec.ownership_claims()?;
    update_status(ctx, resource, |status| {
        status.managed_database_identity = Some(identity.as_str().to_string());
        status.owned_roles = ownership.roles.iter().cloned().collect();
        status.owned_schemas = ownership.schemas.iter().cloned().collect();
    })
    .await?;

    if let Some(conflict_message) =
        detect_policy_conflict(ctx, resource, identity, &ownership).await?
    {
        update_status(ctx, resource, |status| {
            status.set_condition(ready_condition(
                false,
                "ConflictingPolicy",
                &conflict_message,
            ));
            status.set_condition(conflict_condition("ConflictingPolicy", &conflict_message));
            status.set_condition(degraded_condition("ConflictingPolicy", &conflict_message));
            status
                .conditions
                .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Drifted");
            status.change_summary = None;
            status.planned_sql = None;
            status.planned_sql_truncated = false;
            status.last_error = Some(conflict_message.clone());
            status.transient_failure_count = 0;
        })
        .await?;
        ctx.observability.record_policy_conflict();
        info!(name, namespace, %conflict_message, "reconciliation blocked by conflicting policy");
        return Ok((
            Action::requeue(requeue_interval),
            ReconcileOutcome::Conflict,
        ));
    }

    // 1. Convert CRD spec to core manifest.
    let manifest = spec.to_policy_manifest();

    // 2. Expand the manifest (profiles × schemas → concrete roles/grants).
    let expanded = pgroles_core::manifest::expand_manifest(&manifest)?;

    // 3. Build desired RoleGraph from expanded manifest.
    let default_owner = manifest.default_owner.as_deref();
    let desired = pgroles_core::model::RoleGraph::from_expanded(&expanded, default_owner)?;

    // 4. Get a database pool.
    let pool = ctx
        .get_or_create_pool(&namespace, &spec.connection)
        .await
        .map_err(Box::new)?;

    // 5. Acquire PostgreSQL advisory lock for cross-replica safety.
    let advisory_lock = match crate::advisory::try_acquire(&pool, identity.as_str()).await {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            return Err(ReconcileError::LockContention(
                identity.as_str().to_string(),
                "PostgreSQL advisory lock held by another session".to_string(),
            ));
        }
        Err(err) => {
            tracing::warn!(%err, "failed to acquire advisory lock — treating as connection error");
            return Err(ReconcileError::SqlExec(err));
        }
    };

    // Wrap the remaining work so the advisory lock is released on all paths.
    let result = apply_under_lock(
        resource,
        ctx,
        &pool,
        &manifest,
        &expanded,
        &desired,
        generation,
        requeue_interval,
        &name,
        &namespace,
        identity,
    )
    .await;

    // Release advisory lock (always, even on error).
    advisory_lock.release().await;

    crate::plan::cleanup_old_plans_best_effort(&ctx.kube_client, resource, None).await;

    result
}

/// Execute the inspect/diff/apply cycle while both locks are held.
///
/// Extracted to keep `reconcile_apply_inner` focused on lock acquisition.
#[allow(clippy::too_many_arguments)]
async fn apply_under_lock(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
    pool: &sqlx::PgPool,
    manifest: &pgroles_core::manifest::PolicyManifest,
    expanded: &pgroles_core::manifest::ExpandedManifest,
    desired: &pgroles_core::model::RoleGraph,
    generation: Option<i64>,
    requeue_interval: Duration,
    name: &str,
    namespace: &str,
    identity: &DatabaseIdentity,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    // 5b. Recover stuck Applying plans (operator may have crashed mid-apply).
    if let Some(stuck_plan) =
        crate::plan::get_plan_by_phase(&ctx.kube_client, resource, crate::crd::PlanPhase::Applying)
            .await?
    {
        let applying_since_secs = stuck_plan
            .status
            .as_ref()
            .and_then(|s| s.applying_since.as_deref())
            .and_then(parse_rfc3339_to_epoch_secs);
        if let Some(since_secs) = applying_since_secs {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let elapsed_secs = now_secs.saturating_sub(since_secs);
            let stuck_threshold_secs = 5 * 60; // 5 minutes
            if elapsed_secs > stuck_threshold_secs {
                tracing::warn!(
                    plan = %stuck_plan.name_any(),
                    elapsed_secs,
                    "detected stuck Applying plan — marking as Failed"
                );
                crate::plan::mark_plan_failed(
                    &ctx.kube_client,
                    &stuck_plan,
                    "execution interrupted: operator restarted during apply",
                )
                .await?;
            }
        }
    }

    // 6. Inspect current state from the database.
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|g| g.object.object_type == pgroles_core::manifest::ObjectType::Database);
    let inspect_config =
        pgroles_inspect::InspectConfig::from_expanded(expanded, has_database_grants)
            .with_additional_roles(
                manifest
                    .retirements
                    .iter()
                    .map(|retirement| retirement.role.clone()),
            );
    let current = pgroles_inspect::inspect(pool, &inspect_config).await?;

    // 6b. Pre-flight: validate that every schema referenced by the policy
    // exists in the target database. This turns a mid-transaction
    // `schema "X" does not exist` failure into a clear spec/environment
    // mismatch error before we issue any DDL.
    validate_referenced_schemas_exist(pool, expanded).await?;

    // 7. Compute diff, filter by reconciliation mode, then inject password
    // changes resolved from Kubernetes Secrets.
    let reconciliation_mode: pgroles_core::diff::ReconciliationMode =
        resource.spec.reconciliation_mode.into();
    tracing::info!(%reconciliation_mode, "reconciliation mode");
    let mut changes = pgroles_core::diff::filter_changes(
        pgroles_core::diff::apply_role_retirements(
            pgroles_core::diff::diff(&current, desired),
            &manifest.retirements,
        ),
        reconciliation_mode,
    );

    let resolved_passwords = resolve_passwords_from_secrets(ctx, resource, namespace).await?;
    let (password_changes, applied_password_source_versions) =
        select_password_changes(&changes, &resolved_passwords, resource.status.as_ref());
    if !password_changes.is_empty() {
        changes = pgroles_core::diff::inject_password_changes(changes, &password_changes);
    }
    let dropped_roles: Vec<String> = changes
        .iter()
        .filter_map(|change| match change {
            pgroles_core::diff::Change::DropRole { name } => Some(name.clone()),
            _ => None,
        })
        .collect();
    let drop_safety = pgroles_inspect::inspect_drop_role_safety(pool, &dropped_roles)
        .await?
        .assess(&manifest.retirements);
    if !drop_safety.warnings.is_empty() {
        tracing::info!(warnings = %drop_safety.warnings, "role-drop cleanup warnings");
    }
    if drop_safety.has_blockers() {
        return Err(ReconcileError::UnsafeRoleDrops(
            drop_safety.blockers.to_string(),
        ));
    }

    let summary = summarize_changes(&changes);
    let sql_ctx = detect_sql_context(pool, &inspect_config).await?;
    let (planned_sql, planned_sql_truncated) = render_plan_sql_for_status(&changes, &sql_ctx);

    let effective_approval = resource.spec.effective_approval();

    if resource.spec.mode == PolicyMode::Plan {
        let drift_detected = !changes.is_empty();
        let ready_message = if drift_detected {
            format!("Plan computed; {} change(s) pending", summary.total)
        } else {
            "Plan computed; database already matches desired state".to_string()
        };
        let drift_reason = if drift_detected {
            "DriftDetected"
        } else {
            "InSync"
        };
        let drift_message = if drift_detected {
            format!("{} planned change(s) pending review", summary.total)
        } else {
            "No pending changes".to_string()
        };

        ctx.observability
            .record_plan_result(if drift_detected { "drift" } else { "clean" });
        ctx.observability
            .record_planned_changes(summary.total.max(0) as usize);

        // Create a PostgresPolicyPlan resource for changes (if any).
        let mut plan_ref_name = None;
        if drift_detected {
            let creation_result = crate::plan::create_or_update_plan(
                &ctx.kube_client,
                resource,
                &changes,
                &sql_ctx,
                &inspect_config,
                resource.spec.reconciliation_mode,
                identity.as_str(),
                &summary,
            )
            .await?;
            let plan_name = creation_result.plan_name().to_string();

            // Only emit PlanCreated event for genuinely new plans, not dedup hits.
            if creation_result.is_created() {
                let plans_api: Api<PostgresPolicyPlan> =
                    Api::namespaced(ctx.kube_client.clone(), namespace);
                let created_plan = plans_api.get(&plan_name).await?;
                emit_plan_event(
                    ctx,
                    resource,
                    &created_plan,
                    PlanEventType::Created {
                        change_count: summary.total,
                    },
                )
                .await;
            }

            crate::plan::update_policy_plan_ref(&ctx.kube_client, resource, &plan_name).await?;

            plan_ref_name = Some(plan_name);
        }

        // Still write deprecated planned_sql to status for backward compat.
        update_status(ctx, resource, |status| {
            status.set_condition(ready_condition(true, "Planned", &ready_message));
            status.set_condition(drifted_condition(
                drift_detected,
                drift_reason,
                &drift_message,
            ));
            status.conditions.retain(|c| {
                c.condition_type != "Reconciling"
                    && c.condition_type != "Degraded"
                    && c.condition_type != "Conflict"
                    && c.condition_type != "Paused"
            });
            status.observed_generation = generation;
            status.last_attempted_generation = generation;
            status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
            status.last_reconcile_time = Some(crate::crd::now_rfc3339());
            status.change_summary = Some(summary.clone());
            status.last_reconcile_mode = Some(PolicyMode::Plan);
            status.planned_sql = planned_sql.clone();
            status.planned_sql_truncated = planned_sql_truncated;
            status.last_error = None;
            status.transient_failure_count = 0;
            if let Some(ref plan_name) = plan_ref_name {
                status.current_plan_ref = Some(crate::crd::PlanReference {
                    name: plan_name.clone(),
                });
            }
        })
        .await?;

        info!(
            name,
            namespace,
            total = summary.total,
            drift_detected,
            "plan reconciliation complete"
        );
        return Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned));
    }

    // Apply mode — behavior depends on effective approval mode.
    match effective_approval {
        crate::crd::ApprovalMode::Auto => {
            // Auto-approval: create plan -> immediately execute -> update status.
            // This wraps the existing apply behavior in the plan lifecycle.
            if !changes.is_empty() {
                let creation_result = crate::plan::create_or_update_plan(
                    &ctx.kube_client,
                    resource,
                    &changes,
                    &sql_ctx,
                    &inspect_config,
                    resource.spec.reconciliation_mode,
                    identity.as_str(),
                    &summary,
                )
                .await?;
                let plan_name = creation_result.plan_name().to_string();

                // Fetch the plan, mark it approved, and execute it.
                let plans_api: Api<PostgresPolicyPlan> =
                    Api::namespaced(ctx.kube_client.clone(), namespace);
                let plan = plans_api.get(&plan_name).await?;

                if creation_result.is_created() {
                    emit_plan_event(
                        ctx,
                        resource,
                        &plan,
                        PlanEventType::Created {
                            change_count: summary.total,
                        },
                    )
                    .await;
                }

                crate::plan::mark_plan_approved(
                    &ctx.kube_client,
                    &plan,
                    "AutoApproved",
                    "Plan auto-approved by policy approval mode",
                )
                .await?;

                // Re-fetch after approval status update.
                let plan = plans_api.get(&plan_name).await?;
                emit_plan_event(ctx, resource, &plan, PlanEventType::Approved).await;
                emit_plan_event(ctx, resource, &plan, PlanEventType::ApplyStarted).await;

                match crate::plan::execute_plan(&ctx.kube_client, &plan, pool, &sql_ctx, &changes)
                    .await
                {
                    Ok(()) => {
                        emit_plan_event(ctx, resource, &plan, PlanEventType::ApplySucceeded).await;
                    }
                    Err(err) => {
                        emit_plan_event(
                            ctx,
                            resource,
                            &plan,
                            PlanEventType::ApplyFailed {
                                error: err.to_string(),
                            },
                        )
                        .await;
                        return Err(err);
                    }
                }

                ctx.observability.record_apply_result("success");

                crate::plan::update_policy_plan_ref(&ctx.kube_client, resource, &plan_name).await?;

                info!(
                    name,
                    namespace,
                    total = summary.total,
                    plan = %plan_name,
                    "auto-approved plan applied"
                );
            } else {
                info!(name, namespace, "no changes needed");
            }

            // Update status to Ready.
            update_status(ctx, resource, |status| {
                status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
                status.set_condition(drifted_condition(false, "InSync", "No pending changes"));
                status.conditions.retain(|c| {
                    c.condition_type != "Reconciling"
                        && c.condition_type != "Degraded"
                        && c.condition_type != "Conflict"
                        && c.condition_type != "Paused"
                });
                status.observed_generation = generation;
                status.last_attempted_generation = generation;
                status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
                status.last_reconcile_time = Some(crate::crd::now_rfc3339());
                status.change_summary = Some(summary);
                status.last_reconcile_mode = Some(PolicyMode::Apply);
                status.planned_sql = None;
                status.planned_sql_truncated = false;
                status.last_error = None;
                status.applied_password_source_versions = applied_password_source_versions;
                status.transient_failure_count = 0;
            })
            .await?;

            Ok((
                Action::requeue(requeue_interval),
                ReconcileOutcome::Reconciled,
            ))
        }
        crate::crd::ApprovalMode::Manual => {
            // Manual approval: check for an existing approved plan, or create one.

            // First, check if there is a current pending plan that has been approved.
            if let Some(current_plan) =
                crate::plan::get_current_actionable_plan(&ctx.kube_client, resource).await?
            {
                let approval_state = crate::plan::check_plan_approval(&current_plan);

                match approval_state {
                    crate::plan::PlanApprovalState::Approved => {
                        // Validate that the database state has not drifted since
                        // the plan was approved by comparing SQL hashes.
                        let fresh_sql = crate::plan::render_full_sql(&changes, &sql_ctx);
                        let fresh_hash = crate::plan::compute_sql_hash(&fresh_sql);
                        let stored_hash = current_plan
                            .status
                            .as_ref()
                            .and_then(|s| s.sql_hash.as_deref());

                        if stored_hash != Some(&fresh_hash) {
                            // Database state changed since the plan was approved.
                            tracing::warn!(
                                plan = %current_plan.name_any(),
                                stored_hash = ?stored_hash,
                                fresh_hash = %fresh_hash,
                                "approved plan superseded: database state changed since approval"
                            );

                            crate::plan::mark_plan_superseded(&ctx.kube_client, &current_plan)
                                .await?;

                            // Create a new plan with the fresh changes.
                            let new_creation_result = crate::plan::create_or_update_plan(
                                &ctx.kube_client,
                                resource,
                                &changes,
                                &sql_ctx,
                                &inspect_config,
                                resource.spec.reconciliation_mode,
                                identity.as_str(),
                                &summary,
                            )
                            .await?;
                            let new_plan_name = new_creation_result.plan_name().to_string();

                            if new_creation_result.is_created() {
                                let plans_api: Api<PostgresPolicyPlan> =
                                    Api::namespaced(ctx.kube_client.clone(), namespace);
                                let new_plan = plans_api.get(&new_plan_name).await?;
                                emit_plan_event(
                                    ctx,
                                    resource,
                                    &new_plan,
                                    PlanEventType::Created {
                                        change_count: summary.total,
                                    },
                                )
                                .await;
                            }

                            crate::plan::update_policy_plan_ref(
                                &ctx.kube_client,
                                resource,
                                &new_plan_name,
                            )
                            .await?;

                            let msg = format!(
                                "Plan {} superseded (DB state changed); new plan {} created with {} change(s) awaiting approval",
                                current_plan.name_any(),
                                new_plan_name,
                                summary.total,
                            );
                            update_status(ctx, resource, |status| {
                                status.set_condition(ready_condition(true, "Planned", &msg));
                                status.set_condition(drifted_condition(
                                    true,
                                    "DriftDetected",
                                    &format!("{} planned change(s) pending review", summary.total),
                                ));
                                status.conditions.retain(|c| {
                                    c.condition_type != "Reconciling"
                                        && c.condition_type != "Degraded"
                                        && c.condition_type != "Conflict"
                                        && c.condition_type != "Paused"
                                });
                                status.last_attempted_generation = generation;
                                status.change_summary = Some(summary.clone());
                                status.last_reconcile_mode = Some(PolicyMode::Apply);
                                status.planned_sql = planned_sql.clone();
                                status.planned_sql_truncated = planned_sql_truncated;
                                status.last_error = None;
                                status.transient_failure_count = 0;
                                status.current_plan_ref = Some(crate::crd::PlanReference {
                                    name: new_plan_name.clone(),
                                });
                            })
                            .await?;

                            return Ok((
                                Action::requeue(requeue_interval),
                                ReconcileOutcome::Planned,
                            ));
                        }

                        // Hash matches — safe to execute the approved plan.
                        info!(
                            name,
                            namespace,
                            plan = %current_plan.name_any(),
                            "executing manually approved plan"
                        );

                        emit_plan_event(ctx, resource, &current_plan, PlanEventType::Approved)
                            .await;

                        crate::plan::mark_plan_approved(
                            &ctx.kube_client,
                            &current_plan,
                            "ManuallyApproved",
                            "Plan approved via annotation",
                        )
                        .await?;

                        let plans_api: Api<PostgresPolicyPlan> =
                            Api::namespaced(ctx.kube_client.clone(), namespace);
                        let plan = plans_api.get(&current_plan.name_any()).await?;

                        emit_plan_event(ctx, resource, &plan, PlanEventType::ApplyStarted).await;

                        match crate::plan::execute_plan(
                            &ctx.kube_client,
                            &plan,
                            pool,
                            &sql_ctx,
                            &changes,
                        )
                        .await
                        {
                            Ok(()) => {
                                emit_plan_event(
                                    ctx,
                                    resource,
                                    &plan,
                                    PlanEventType::ApplySucceeded,
                                )
                                .await;
                            }
                            Err(err) => {
                                emit_plan_event(
                                    ctx,
                                    resource,
                                    &plan,
                                    PlanEventType::ApplyFailed {
                                        error: err.to_string(),
                                    },
                                )
                                .await;
                                return Err(err);
                            }
                        }

                        ctx.observability.record_apply_result("success");

                        // Update status to Ready.
                        update_status(ctx, resource, |status| {
                            status.set_condition(ready_condition(
                                true,
                                "Reconciled",
                                "Approved plan applied",
                            ));
                            status.set_condition(drifted_condition(
                                false,
                                "InSync",
                                "No pending changes",
                            ));
                            status.conditions.retain(|c| {
                                c.condition_type != "Reconciling"
                                    && c.condition_type != "Degraded"
                                    && c.condition_type != "Conflict"
                                    && c.condition_type != "Paused"
                            });
                            status.observed_generation = generation;
                            status.last_attempted_generation = generation;
                            status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
                            status.last_reconcile_time = Some(crate::crd::now_rfc3339());
                            status.change_summary = Some(summary);
                            status.last_reconcile_mode = Some(PolicyMode::Apply);
                            status.planned_sql = None;
                            status.planned_sql_truncated = false;
                            status.last_error = None;
                            status.applied_password_source_versions =
                                applied_password_source_versions;
                            status.transient_failure_count = 0;
                        })
                        .await?;

                        return Ok((
                            Action::requeue(requeue_interval),
                            ReconcileOutcome::Reconciled,
                        ));
                    }
                    crate::plan::PlanApprovalState::Rejected => {
                        crate::plan::mark_plan_rejected(&ctx.kube_client, &current_plan).await?;
                        emit_plan_event(ctx, resource, &current_plan, PlanEventType::Rejected)
                            .await;
                        info!(
                            name,
                            namespace,
                            plan = %current_plan.name_any(),
                            "plan rejected via annotation"
                        );

                        // Update status to reflect rejection, but don't create a new plan
                        // in the same cycle to avoid tight reject-create loops.
                        update_status(ctx, resource, |status| {
                            status.set_condition(ready_condition(
                                true,
                                "Planned",
                                &format!(
                                    "Plan {} rejected; new plan will be created on next reconcile",
                                    current_plan.name_any()
                                ),
                            ));
                            status.last_attempted_generation = generation;
                            status.last_error = None;
                            status.transient_failure_count = 0;
                            status.current_plan_ref = None;
                        })
                        .await?;

                        return Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned));
                    }
                    crate::plan::PlanApprovalState::Pending => {
                        // Plan exists and is pending — nothing to do, requeue.
                        info!(
                            name,
                            namespace,
                            plan = %current_plan.name_any(),
                            "plan awaiting manual approval"
                        );

                        update_status(ctx, resource, |status| {
                            let msg = format!(
                                "Plan {} awaiting approval; {} change(s) pending",
                                current_plan.name_any(),
                                summary.total,
                            );
                            status.set_condition(ready_condition(true, "Planned", &msg));
                            status.set_condition(drifted_condition(
                                !changes.is_empty(),
                                if changes.is_empty() {
                                    "InSync"
                                } else {
                                    "DriftDetected"
                                },
                                &msg,
                            ));
                            status.conditions.retain(|c| {
                                c.condition_type != "Reconciling"
                                    && c.condition_type != "Degraded"
                                    && c.condition_type != "Conflict"
                                    && c.condition_type != "Paused"
                            });
                            status.last_attempted_generation = generation;
                            status.change_summary = Some(summary.clone());
                            status.planned_sql = planned_sql.clone();
                            status.planned_sql_truncated = planned_sql_truncated;
                            status.last_error = None;
                            status.transient_failure_count = 0;
                        })
                        .await?;

                        return Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned));
                    }
                }
            }

            // No pending plan (or previous one was rejected) — create a new plan.
            if changes.is_empty() {
                info!(name, namespace, "no changes needed (manual approval mode)");

                update_status(ctx, resource, |status| {
                    status.set_condition(ready_condition(true, "Reconciled", "No changes needed"));
                    status.set_condition(drifted_condition(false, "InSync", "No pending changes"));
                    status.conditions.retain(|c| {
                        c.condition_type != "Reconciling"
                            && c.condition_type != "Degraded"
                            && c.condition_type != "Conflict"
                            && c.condition_type != "Paused"
                    });
                    status.observed_generation = generation;
                    status.last_attempted_generation = generation;
                    status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
                    status.last_reconcile_time = Some(crate::crd::now_rfc3339());
                    status.change_summary = Some(summary);
                    status.last_reconcile_mode = Some(PolicyMode::Apply);
                    status.planned_sql = None;
                    status.planned_sql_truncated = false;
                    status.last_error = None;
                    status.applied_password_source_versions = applied_password_source_versions;
                    status.transient_failure_count = 0;
                })
                .await?;

                return Ok((
                    Action::requeue(requeue_interval),
                    ReconcileOutcome::Reconciled,
                ));
            }

            // Create a new plan and wait for approval.
            let creation_result = crate::plan::create_or_update_plan(
                &ctx.kube_client,
                resource,
                &changes,
                &sql_ctx,
                &inspect_config,
                resource.spec.reconciliation_mode,
                identity.as_str(),
                &summary,
            )
            .await?;
            let plan_name = creation_result.plan_name().to_string();

            // Only emit PlanCreated event for genuinely new plans, not dedup hits.
            if creation_result.is_created() {
                let plans_api: Api<PostgresPolicyPlan> =
                    Api::namespaced(ctx.kube_client.clone(), namespace);
                let created_plan = plans_api.get(&plan_name).await?;
                emit_plan_event(
                    ctx,
                    resource,
                    &created_plan,
                    PlanEventType::Created {
                        change_count: summary.total,
                    },
                )
                .await;
            }

            crate::plan::update_policy_plan_ref(&ctx.kube_client, resource, &plan_name).await?;

            let msg = format!(
                "Plan {plan_name} created; {} change(s) awaiting approval",
                summary.total,
            );
            update_status(ctx, resource, |status| {
                status.set_condition(ready_condition(true, "Planned", &msg));
                status.set_condition(drifted_condition(
                    true,
                    "DriftDetected",
                    &format!("{} planned change(s) pending review", summary.total),
                ));
                status.conditions.retain(|c| {
                    c.condition_type != "Reconciling"
                        && c.condition_type != "Degraded"
                        && c.condition_type != "Conflict"
                        && c.condition_type != "Paused"
                });
                status.last_attempted_generation = generation;
                status.change_summary = Some(summary.clone());
                status.last_reconcile_mode = Some(PolicyMode::Apply);
                status.planned_sql = planned_sql.clone();
                status.planned_sql_truncated = planned_sql_truncated;
                status.last_error = None;
                status.transient_failure_count = 0;
                status.current_plan_ref = Some(crate::crd::PlanReference {
                    name: plan_name.clone(),
                });
            })
            .await?;

            info!(
                name,
                namespace,
                total = summary.total,
                plan = %plan_name,
                "plan created, awaiting manual approval"
            );

            Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned))
        }
    }
}

/// Resolve role passwords from Kubernetes Secrets or generate them.
///
/// For each role that declares a `password`:
/// - `PasswordSpec::SecretRef`: fetches the password from the referenced Secret.
/// - `PasswordSpec::Generate`: reads the generated Secret if it exists; in
///   apply mode it creates the Secret if needed, while in plan mode it keeps
///   reconciliation non-mutating and synthesizes an in-memory password.
///
/// Returns a map of role name → cleartext password string suitable for
/// [`pgroles_core::diff::inject_password_changes`] (which computes the
/// SCRAM-SHA-256 verifier before creating `SetPassword` changes).
async fn resolve_passwords_from_secrets(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    namespace: &str,
) -> Result<std::collections::BTreeMap<String, ResolvedPassword>, ReconcileError> {
    use k8s_openapi::api::core::v1::Secret;

    let mut resolved = std::collections::BTreeMap::new();

    // Cache fetched Secrets by name to avoid duplicate API calls when
    // multiple roles reference different keys in the same Secret.
    let mut secret_cache: std::collections::BTreeMap<String, Secret> =
        std::collections::BTreeMap::new();

    let secrets_api: kube::Api<Secret> = kube::Api::namespaced(ctx.kube_client.clone(), namespace);

    // First pass: fetch all referenced Secrets for secretRef roles.
    for role_spec in &resource.spec.roles {
        if let Some(pw) = &role_spec.password
            && let Some(secret_ref) = &pw.secret_ref
        {
            let secret_name = &secret_ref.name;
            if !secret_cache.contains_key(secret_name.as_str()) {
                let fetched = secrets_api.get(secret_name).await.map_err(|err| {
                    Box::new(crate::context::ContextError::SecretFetch {
                        name: secret_name.clone(),
                        namespace: namespace.to_string(),
                        source: err,
                    })
                })?;
                secret_cache.insert(secret_name.clone(), fetched);
            }
        }
    }

    // Second pass: resolve passwords from cache (secretRef) or generate.
    for role_spec in &resource.spec.roles {
        if let Some(pw) = &role_spec.password {
            if let Some(gen_spec) = &pw.generate {
                let password = if resource.spec.mode == PolicyMode::Plan {
                    match crate::password::get_generated_secret(
                        ctx.kube_client.clone(),
                        namespace,
                        &resource.name_any(),
                        &role_spec.name,
                        gen_spec,
                    )
                    .await
                    .map_err(Box::new)?
                    {
                        Some(existing) => existing,
                        None => {
                            let secret_name = crate::password::generated_secret_name(
                                &resource.name_any(),
                                &role_spec.name,
                                gen_spec,
                            );
                            let secret_key = crate::password::generated_secret_key(gen_spec);
                            let cleartext = crate::password::generate_password(
                                gen_spec
                                    .length
                                    .unwrap_or(crate::password::DEFAULT_PASSWORD_LENGTH),
                            );

                            crate::password::GeneratedPasswordSecret {
                                password: cleartext,
                                source_version:
                                    crate::password::missing_generated_secret_source_version(
                                        &secret_name,
                                        &secret_key,
                                    ),
                            }
                        }
                    }
                } else {
                    // Apply mode — ensure a Secret exists with a generated password.
                    crate::password::ensure_generated_secret(
                        ctx.kube_client.clone(),
                        namespace,
                        resource,
                        &role_spec.name,
                        gen_spec,
                    )
                    .await
                    .map_err(Box::new)?
                };
                resolved.insert(
                    role_spec.name.clone(),
                    ResolvedPassword {
                        cleartext: password.password,
                        source_version: password.source_version,
                    },
                );
            } else if pw.secret_ref.is_some() {
                // SecretRef mode — read from an existing Secret.
                let password = resolve_password_from_cache(&role_spec.name, pw, &secret_cache)?;
                resolved.insert(role_spec.name.clone(), password);
            }
        }
    }

    Ok(resolved)
}

/// Extract a password from a pre-fetched Secret cache for a `secretRef` role.
fn resolve_password_from_cache(
    role_name: &str,
    password_spec: &crate::crd::PasswordSpec,
    secret_cache: &std::collections::BTreeMap<String, k8s_openapi::api::core::v1::Secret>,
) -> Result<ResolvedPassword, ReconcileError> {
    let secret_ref = password_spec.secret_ref.as_ref().ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: "(no secretRef)".to_string(),
            key: role_name.to_string(),
        })
    })?;
    let secret_name = &secret_ref.name;
    let secret_key = password_spec.secret_key.as_deref().unwrap_or(role_name);

    let secret = secret_cache.get(secret_name.as_str()).ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    let data = secret.data.as_ref().ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    let value_bytes = data.get(secret_key).ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    let password = String::from_utf8(value_bytes.0.clone()).map_err(|_| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    if password.is_empty() {
        return Err(ReconcileError::EmptyPasswordSecret {
            role: role_name.to_string(),
            secret: secret_name.clone(),
            key: secret_key.to_string(),
        });
    }

    let resource_version = secret
        .metadata
        .resource_version
        .as_deref()
        .unwrap_or("unknown");
    Ok(ResolvedPassword {
        cleartext: password,
        source_version: format!("{secret_name}:{secret_key}:{resource_version}"),
    })
}

/// Resolve passwords from a pre-populated cache (for unit testing without K8s).
#[cfg(test)]
fn resolve_passwords_from_cached_secrets(
    resource: &PostgresPolicy,
    secret_cache: &std::collections::BTreeMap<String, k8s_openapi::api::core::v1::Secret>,
) -> Result<std::collections::BTreeMap<String, ResolvedPassword>, ReconcileError> {
    let mut resolved = std::collections::BTreeMap::new();
    for role_spec in &resource.spec.roles {
        if let Some(pw) = &role_spec.password
            && pw.secret_ref.is_some()
        {
            let password = resolve_password_from_cache(&role_spec.name, pw, secret_cache)?;
            resolved.insert(role_spec.name.clone(), password);
        }
    }
    Ok(resolved)
}

fn select_password_changes(
    changes: &[pgroles_core::diff::Change],
    resolved_passwords: &std::collections::BTreeMap<String, ResolvedPassword>,
    status: Option<&PostgresPolicyStatus>,
) -> (
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
) {
    let created_roles: std::collections::BTreeSet<&str> = changes
        .iter()
        .filter_map(|change| match change {
            pgroles_core::diff::Change::CreateRole { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let previous_versions = status
        .map(|status| &status.applied_password_source_versions)
        .cloned()
        .unwrap_or_default();

    let mut password_changes = std::collections::BTreeMap::new();
    let mut current_versions = std::collections::BTreeMap::new();

    for (role, resolved) in resolved_passwords {
        current_versions.insert(role.clone(), resolved.source_version.clone());
        if created_roles.contains(role.as_str())
            || previous_versions.get(role) != Some(&resolved.source_version)
        {
            password_changes.insert(role.clone(), resolved.cleartext.clone());
        }
    }

    (password_changes, current_versions)
}

/// Cleanup on deletion — evict cached pool.
async fn reconcile_cleanup(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
) -> Result<Action, ReconcileError> {
    let name = resource.name_any();
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;

    info!(name, namespace, "cleaning up (resource deleted)");

    // Evict any cached pool for this resource's connection.
    ctx.evict_pool(&namespace, &resource.spec.connection).await;

    // Note: we do NOT revoke grants on deletion. The resource being deleted
    // means the user no longer wants pgroles to manage these roles — it does
    // NOT mean "revoke everything". This is the safe default.

    Ok(Action::await_change())
}

/// Accumulate change counts into the summary.
fn accumulate_summary(summary: &mut ChangeSummary, change: &pgroles_core::diff::Change) {
    use pgroles_core::diff::Change;
    match change {
        Change::CreateRole { .. } => summary.roles_created += 1,
        Change::CreateSchema { .. } => summary.schemas_created += 1,
        Change::AlterSchemaOwner { .. } => summary.schema_owners_altered += 1,
        Change::AlterRole { .. } => summary.roles_altered += 1,
        Change::SetComment { .. } => summary.roles_altered += 1,
        Change::DropRole { .. } => summary.roles_dropped += 1,
        Change::TerminateSessions { .. } => summary.sessions_terminated += 1,
        Change::ReassignOwned { .. } => {}
        Change::DropOwned { .. } => {}
        Change::Grant { .. } | Change::EnsureSchemaOwnerPrivileges { .. } => {
            summary.grants_added += 1
        }
        Change::Revoke { .. } => summary.grants_revoked += 1,
        Change::SetDefaultPrivilege { .. } => summary.default_privileges_set += 1,
        Change::RevokeDefaultPrivilege { .. } => summary.default_privileges_revoked += 1,
        Change::AddMember { .. } => summary.members_added += 1,
        Change::RemoveMember { .. } => summary.members_removed += 1,
        Change::SetPassword { .. } => summary.passwords_set += 1,
    }
}

fn summarize_changes(changes: &[pgroles_core::diff::Change]) -> ChangeSummary {
    let mut summary = ChangeSummary::default();
    for change in changes {
        accumulate_summary(&mut summary, change);
    }
    summary.total = summary.roles_created
        + summary.roles_altered
        + summary.schemas_created
        + summary.schema_owners_altered
        + summary.roles_dropped
        + summary.sessions_terminated
        + summary.grants_added
        + summary.grants_revoked
        + summary.default_privileges_set
        + summary.default_privileges_revoked
        + summary.members_added
        + summary.members_removed
        + summary.passwords_set;
    summary
}

/// Parse a simplified RFC 3339 / ISO 8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`)
/// into seconds since the Unix epoch.
///
/// Returns `None` if the string does not match the expected format.
fn parse_rfc3339_to_epoch_secs(timestamp: &str) -> Option<u64> {
    // Expected format: "2026-03-31T12:34:56Z"
    if timestamp.len() < 20 || !timestamp.ends_with('Z') {
        return None;
    }
    let year: u64 = timestamp.get(0..4)?.parse().ok()?;
    let month: u64 = timestamp.get(5..7)?.parse().ok()?;
    let day: u64 = timestamp.get(8..10)?.parse().ok()?;
    let hours: u64 = timestamp.get(11..13)?.parse().ok()?;
    let minutes: u64 = timestamp.get(14..16)?.parse().ok()?;
    let seconds: u64 = timestamp.get(17..19)?.parse().ok()?;

    // Convert to days since epoch using the inverse of the civil algorithm.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146097 + doe - 719468;

    Some(days_since_epoch * 86400 + hours * 3600 + minutes * 60 + seconds)
}

async fn detect_sql_context(
    pool: &sqlx::PgPool,
    inspect_config: &pgroles_inspect::InspectConfig,
) -> Result<pgroles_core::sql::SqlContext, ReconcileError> {
    let pg_version = pgroles_inspect::detect_pg_version(pool).await?;
    let privilege_schemas: Vec<&str> = inspect_config
        .privilege_schemas
        .iter()
        .map(|schema| schema.as_str())
        .collect();
    let relation_inventory =
        pgroles_inspect::fetch_relation_inventory(pool, &privilege_schemas).await?;
    Ok(
        pgroles_core::sql::SqlContext::from_version_num(pg_version.version_num)
            .with_relation_inventory(relation_inventory),
    )
}

fn render_plan_sql_for_status(
    changes: &[pgroles_core::diff::Change],
    sql_ctx: &pgroles_core::sql::SqlContext,
) -> (Option<String>, bool) {
    if changes.is_empty() {
        return (None, false);
    }

    // Render each change individually so we can redact passwords.
    let rendered: String = changes
        .iter()
        .flat_map(|change| {
            if let pgroles_core::diff::Change::SetPassword { name, .. } = change {
                vec![format!(
                    "ALTER ROLE {} PASSWORD '[REDACTED]';",
                    pgroles_core::sql::quote_ident(name)
                )]
            } else {
                pgroles_core::sql::render_statements_with_context(change, sql_ctx)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let (truncated, did_truncate) = truncate_status_text(&rendered, MAX_PLANNED_SQL_STATUS_BYTES);
    (Some(truncated), did_truncate)
}

fn truncate_status_text(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }

    let marker = "\n-- truncated for status --";
    let target_len = max_bytes.saturating_sub(marker.len());
    let mut end = target_len.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = text[..end].to_string();
    truncated.push_str(marker);
    (truncated, true)
}

/// Emit a plan lifecycle event on the parent policy, logging warnings on failure.
async fn emit_plan_event(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    plan: &PostgresPolicyPlan,
    event_type: PlanEventType,
) {
    if let Err(error) = publish_plan_event(&ctx.event_recorder, policy, plan, event_type).await {
        let namespace = policy.namespace().unwrap_or_default();
        let name = policy.name_any();
        tracing::warn!(
            policy = %format!("{namespace}/{name}"),
            %error,
            "failed to publish plan lifecycle event"
        );
    }
}

/// Patch the status sub-resource of a PostgresPolicy.
async fn update_status<F>(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    mutate: F,
) -> Result<(), ReconcileError>
where
    F: FnOnce(&mut PostgresPolicyStatus),
{
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;
    let name = resource.name_any();

    let api: Api<PostgresPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let latest = api.get(&name).await?;
    let old_status = latest.status.clone();
    let mut status = old_status.clone().unwrap_or_default();

    mutate(&mut status);

    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        &name,
        &PatchParams::apply("pgroles-operator"),
        &Patch::Merge(&patch),
    )
    .await?;

    if let Err(error) =
        publish_status_events(&ctx.event_recorder, &latest, old_status.as_ref(), &status).await
    {
        tracing::warn!(policy = %format!("{namespace}/{name}"), %error, "failed to publish Kubernetes Events");
    }

    Ok(())
}

async fn detect_policy_conflict(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    identity: &DatabaseIdentity,
    ownership: &crate::crd::OwnershipClaims,
) -> Result<Option<String>, ReconcileError> {
    let api: Api<PostgresPolicy> = Api::all(ctx.kube_client.clone());
    let policies = api.list(&Default::default()).await?;

    Ok(detect_policy_conflict_in_list(
        resource,
        identity,
        ownership,
        policies.into_iter(),
    ))
}

fn detect_policy_conflict_in_list(
    resource: &PostgresPolicy,
    identity: &DatabaseIdentity,
    ownership: &crate::crd::OwnershipClaims,
    policies: impl IntoIterator<Item = PostgresPolicy>,
) -> Option<String> {
    let this_ns = resource.namespace()?;
    let this_name = resource.name_any();

    let mut conflicts = Vec::new();
    for other in policies {
        let other_ns = match other.namespace() {
            Some(ns) => ns,
            None => continue,
        };
        let other_name = other.name_any();
        if other_ns == this_ns && other_name == this_name {
            continue;
        }

        let other_identity = DatabaseIdentity::from_connection(&other_ns, &other.spec.connection);
        if &other_identity != identity {
            continue;
        }

        if let Err(error) = other.spec.validate_password_specs(&other_name) {
            tracing::warn!(
                policy = %format!("{other_ns}/{other_name}"),
                database = %identity.as_str(),
                %error,
                "skipping conflict detection for invalid peer policy"
            );
            continue;
        }

        let other_ownership = match other.spec.ownership_claims() {
            Ok(claims) => claims,
            Err(error) => {
                tracing::warn!(
                    policy = %format!("{other_ns}/{other_name}"),
                    database = %identity.as_str(),
                    %error,
                    "skipping conflict detection for invalid peer policy"
                );
                continue;
            }
        };
        if ownership.overlaps(&other_ownership) {
            let overlap = ownership.overlap_summary(&other_ownership);
            conflicts.push(format!("{other_ns}/{other_name} ({overlap})"));
        }
    }

    if conflicts.is_empty() {
        None
    } else {
        Some(format!(
            "policy ownership overlaps with {} on database target {}",
            conflicts.join(", "),
            identity.as_str()
        ))
    }
}

impl ReconcileError {
    fn reason(&self) -> &'static str {
        match self {
            ReconcileError::ManifestExpansion(_)
            | ReconcileError::InvalidInterval(_, _)
            | ReconcileError::InvalidSpec(_) => "InvalidSpec",
            ReconcileError::ConflictingPolicy(_) => "ConflictingPolicy",
            ReconcileError::LockContention(_, _) => "LockContention",
            ReconcileError::Context(context) => match context.as_ref() {
                ContextError::SecretFetch { .. } => "SecretFetchFailed",
                ContextError::SecretMissing { .. } => "SecretMissing",
                ContextError::DatabaseConnect { .. } => "DatabaseConnectionFailed",
                ContextError::EmptyResolvedValue { .. } => "InvalidConnectionParams",
                ContextError::InvalidResolvedSslMode { .. } => "InvalidConnectionParams",
            },
            ReconcileError::Inspect(error) => match error {
                pgroles_inspect::InspectError::Database(sql_err) => {
                    match classify_sqlx_error(sql_err) {
                        SqlErrorKind::InsufficientPrivileges => "InsufficientPrivileges",
                        SqlErrorKind::MissingDatabaseObject => "MissingDatabaseObject",
                        SqlErrorKind::Transient => "DatabaseInspectionFailed",
                    }
                }
            },
            ReconcileError::SqlExec(error) => match classify_sqlx_error(error) {
                SqlErrorKind::InsufficientPrivileges => "InsufficientPrivileges",
                SqlErrorKind::MissingDatabaseObject => "MissingDatabaseObject",
                SqlErrorKind::Transient => "ApplyFailed",
            },
            ReconcileError::UnsafeRoleDrops(_) => "UnsafeRoleDrops",
            ReconcileError::EmptyPasswordSecret { .. } => "InvalidSpec",
            ReconcileError::MissingDatabaseObjects(_) => "MissingDatabaseObject",
            ReconcileError::PasswordGeneration(_) => "SecretFetchFailed",
            ReconcileError::PlanSqlStorage(_) => "PlanSqlStorageFailed",
            ReconcileError::Kube(_) => "KubernetesApiError",
            ReconcileError::NoNamespace => "InvalidResource",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ConnectionSpec, CrdReconciliationMode, PasswordSpec, PolicyMode, PostgresPolicySpec,
        RoleSpec, SecretReference,
    };
    use k8s_openapi::{
        ByteString, api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::ObjectMeta,
    };
    use sqlx::error::{DatabaseError, ErrorKind};
    use std::borrow::Cow;
    use std::collections::BTreeMap;
    use std::error::Error as StdError;
    use std::fmt;

    #[derive(Debug)]
    struct TestDatabaseError {
        message: String,
        code: Option<&'static str>,
    }

    impl fmt::Display for TestDatabaseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl StdError for TestDatabaseError {}

    impl DatabaseError for TestDatabaseError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.map(Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    fn insufficient_privilege_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "permission denied to create role".to_string(),
            code: Some(SQLSTATE_INSUFFICIENT_PRIVILEGE),
        }))
    }

    fn missing_schema_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "schema \"etl\" does not exist".to_string(),
            code: Some(SQLSTATE_INVALID_SCHEMA_NAME),
        }))
    }

    fn missing_table_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "relation \"foo\" does not exist".to_string(),
            code: Some(SQLSTATE_UNDEFINED_TABLE),
        }))
    }

    fn missing_function_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "function foo() does not exist".to_string(),
            code: Some(SQLSTATE_UNDEFINED_FUNCTION),
        }))
    }

    fn missing_object_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "role \"nope\" does not exist".to_string(),
            code: Some(SQLSTATE_UNDEFINED_OBJECT),
        }))
    }

    fn transient_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "connection timed out".to_string(),
            code: Some("08006"),
        }))
    }

    fn test_policy(interval: &str, transient_failure_count: i32) -> Arc<PostgresPolicy> {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "db-credentials".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
            },
            interval: interval.to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: Default::default(),
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
            retirements: Vec::new(),
            approval: None,
        };
        let mut resource = PostgresPolicy::new("example", spec);
        resource.metadata.namespace = Some("default".to_string());
        resource.status = Some(PostgresPolicyStatus {
            transient_failure_count,
            ..Default::default()
        });
        Arc::new(resource)
    }

    fn test_policy_with_spec(name: &str, spec: PostgresPolicySpec) -> PostgresPolicy {
        let mut resource = PostgresPolicy::new(name, spec);
        resource.metadata.namespace = Some("default".to_string());
        resource
    }

    fn valid_role_policy(name: &str, role_name: &str, secret_name: &str) -> PostgresPolicy {
        test_policy_with_spec(
            name,
            PostgresPolicySpec {
                connection: ConnectionSpec {
                    secret_ref: Some(SecretReference {
                        name: secret_name.to_string(),
                    }),
                    secret_key: Some("DATABASE_URL".to_string()),
                    params: None,
                },
                interval: "5m".to_string(),
                suspend: false,
                mode: PolicyMode::Apply,
                reconciliation_mode: CrdReconciliationMode::default(),
                default_owner: None,
                profiles: Default::default(),
                schemas: Vec::new(),
                roles: vec![RoleSpec {
                    name: role_name.to_string(),
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
                grants: Vec::new(),
                default_privileges: Vec::new(),
                memberships: Vec::new(),
                retirements: Vec::new(),
                approval: None,
            },
        )
    }

    fn invalid_profile_policy(name: &str, secret_name: &str) -> PostgresPolicy {
        test_policy_with_spec(
            name,
            PostgresPolicySpec {
                connection: ConnectionSpec {
                    secret_ref: Some(SecretReference {
                        name: secret_name.to_string(),
                    }),
                    secret_key: Some("DATABASE_URL".to_string()),
                    params: None,
                },
                interval: "5m".to_string(),
                suspend: false,
                mode: PolicyMode::Apply,
                reconciliation_mode: CrdReconciliationMode::default(),
                default_owner: None,
                profiles: Default::default(),
                schemas: vec![pgroles_core::manifest::SchemaBinding {
                    name: "reporting".to_string(),
                    profiles: vec!["missing-profile".to_string()],
                    role_pattern: "{schema}-{profile}".to_string(),
                    owner: None,
                }],
                roles: Vec::new(),
                grants: Vec::new(),
                default_privileges: Vec::new(),
                memberships: Vec::new(),
                retirements: Vec::new(),
                approval: None,
            },
        )
    }

    fn password_role_policy() -> PostgresPolicy {
        test_policy_with_spec(
            "password-policy",
            PostgresPolicySpec {
                connection: ConnectionSpec {
                    secret_ref: Some(SecretReference {
                        name: "db-credentials".to_string(),
                    }),
                    secret_key: Some("DATABASE_URL".to_string()),
                    params: None,
                },
                interval: "5m".to_string(),
                suspend: false,
                mode: PolicyMode::Apply,
                reconciliation_mode: CrdReconciliationMode::default(),
                default_owner: None,
                profiles: Default::default(),
                schemas: Vec::new(),
                roles: vec![
                    RoleSpec {
                        name: "app".to_string(),
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
                            generate: None,
                        }),
                        password_valid_until: None,
                    },
                    RoleSpec {
                        name: "reporter".to_string(),
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
                            secret_key: Some("reporter-password".to_string()),
                            generate: None,
                        }),
                        password_valid_until: None,
                    },
                ],
                grants: Vec::new(),
                default_privileges: Vec::new(),
                memberships: Vec::new(),
                retirements: Vec::new(),
                approval: None,
            },
        )
    }

    fn secret_with_keys(name: &str, entries: &[(&str, &str)]) -> Secret {
        secret_with_keys_and_version(name, "1", entries)
    }

    fn secret_with_keys_and_version(
        name: &str,
        resource_version: &str,
        entries: &[(&str, &str)],
    ) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                resource_version: Some(resource_version.to_string()),
                ..Default::default()
            },
            data: Some(
                entries
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), ByteString(value.as_bytes().to_vec())))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn parse_interval_minutes() {
        let d = parse_interval("5m").unwrap();
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn parse_interval_hours() {
        let d = parse_interval("1h").unwrap();
        assert_eq!(d, Duration::from_secs(3600));
    }

    #[test]
    fn parse_interval_seconds() {
        let d = parse_interval("30s").unwrap();
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn parse_interval_compound() {
        let d = parse_interval("1h30m").unwrap();
        assert_eq!(d, Duration::from_secs(5400));
    }

    #[test]
    fn parse_interval_empty_uses_default() {
        let d = parse_interval("").unwrap();
        assert_eq!(d, Duration::from_secs(DEFAULT_REQUEUE_SECS));
    }

    #[test]
    fn parse_interval_bare_number_treated_as_seconds() {
        let d = parse_interval("120").unwrap();
        assert_eq!(d, Duration::from_secs(120));
    }

    #[test]
    fn parse_interval_invalid_unit() {
        let result = parse_interval("5x");
        assert!(result.is_err());
    }

    #[test]
    fn accumulate_summary_counts() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let mut summary = ChangeSummary::default();

        accumulate_summary(
            &mut summary,
            &Change::CreateRole {
                name: "test".to_string(),
                state: RoleState {
                    login: true,
                    ..RoleState::default()
                },
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::Grant {
                role: "test".to_string(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("public".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::TerminateSessions {
                role: "test".to_string(),
            },
        );

        assert_eq!(summary.roles_created, 1);
        assert_eq!(summary.grants_added, 1);
        assert_eq!(summary.sessions_terminated, 1);
    }

    #[test]
    fn accumulate_summary_counts_schema_changes_separately() {
        use pgroles_core::diff::Change;

        let mut summary = ChangeSummary::default();

        accumulate_summary(
            &mut summary,
            &Change::CreateSchema {
                name: "inventory".to_string(),
                owner: Some("inventory_owner".to_string()),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AlterSchemaOwner {
                name: "catalog".to_string(),
                owner: "catalog_owner".to_string(),
            },
        );

        assert_eq!(summary.schemas_created, 1);
        assert_eq!(summary.schema_owners_altered, 1);
        assert_eq!(summary.grants_added, 0);
    }

    #[test]
    fn summarize_changes_sets_total() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let changes = vec![
            Change::CreateRole {
                name: "test".to_string(),
                state: RoleState::default(),
            },
            Change::CreateSchema {
                name: "inventory".to_string(),
                owner: Some("inventory_owner".to_string()),
            },
            Change::Grant {
                role: "test".to_string(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("public".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        ];

        let summary = summarize_changes(&changes);
        assert_eq!(summary.roles_created, 1);
        assert_eq!(summary.schemas_created, 1);
        assert_eq!(summary.grants_added, 1);
        assert_eq!(summary.total, 3);
    }

    #[test]
    fn truncate_status_text_marks_truncation() {
        let text = "x".repeat(MAX_PLANNED_SQL_STATUS_BYTES + 32);
        let (truncated, did_truncate) = truncate_status_text(&text, MAX_PLANNED_SQL_STATUS_BYTES);
        assert!(did_truncate);
        assert!(truncated.len() <= MAX_PLANNED_SQL_STATUS_BYTES);
        assert!(truncated.ends_with("-- truncated for status --"));
    }

    #[test]
    fn accumulate_summary_all_change_types() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let mut summary = ChangeSummary::default();

        accumulate_summary(
            &mut summary,
            &Change::CreateRole {
                name: "r1".to_string(),
                state: RoleState::default(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AlterRole {
                name: "r1".to_string(),
                attributes: vec![pgroles_core::model::RoleAttribute::Login(true)],
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::CreateSchema {
                name: "schema1".to_string(),
                owner: Some("owner1".to_string()),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AlterSchemaOwner {
                name: "schema2".to_string(),
                owner: "owner2".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::SetComment {
                name: "r1".to_string(),
                comment: Some("comment".to_string()),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::DropRole {
                name: "r1".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::TerminateSessions {
                role: "r1".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::ReassignOwned {
                from_role: "r1".to_string(),
                to_role: "r2".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::DropOwned {
                role: "r1".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::Grant {
                role: "r1".to_string(),
                object_type: pgroles_core::manifest::ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::Revoke {
                role: "r1".to_string(),
                object_type: pgroles_core::manifest::ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::SetDefaultPrivilege {
                schema: "public".to_string(),
                owner: "owner".to_string(),
                grantee: "r1".to_string(),
                on_type: pgroles_core::manifest::ObjectType::Table,
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::RevokeDefaultPrivilege {
                schema: "public".to_string(),
                owner: "owner".to_string(),
                grantee: "r1".to_string(),
                on_type: pgroles_core::manifest::ObjectType::Table,
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AddMember {
                role: "r1".to_string(),
                member: "r2".to_string(),
                inherit: true,
                admin: false,
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::RemoveMember {
                role: "r1".to_string(),
                member: "r2".to_string(),
            },
        );

        assert_eq!(summary.roles_created, 1);
        // AlterRole + SetComment both increment roles_altered
        assert_eq!(summary.roles_altered, 2);
        assert_eq!(summary.schemas_created, 1);
        assert_eq!(summary.schema_owners_altered, 1);
        assert_eq!(summary.roles_dropped, 1);
        assert_eq!(summary.sessions_terminated, 1);
        assert_eq!(summary.grants_added, 1);
        assert_eq!(summary.grants_revoked, 1);
        assert_eq!(summary.default_privileges_set, 1);
        assert_eq!(summary.default_privileges_revoked, 1);
        assert_eq!(summary.members_added, 1);
        assert_eq!(summary.members_removed, 1);
    }

    #[test]
    fn error_reason_invalid_spec_for_manifest_expansion() {
        let err = ReconcileError::ManifestExpansion(
            pgroles_core::manifest::ManifestError::UndefinedProfile("bad".into(), "schema1".into()),
        );
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn error_reason_invalid_spec_for_invalid_interval() {
        let err = ReconcileError::InvalidInterval("5x".into(), "unknown unit 'x'".into());
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn error_reason_invalid_spec_for_password_validation() {
        let err = ReconcileError::InvalidSpec("role password must set exactly one mode".into());
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn error_reason_missing_database_objects() {
        let err = ReconcileError::MissingDatabaseObjects("schema \"etl\"".into());
        assert_eq!(err.reason(), "MissingDatabaseObject");
    }

    #[test]
    fn error_display_missing_database_objects_lists_schemas() {
        let err = ReconcileError::MissingDatabaseObjects("schema \"etl\", schema \"jobs\"".into());
        let msg = err.to_string();
        assert!(msg.contains("schema \"etl\""));
        assert!(msg.contains("schema \"jobs\""));
        assert!(
            msg.contains("pointing at the intended database"),
            "message should include remediation hint"
        );
    }

    #[test]
    fn referenced_schema_names_from_schema_grants() {
        use pgroles_core::manifest::{
            ExpandedManifest, Grant, ObjectTarget, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![Grant {
                role: "app".into(),
                privileges: vec![Privilege::Usage],
                object: ObjectTarget {
                    object_type: ObjectType::Schema,
                    schema: None,
                    name: Some("etl".into()),
                },
            }],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(names.contains("etl"));
    }

    #[test]
    fn referenced_schema_names_from_table_grants() {
        use pgroles_core::manifest::{
            ExpandedManifest, Grant, ObjectTarget, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![Grant {
                role: "app".into(),
                privileges: vec![Privilege::Select],
                object: ObjectTarget {
                    object_type: ObjectType::Table,
                    schema: Some("analytics".into()),
                    name: Some("*".into()),
                },
            }],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(names.contains("analytics"));
    }

    #[test]
    fn referenced_schema_names_from_default_privileges() {
        use pgroles_core::manifest::{
            DefaultPrivilege, DefaultPrivilegeGrant, ExpandedManifest, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: vec![DefaultPrivilege {
                owner: Some("app_owner".into()),
                schema: "reporting".into(),
                grant: vec![DefaultPrivilegeGrant {
                    role: Some("app".into()),
                    privileges: vec![Privilege::Select],
                    on_type: ObjectType::Table,
                }],
            }],
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(names.contains("reporting"));
    }

    #[test]
    fn referenced_schema_names_deduplicates_across_sources() {
        use pgroles_core::manifest::{
            DefaultPrivilege, DefaultPrivilegeGrant, ExpandedManifest, Grant, ObjectTarget,
            ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![
                Grant {
                    role: "app".into(),
                    privileges: vec![Privilege::Usage],
                    object: ObjectTarget {
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some("shared".into()),
                    },
                },
                Grant {
                    role: "app".into(),
                    privileges: vec![Privilege::Select],
                    object: ObjectTarget {
                        object_type: ObjectType::Table,
                        schema: Some("shared".into()),
                        name: Some("*".into()),
                    },
                },
            ],
            default_privileges: vec![DefaultPrivilege {
                owner: Some("app_owner".into()),
                schema: "shared".into(),
                grant: vec![DefaultPrivilegeGrant {
                    role: Some("app".into()),
                    privileges: vec![Privilege::Select],
                    on_type: ObjectType::Table,
                }],
            }],
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        // BTreeSet deduplicates so a schema referenced three ways appears once.
        assert_eq!(names.len(), 1);
        assert!(names.contains("shared"));
    }

    #[test]
    fn referenced_schema_names_skips_database_and_roleless_grants() {
        use pgroles_core::manifest::{
            ExpandedManifest, Grant, ObjectTarget, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![Grant {
                role: "app".into(),
                privileges: vec![Privilege::Connect],
                object: ObjectTarget {
                    object_type: ObjectType::Database,
                    schema: None,
                    name: Some("mydb".into()),
                },
            }],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(
            names.is_empty(),
            "database-level grants should not contribute schema names"
        );
    }

    #[test]
    fn is_system_schema_identifies_pg_and_information_schema() {
        assert!(is_system_schema("pg_catalog"));
        assert!(is_system_schema("pg_toast"));
        assert!(is_system_schema("pg_temp_1"));
        assert!(is_system_schema("information_schema"));
        assert!(!is_system_schema("public"));
        assert!(!is_system_schema("etl"));
        assert!(!is_system_schema("analytics"));
    }

    #[test]
    fn referenced_schema_names_include_declared_schemas() {
        use pgroles_core::manifest::{ExpandedManifest, ExpandedSchema};

        let expanded = ExpandedManifest {
            schemas: vec![ExpandedSchema {
                name: "cdc".into(),
                owner: Some("cdc_owner".into()),
            }],
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };

        let names = referenced_schema_names(&expanded);
        assert!(names.contains("cdc"));
    }

    #[test]
    fn declared_schema_names_returns_declared_only() {
        use pgroles_core::manifest::{ExpandedManifest, ExpandedSchema};

        let expanded = ExpandedManifest {
            schemas: vec![ExpandedSchema {
                name: "cdc".into(),
                owner: Some("cdc_owner".into()),
            }],
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };

        let names = declared_schema_names(&expanded);
        assert_eq!(names.len(), 1);
        assert!(names.contains("cdc"));
    }

    #[test]
    fn externally_required_schema_names_excludes_declared_schemas() {
        use pgroles_core::manifest::{
            ExpandedManifest, ExpandedSchema, Grant, ObjectTarget, ObjectType, Privilege,
        };

        let expanded = ExpandedManifest {
            schemas: vec![ExpandedSchema {
                name: "managed".into(),
                owner: Some("managed_owner".into()),
            }],
            roles: Vec::new(),
            grants: vec![
                Grant {
                    role: "app".into(),
                    privileges: vec![Privilege::Usage],
                    object: ObjectTarget {
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some("managed".into()),
                    },
                },
                Grant {
                    role: "app".into(),
                    privileges: vec![Privilege::Select],
                    object: ObjectTarget {
                        object_type: ObjectType::Table,
                        schema: Some("external".into()),
                        name: Some("*".into()),
                    },
                },
            ],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };

        let names = externally_required_schema_names(&expanded);
        assert_eq!(names.len(), 1);
        assert!(names.contains("external"));
        assert!(!names.contains("managed"));
    }

    #[test]
    fn error_reason_conflicting_policy() {
        let err = ReconcileError::ConflictingPolicy("overlaps with other".into());
        assert_eq!(err.reason(), "ConflictingPolicy");
    }

    #[test]
    fn error_reason_unsafe_role_drops() {
        let err = ReconcileError::UnsafeRoleDrops("role owns objects".into());
        assert_eq!(err.reason(), "UnsafeRoleDrops");
    }

    #[test]
    fn error_reason_no_namespace() {
        let err = ReconcileError::NoNamespace;
        assert_eq!(err.reason(), "InvalidResource");
    }

    #[test]
    fn error_reason_context_secret_missing() {
        let err = ReconcileError::Context(Box::new(crate::context::ContextError::SecretMissing {
            name: "pg-secret".into(),
            key: "DATABASE_URL".into(),
        }));
        assert_eq!(err.reason(), "SecretMissing");
    }

    #[test]
    fn error_reason_sql_exec_insufficient_privileges() {
        let err = ReconcileError::SqlExec(insufficient_privilege_sqlx_error());
        assert_eq!(err.reason(), "InsufficientPrivileges");
    }

    #[test]
    fn error_reason_inspect_insufficient_privileges() {
        let err = ReconcileError::Inspect(pgroles_inspect::InspectError::Database(
            insufficient_privilege_sqlx_error(),
        ));
        assert_eq!(err.reason(), "InsufficientPrivileges");
    }

    #[test]
    fn error_display_includes_details() {
        let err = ReconcileError::InvalidInterval("5x".into(), "unknown unit 'x'".into());
        let msg = err.to_string();
        assert!(msg.contains("5x"), "error display should contain interval");
        assert!(
            msg.contains("unknown unit"),
            "error display should contain reason"
        );
    }

    #[test]
    fn error_reason_lock_contention() {
        let err = ReconcileError::LockContention(
            "prod/db-creds/DATABASE_URL".into(),
            "in-process lock held".into(),
        );
        assert_eq!(err.reason(), "LockContention");
    }

    #[test]
    fn error_display_lock_contention_includes_database() {
        let err = ReconcileError::LockContention(
            "prod/db-creds/DATABASE_URL".into(),
            "advisory lock held by another session".into(),
        );
        let msg = err.to_string();
        assert!(
            msg.contains("prod/db-creds/DATABASE_URL"),
            "lock contention error should include database identity"
        );
        assert!(
            msg.contains("advisory lock"),
            "lock contention error should include reason"
        );
    }

    #[test]
    fn requeue_with_jitter_produces_bounded_delay() {
        // Run multiple times to exercise the jitter distribution.
        let base = LOCK_CONTENTION_BASE_SECS;
        let max = LOCK_CONTENTION_BASE_SECS + LOCK_CONTENTION_JITTER_SECS;
        for _ in 0..20 {
            let delay = jitter_delay();
            let secs = delay.as_secs();
            assert!(
                secs >= base,
                "jitter delay {secs}s should be at least base {base}s",
            );
            assert!(
                secs <= max,
                "jitter delay {secs}s should not exceed base+jitter {max}s",
            );
        }
    }

    #[test]
    fn lock_contention_constants_are_reasonable() {
        // Use variables to avoid clippy::assertions_on_constants.
        let base = LOCK_CONTENTION_BASE_SECS;
        let jitter = LOCK_CONTENTION_JITTER_SECS;
        assert!(base > 0, "base delay must be positive");
        assert!(jitter > 0, "jitter window must be positive");
        assert!(
            base + jitter <= 60,
            "total max contention delay should not exceed error_policy's 60s"
        );
    }

    #[test]
    fn transient_backoff_delay_is_bounded_and_caps() {
        for _ in 0..20 {
            let first = transient_backoff_delay(1).as_secs();
            assert!((TRANSIENT_BACKOFF_BASE_SECS..=7).contains(&first));

            let fourth = transient_backoff_delay(4).as_secs();
            assert!((40..=60).contains(&fourth));

            let capped = transient_backoff_delay(10).as_secs();
            assert_eq!(capped, TRANSIENT_BACKOFF_MAX_SECS);
        }
    }

    #[test]
    fn slow_retry_delay_uses_policy_interval() {
        let resource = test_policy("7m", 0);
        assert_eq!(slow_retry_delay(&resource), Duration::from_secs(420));
    }

    #[test]
    fn slow_retry_delay_falls_back_on_invalid_interval() {
        let resource = test_policy("nope", 0);
        assert_eq!(
            slow_retry_delay(&resource),
            Duration::from_secs(DEFAULT_REQUEUE_SECS)
        );
    }

    #[test]
    fn retry_classifies_lock_contention_separately() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::LockContention(
            "default/db-credentials/DATABASE_URL".into(),
            "lock held".into(),
        ));
        assert_eq!(retry_class(&error), RetryClass::LockContention);
    }

    #[test]
    fn retry_classifies_invalid_spec_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::InvalidInterval(
            "oops".into(),
            "bad interval".into(),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_missing_database_objects_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::MissingDatabaseObjects(
            "schema \"etl\"".into(),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_plan_sql_storage_as_slow() {
        let error =
            finalizer::Error::ApplyFailed(ReconcileError::PlanSqlStorage("gzip failed".into()));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_secret_missing_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretMissing {
                name: "db-credentials".into(),
                key: "DATABASE_URL".into(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_secret_fetch_not_found_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretFetch {
                name: "db-credentials".into(),
                namespace: "default".into(),
                source: kube::Error::Api(
                    kube::core::Status::failure("secrets \"db-credentials\" not found", "NotFound")
                        .with_code(404)
                        .boxed(),
                ),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_secret_fetch_transport_errors_as_transient() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretFetch {
                name: "db-credentials".into(),
                namespace: "default".into(),
                source: kube::Error::Api(
                    kube::core::Status::failure("internal error", "InternalError")
                        .with_code(500)
                        .boxed(),
                ),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Transient);
    }

    #[test]
    fn retry_classifies_secret_fetch_forbidden_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretFetch {
                name: "db-credentials".into(),
                namespace: "default".into(),
                source: kube::Error::Api(
                    kube::core::Status::failure("forbidden", "Forbidden")
                        .with_code(403)
                        .boxed(),
                ),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_database_connect_as_transient() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::DatabaseConnect {
                source: sqlx::Error::PoolTimedOut,
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Transient);
    }

    #[test]
    fn retry_classifies_sql_exec_insufficient_privilege_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::SqlExec(
            insufficient_privilege_sqlx_error(),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_inspect_insufficient_privilege_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Inspect(
            pgroles_inspect::InspectError::Database(insufficient_privilege_sqlx_error()),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn classify_sqlx_error_categories() {
        assert_eq!(
            classify_sqlx_error(&insufficient_privilege_sqlx_error()),
            SqlErrorKind::InsufficientPrivileges
        );
        assert_eq!(
            classify_sqlx_error(&missing_schema_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&missing_table_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&missing_function_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&missing_object_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&transient_sqlx_error()),
            SqlErrorKind::Transient
        );
    }

    #[test]
    fn retry_classifies_sql_exec_missing_schema_as_slow() {
        let error =
            finalizer::Error::ApplyFailed(ReconcileError::SqlExec(missing_schema_sqlx_error()));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_sql_exec_missing_table_as_slow() {
        let error =
            finalizer::Error::ApplyFailed(ReconcileError::SqlExec(missing_table_sqlx_error()));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_inspect_missing_schema_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Inspect(
            pgroles_inspect::InspectError::Database(missing_schema_sqlx_error()),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_sql_exec_missing_database_object() {
        let err = ReconcileError::SqlExec(missing_schema_sqlx_error());
        assert_eq!(err.reason(), "MissingDatabaseObject");
    }

    #[test]
    fn error_reason_inspect_missing_database_object() {
        let err = ReconcileError::Inspect(pgroles_inspect::InspectError::Database(
            missing_table_sqlx_error(),
        ));
        assert_eq!(err.reason(), "MissingDatabaseObject");
    }

    #[test]
    fn retry_classifies_empty_resolved_value_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::EmptyResolvedValue {
                field: "password".to_string(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_empty_resolved_value() {
        let err =
            ReconcileError::Context(Box::new(crate::context::ContextError::EmptyResolvedValue {
                field: "host".to_string(),
            }));
        assert_eq!(err.reason(), "InvalidConnectionParams");
    }

    #[test]
    fn retry_classifies_invalid_resolved_ssl_mode_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::InvalidResolvedSslMode {
                value: "bogus".to_string(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_invalid_resolved_ssl_mode() {
        let err = ReconcileError::Context(Box::new(
            crate::context::ContextError::InvalidResolvedSslMode {
                value: "bogus".to_string(),
            },
        ));
        assert_eq!(err.reason(), "InvalidConnectionParams");
    }

    #[test]
    fn error_reason_sql_exec_transient_is_apply_failed() {
        let err = ReconcileError::SqlExec(transient_sqlx_error());
        assert_eq!(err.reason(), "ApplyFailed");
    }

    #[test]
    fn error_reason_plan_sql_storage_failed() {
        let err = ReconcileError::PlanSqlStorage("gzip failed".into());
        assert_eq!(err.reason(), "PlanSqlStorageFailed");
    }

    #[test]
    fn error_policy_uses_normal_interval_for_invalid_spec() {
        let resource = test_policy("11m", 0);
        let error = finalizer::Error::ApplyFailed(ReconcileError::InvalidInterval(
            "oops".into(),
            "bad interval".into(),
        ));
        assert_eq!(
            retry_action(&resource, &error),
            Action::requeue(Duration::from_secs(660))
        );
    }

    #[test]
    fn error_policy_uses_exponential_backoff_for_transient_failures() {
        let resource = test_policy("5m", 3);
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::DatabaseConnect {
                source: sqlx::Error::PoolTimedOut,
            },
        )));
        let action = retry_action(&resource, &error);
        assert!(
            (40..=60).any(|secs| action == Action::requeue(Duration::from_secs(secs))),
            "expected transient retry between 40s and 60s, got {action:?}"
        );
    }

    #[test]
    fn render_plan_sql_for_status_redacts_passwords() {
        let changes = vec![
            pgroles_core::diff::Change::CreateRole {
                name: "app-svc".to_string(),
                state: pgroles_core::model::RoleState {
                    login: true,
                    ..pgroles_core::model::RoleState::default()
                },
            },
            pgroles_core::diff::Change::SetPassword {
                name: "app-svc".to_string(),
                password: "super_secret_p@ssw0rd!".to_string(),
            },
        ];

        let sql_ctx = pgroles_core::sql::SqlContext::default();
        let (sql, truncated) = render_plan_sql_for_status(&changes, &sql_ctx);

        let sql = sql.expect("expected non-empty planned SQL");
        assert!(!truncated);
        assert!(
            sql.contains("[REDACTED]"),
            "status SQL should contain [REDACTED], got: {sql}"
        );
        assert!(
            !sql.contains("super_secret_p@ssw0rd!"),
            "status SQL must NOT contain the actual password, got: {sql}"
        );
        assert!(
            sql.contains("CREATE ROLE"),
            "status SQL should still contain non-password changes, got: {sql}"
        );
    }

    #[test]
    fn render_plan_sql_for_status_empty_changes_returns_none() {
        let sql_ctx = pgroles_core::sql::SqlContext::default();
        let (sql, truncated) = render_plan_sql_for_status(&[], &sql_ctx);
        assert!(sql.is_none());
        assert!(!truncated);
    }

    #[test]
    fn render_plan_sql_for_status_password_only_plan() {
        let changes = vec![pgroles_core::diff::Change::SetPassword {
            name: "db-user".to_string(),
            password: "my_secret_pw".to_string(),
        }];

        let sql_ctx = pgroles_core::sql::SqlContext::default();
        let (sql, _) = render_plan_sql_for_status(&changes, &sql_ctx);

        let sql = sql.expect("expected non-empty planned SQL");
        assert!(
            sql.contains("[REDACTED]"),
            "password-only plan should still show redacted SQL"
        );
        assert!(
            !sql.contains("my_secret_pw"),
            "password-only plan must NOT leak the password"
        );
    }

    #[test]
    fn error_reason_empty_password_secret() {
        let err = ReconcileError::EmptyPasswordSecret {
            role: "app-svc".to_string(),
            secret: "pg-passwords".to_string(),
            key: "app-svc".to_string(),
        };
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn retry_classifies_empty_password_secret_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::EmptyPasswordSecret {
            role: "app-svc".to_string(),
            secret: "pg-passwords".to_string(),
            key: "app-svc".to_string(),
        });
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_password_generation() {
        let err = ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::MissingKey {
                secret: "my-secret".to_string(),
                key: "password".to_string(),
            },
        ));
        assert_eq!(err.reason(), "SecretFetchFailed");
    }

    #[test]
    fn retry_classifies_password_generation_missing_key_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::MissingKey {
                secret: "my-secret".to_string(),
                key: "password".to_string(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_password_generation_kube_server_error_as_transient() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::KubeApi {
                secret: "my-secret".to_string(),
                source: Box::new(kube::Error::Api(
                    kube::core::Status::failure("internal error", "InternalError")
                        .with_code(500)
                        .boxed(),
                )),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Transient);
    }

    #[test]
    fn retry_classifies_password_generation_kube_forbidden_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::KubeApi {
                secret: "my-secret".to_string(),
                source: Box::new(kube::Error::Api(
                    kube::core::Status::failure("forbidden", "Forbidden")
                        .with_code(403)
                        .boxed(),
                )),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn accumulate_summary_counts_passwords() {
        use pgroles_core::diff::Change;

        let mut summary = ChangeSummary::default();
        accumulate_summary(
            &mut summary,
            &Change::SetPassword {
                name: "app-svc".to_string(),
                password: "secret".to_string(),
            },
        );
        assert_eq!(summary.passwords_set, 1);
    }

    #[test]
    fn conflict_detection_ignores_invalid_peer_policies() {
        let resource = valid_role_policy("valid-policy", "analytics", "shared-db-secret");
        let identity = DatabaseIdentity::from_connection("default", &resource.spec.connection);
        let ownership = resource.spec.ownership_claims().unwrap();
        let invalid_peer = invalid_profile_policy("invalid-peer", "shared-db-secret");

        let conflict =
            detect_policy_conflict_in_list(&resource, &identity, &ownership, vec![invalid_peer]);

        assert_eq!(conflict, None);
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_supports_default_and_explicit_keys() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys(
                "role-passwords",
                &[
                    ("app", "app-secret"),
                    ("reporter-password", "reporter-secret"),
                ],
            ),
        )]);

        let resolved =
            resolve_passwords_from_cached_secrets(&resource, &cache).expect("should resolve");

        assert_eq!(
            resolved
                .get("app")
                .map(|password| password.cleartext.as_str()),
            Some("app-secret")
        );
        assert_eq!(
            resolved
                .get("reporter")
                .map(|password| password.cleartext.as_str()),
            Some("reporter-secret")
        );
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_reports_missing_key() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys("role-passwords", &[("app", "app-secret")]),
        )]);

        let err = resolve_passwords_from_cached_secrets(&resource, &cache).unwrap_err();
        let context = match err {
            ReconcileError::Context(context) => context,
            other => panic!("expected context error, got {other:?}"),
        };
        assert!(matches!(
            *context,
            crate::context::ContextError::SecretMissing { ref name, ref key }
            if name == "role-passwords" && key == "reporter-password"
        ));
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_reports_empty_password() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys(
                "role-passwords",
                &[("app", ""), ("reporter-password", "ok")],
            ),
        )]);

        let err = resolve_passwords_from_cached_secrets(&resource, &cache).unwrap_err();
        assert!(matches!(
            err,
            ReconcileError::EmptyPasswordSecret { ref role, ref secret, ref key }
            if role == "app" && secret == "role-passwords" && key == "app"
        ));
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_allows_whitespace_passwords() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys(
                "role-passwords",
                &[("app", "   "), ("reporter-password", "\tsecret")],
            ),
        )]);

        let resolved =
            resolve_passwords_from_cached_secrets(&resource, &cache).expect("should resolve");

        assert_eq!(
            resolved
                .get("app")
                .map(|password| password.cleartext.as_str()),
            Some("   ")
        );
        assert_eq!(
            resolved
                .get("reporter")
                .map(|password| password.cleartext.as_str()),
            Some("\tsecret")
        );
    }

    #[test]
    fn select_password_changes_skips_unchanged_password_sources() {
        let resolved = BTreeMap::from([(
            "app".to_string(),
            ResolvedPassword {
                cleartext: "app-secret".to_string(),
                source_version: "role-passwords:app:7".to_string(),
            },
        )]);
        let status = PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                "role-passwords:app:7".to_string(),
            )]),
            ..Default::default()
        };

        let (password_changes, current_versions) =
            select_password_changes(&[], &resolved, Some(&status));

        assert!(password_changes.is_empty());
        assert_eq!(
            current_versions.get("app").map(String::as_str),
            Some("role-passwords:app:7")
        );
    }

    #[test]
    fn select_password_changes_applies_on_source_version_change() {
        let resolved = BTreeMap::from([(
            "app".to_string(),
            ResolvedPassword {
                cleartext: "new-secret".to_string(),
                source_version: "role-passwords:app:8".to_string(),
            },
        )]);
        let status = PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                "role-passwords:app:7".to_string(),
            )]),
            ..Default::default()
        };

        let (password_changes, _) = select_password_changes(&[], &resolved, Some(&status));

        assert_eq!(
            password_changes.get("app").map(String::as_str),
            Some("new-secret")
        );
    }

    #[test]
    fn select_password_changes_applies_for_newly_created_role() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let resolved = BTreeMap::from([(
            "app".to_string(),
            ResolvedPassword {
                cleartext: "new-secret".to_string(),
                source_version: "role-passwords:app:7".to_string(),
            },
        )]);
        let status = PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                "role-passwords:app:7".to_string(),
            )]),
            ..Default::default()
        };
        let changes = vec![Change::CreateRole {
            name: "app".to_string(),
            state: RoleState {
                login: true,
                ..RoleState::default()
            },
        }];

        let (password_changes, _) = select_password_changes(&changes, &resolved, Some(&status));

        assert_eq!(
            password_changes.get("app").map(String::as_str),
            Some("new-secret")
        );
    }

    #[test]
    fn select_password_changes_applies_all_on_first_reconcile() {
        // When status is None (first reconcile), all passwords should be applied
        // since there are no previous source versions to compare against.
        let resolved = BTreeMap::from([
            (
                "app".to_string(),
                ResolvedPassword {
                    cleartext: "secret-a".to_string(),
                    source_version: "role-passwords:app:1".to_string(),
                },
            ),
            (
                "reporter".to_string(),
                ResolvedPassword {
                    cleartext: "secret-b".to_string(),
                    source_version: "role-passwords:reporter:1".to_string(),
                },
            ),
        ]);
        let changes: Vec<pgroles_core::diff::Change> = vec![];

        let (password_changes, versions) = select_password_changes(&changes, &resolved, None);

        assert_eq!(
            password_changes.len(),
            2,
            "all passwords should be applied on first reconcile"
        );
        assert_eq!(
            password_changes.get("app").map(String::as_str),
            Some("secret-a")
        );
        assert_eq!(
            password_changes.get("reporter").map(String::as_str),
            Some("secret-b")
        );
        assert_eq!(versions.len(), 2, "all source versions should be tracked");
    }

    #[test]
    fn conflict_detection_still_reports_overlapping_valid_peers() {
        let resource = valid_role_policy("valid-policy", "analytics", "shared-db-secret");
        let identity = DatabaseIdentity::from_connection("default", &resource.spec.connection);
        let ownership = resource.spec.ownership_claims().unwrap();
        let overlapping_peer =
            valid_role_policy("overlapping-peer", "analytics", "shared-db-secret");
        let invalid_peer = invalid_profile_policy("invalid-peer", "shared-db-secret");

        let conflict = detect_policy_conflict_in_list(
            &resource,
            &identity,
            &ownership,
            vec![invalid_peer, overlapping_peer],
        );

        let conflict = conflict.expect("expected overlapping peer to be reported");
        assert!(conflict.contains("overlapping-peer"));
        assert!(conflict.contains("roles: analytics"));
    }

    #[test]
    fn parse_rfc3339_to_epoch_secs_known_timestamp() {
        // 2024-01-01T00:00:00Z = 1704067200
        let result = parse_rfc3339_to_epoch_secs("2024-01-01T00:00:00Z");
        assert_eq!(result, Some(1704067200));
    }

    #[test]
    fn parse_rfc3339_to_epoch_secs_with_time() {
        // 2024-01-01T12:30:45Z = 1704067200 + 12*3600 + 30*60 + 45 = 1704112245
        let result = parse_rfc3339_to_epoch_secs("2024-01-01T12:30:45Z");
        assert_eq!(result, Some(1704112245));
    }

    #[test]
    fn parse_rfc3339_to_epoch_secs_invalid_returns_none() {
        assert_eq!(parse_rfc3339_to_epoch_secs("not-a-date"), None);
        assert_eq!(parse_rfc3339_to_epoch_secs(""), None);
    }

    #[test]
    fn parse_rfc3339_roundtrips_with_now_rfc3339() {
        let timestamp = crate::crd::now_rfc3339();
        let parsed = parse_rfc3339_to_epoch_secs(&timestamp);
        assert!(parsed.is_some(), "should parse our own timestamps");
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Should be within 2 seconds of now.
        let diff = now_secs.abs_diff(parsed.unwrap());
        assert!(diff <= 2, "parsed time should be close to now, diff={diff}");
    }
}
