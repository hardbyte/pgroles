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

use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event as FinalizerEvent};
use tracing::info;

use crate::context::{ContextError, OperatorContext};
use crate::crd::{
    ChangeSummary, DatabaseIdentity, PostgresPolicy, PostgresPolicyStatus, conflict_condition,
    degraded_condition, paused_condition, ready_condition, reconciling_condition,
};

/// Finalizer name for PostgresPolicy resources.
const FINALIZER: &str = "pgroles.io/finalizer";

/// Default requeue interval when no interval is specified on the CR.
const DEFAULT_REQUEUE_SECS: u64 = 300; // 5 minutes

/// Base requeue delay when lock contention is detected.
const LOCK_CONTENTION_BASE_SECS: u64 = 10;

/// Maximum jitter added to the base requeue delay on lock contention.
const LOCK_CONTENTION_JITTER_SECS: u64 = 20;

enum ReconcileOutcome {
    Reconciled,
    Suspended,
    Conflict,
    LockContention,
}

impl ReconcileOutcome {
    fn result(&self) -> &'static str {
        match self {
            ReconcileOutcome::Reconciled => "success",
            ReconcileOutcome::Suspended => "suspended",
            ReconcileOutcome::Conflict => "conflict",
            ReconcileOutcome::LockContention => "contention",
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            ReconcileOutcome::Reconciled => "Reconciled",
            ReconcileOutcome::Suspended => "Suspended",
            ReconcileOutcome::Conflict => "ConflictingPolicy",
            ReconcileOutcome::LockContention => "LockContention",
        }
    }
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

    #[error("{0}")]
    ConflictingPolicy(String),

    #[error("lock contention on database \"{0}\": {1}")]
    LockContention(String, String),
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
    _resource: Arc<PostgresPolicy>,
    error: &finalizer::Error<ReconcileError>,
    _ctx: Arc<OperatorContext>,
) -> Action {
    // Lock contention is expected and should not be logged as an error.
    if let finalizer::Error::ApplyFailed(ReconcileError::LockContention(db, reason)) = error {
        tracing::info!(database = %db, reason = %reason, "requeuing due to lock contention");
        return requeue_with_jitter();
    }
    tracing::error!(%error, "reconciliation failed, requeuing in 60s");
    Action::requeue(Duration::from_secs(60))
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
    let identity = DatabaseIdentity::new(
        &namespace,
        &resource.spec.connection.secret_ref.name,
        &resource.spec.connection.secret_key,
    );

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
            match error_reason {
                "DatabaseConnectionFailed" => {
                    ctx.observability.record_database_connection_failure()
                }
                "InvalidSpec" => ctx.observability.record_invalid_spec(),
                "ConflictingPolicy" => ctx.observability.record_policy_conflict(),
                "ApplyFailed" => ctx.observability.record_apply_result("error"),
                _ => {}
            }
            reconcile_guard.record_result("error", error_reason);
            if let Err(status_err) = update_status(ctx, resource, |status| {
                status.set_condition(ready_condition(false, error_reason, &error_message));
                status.set_condition(degraded_condition(error_reason, &error_message));
                status
                    .conditions
                    .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Paused");
                status.change_summary = None;
                status.last_error = Some(error_message.clone());
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
                .retain(|c| c.condition_type != "Reconciling");
            status.last_attempted_generation = generation;
            status.last_error = None;
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
    update_status(ctx, resource, |status| {
        status.set_condition(reconciling_condition("Reconciliation in progress"));
        status.conditions.retain(|c| c.condition_type != "Paused");
        status.last_attempted_generation = generation;
        status.last_error = None;
    })
    .await?;

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
                .retain(|c| c.condition_type != "Reconciling");
            status.change_summary = None;
            status.last_error = Some(conflict_message.clone());
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
        .get_or_create_pool(
            &namespace,
            &spec.connection.secret_ref.name,
            &spec.connection.secret_key,
        )
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
    )
    .await;

    // Release advisory lock (always, even on error).
    advisory_lock.release().await;

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
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    // 6. Inspect current state from the database.
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|g| g.on.object_type == pgroles_core::manifest::ObjectType::Database);
    let inspect_config =
        pgroles_inspect::InspectConfig::from_expanded(expanded, has_database_grants)
            .with_additional_roles(
                manifest
                    .retirements
                    .iter()
                    .map(|retirement| retirement.role.clone()),
            );
    let current = pgroles_inspect::inspect(pool, &inspect_config).await?;

    // 7. Compute diff.
    let changes = pgroles_core::diff::apply_role_retirements(
        pgroles_core::diff::diff(&current, desired),
        &manifest.retirements,
    );
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

    // 8. Apply changes.
    let mut summary = ChangeSummary::default();

    if changes.is_empty() {
        info!(name, namespace, "no changes needed");
    } else {
        info!(name, namespace, count = changes.len(), "applying changes");

        let mut transaction = pool.begin().await?;
        let mut statements_executed = 0usize;
        for change in &changes {
            for sql in pgroles_core::sql::render_statements(change) {
                tracing::debug!(%sql, "executing");
                sqlx::query(&sql).execute(transaction.as_mut()).await?;
                statements_executed += 1;
            }
            accumulate_summary(&mut summary, change);
        }
        transaction.commit().await?;
        ctx.observability.record_apply_result("success");
        ctx.observability
            .record_apply_statements(statements_executed);

        summary.total = summary.roles_created
            + summary.roles_altered
            + summary.roles_dropped
            + summary.sessions_terminated
            + summary.grants_added
            + summary.grants_revoked
            + summary.default_privileges_set
            + summary.default_privileges_revoked
            + summary.members_added
            + summary.members_removed;

        info!(
            name,
            namespace,
            total = summary.total,
            "reconciliation complete"
        );
    }

    // 9. Update status to Ready.
    update_status(ctx, resource, |status| {
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
        // Clear any previous "Reconciling" or "Degraded" conditions.
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
        status.last_error = None;
    })
    .await?;

    Ok((
        Action::requeue(requeue_interval),
        ReconcileOutcome::Reconciled,
    ))
}

/// Cleanup on deletion — evict cached pool.
async fn reconcile_cleanup(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
) -> Result<Action, ReconcileError> {
    let name = resource.name_any();
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;

    info!(name, namespace, "cleaning up (resource deleted)");

    // Evict any cached pool for this resource's secret.
    ctx.evict_pool(
        &namespace,
        &resource.spec.connection.secret_ref.name,
        &resource.spec.connection.secret_key,
    )
    .await;

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
        Change::AlterRole { .. } => summary.roles_altered += 1,
        Change::SetComment { .. } => summary.roles_altered += 1,
        Change::DropRole { .. } => summary.roles_dropped += 1,
        Change::TerminateSessions { .. } => summary.sessions_terminated += 1,
        Change::ReassignOwned { .. } => {}
        Change::DropOwned { .. } => {}
        Change::Grant { .. } => summary.grants_added += 1,
        Change::Revoke { .. } => summary.grants_revoked += 1,
        Change::SetDefaultPrivilege { .. } => summary.default_privileges_set += 1,
        Change::RevokeDefaultPrivilege { .. } => summary.default_privileges_revoked += 1,
        Change::AddMember { .. } => summary.members_added += 1,
        Change::RemoveMember { .. } => summary.members_removed += 1,
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
    let mut status = latest.status.unwrap_or_default();

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

    let this_ns = resource.namespace().ok_or(ReconcileError::NoNamespace)?;
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

        let other_identity = DatabaseIdentity::new(
            &other_ns,
            &other.spec.connection.secret_ref.name,
            &other.spec.connection.secret_key,
        );
        if &other_identity != identity {
            continue;
        }

        let other_ownership = other.spec.ownership_claims()?;
        if ownership.overlaps(&other_ownership) {
            let overlap = ownership.overlap_summary(&other_ownership);
            conflicts.push(format!("{other_ns}/{other_name} ({overlap})"));
        }
    }

    if conflicts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(format!(
            "policy ownership overlaps with {} on database target {}",
            conflicts.join(", "),
            identity.as_str()
        )))
    }
}

impl ReconcileError {
    fn reason(&self) -> &'static str {
        match self {
            ReconcileError::ManifestExpansion(_) | ReconcileError::InvalidInterval(_, _) => {
                "InvalidSpec"
            }
            ReconcileError::ConflictingPolicy(_) => "ConflictingPolicy",
            ReconcileError::LockContention(_, _) => "LockContention",
            ReconcileError::Context(context) => match context.as_ref() {
                ContextError::SecretFetch { .. } => "SecretFetchFailed",
                ContextError::SecretMissing { .. } => "SecretMissing",
                ContextError::DatabaseConnect { .. } => "DatabaseConnectionFailed",
            },
            ReconcileError::Inspect(_) => "DatabaseInspectionFailed",
            ReconcileError::SqlExec(_) => "ApplyFailed",
            ReconcileError::UnsafeRoleDrops(_) => "UnsafeRoleDrops",
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
}
