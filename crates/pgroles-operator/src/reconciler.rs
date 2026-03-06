//! Reconciliation logic for `PostgresPolicy` custom resources.
//!
//! Implements the core reconcile loop: read desired state from the CR,
//! inspect current state from the database, compute diff, and apply changes.

use std::sync::Arc;
use std::time::Duration;

use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event as FinalizerEvent};
use tracing::info;

use crate::context::{ContextError, OperatorContext};
use crate::crd::{
    ChangeSummary, PostgresPolicy, PostgresPolicyStatus, degraded_condition, ready_condition,
    reconciling_condition,
};

/// Finalizer name for PostgresPolicy resources.
const FINALIZER: &str = "pgroles.io/finalizer";

/// Default requeue interval when no interval is specified on the CR.
const DEFAULT_REQUEUE_SECS: u64 = 300; // 5 minutes

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
    tracing::error!(%error, "reconciliation failed, requeuing in 60s");
    Action::requeue(Duration::from_secs(60))
}

/// Apply reconciliation — the main "ensure desired state" logic.
async fn reconcile_apply(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
) -> Result<Action, ReconcileError> {
    match reconcile_apply_inner(resource, ctx).await {
        Ok(action) => Ok(action),
        Err(err) => {
            let error_message = err.to_string();
            if let Err(status_err) = update_status(ctx, resource, |status| {
                status.set_condition(ready_condition(false, "ReconcileFailed", &error_message));
                status.set_condition(degraded_condition("ReconcileFailed", &error_message));
                status
                    .conditions
                    .retain(|c| c.condition_type != "Reconciling");
                status.change_summary = None;
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
) -> Result<Action, ReconcileError> {
    let name = resource.name_any();
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;

    let spec = &resource.spec;
    let requeue_interval = parse_interval(&spec.interval)?;

    // If suspended, just requeue without doing anything.
    if spec.suspend {
        info!(name, namespace, "reconciliation suspended, requeuing");
        return Ok(Action::requeue(requeue_interval));
    }

    info!(name, namespace, "starting reconciliation");

    // Update status to "Reconciling".
    update_status(ctx, resource, |status| {
        status.set_condition(reconciling_condition("Reconciliation in progress"));
    })
    .await?;

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

    // 5. Inspect current state from the database.
    // Check if any grants target "database" type to decide whether to include database privileges.
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|g| g.on.object_type == pgroles_core::manifest::ObjectType::Database);
    let inspect_config =
        pgroles_inspect::InspectConfig::from_expanded(&expanded, has_database_grants);
    let current = pgroles_inspect::inspect(&pool, &inspect_config).await?;

    // 6. Compute diff.
    let changes = pgroles_core::diff::diff(&current, &desired);
    let dropped_roles: Vec<String> = changes
        .iter()
        .filter_map(|change| match change {
            pgroles_core::diff::Change::DropRole { name } => Some(name.clone()),
            _ => None,
        })
        .collect();
    let drop_safety = pgroles_inspect::inspect_drop_role_safety(&pool, &dropped_roles).await?;
    if !drop_safety.is_empty() {
        return Err(ReconcileError::UnsafeRoleDrops(drop_safety.to_string()));
    }

    // 7. Apply changes.
    let mut summary = ChangeSummary::default();

    if changes.is_empty() {
        info!(name, namespace, "no changes needed");
    } else {
        info!(name, namespace, count = changes.len(), "applying changes");

        let mut transaction = pool.begin().await?;
        for change in &changes {
            for sql in pgroles_core::sql::render_statements(change) {
                tracing::debug!(%sql, "executing");
                sqlx::query(&sql).execute(transaction.as_mut()).await?;
            }
            accumulate_summary(&mut summary, change);
        }
        transaction.commit().await?;

        summary.total = summary.roles_created
            + summary.roles_altered
            + summary.roles_dropped
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

    // 8. Update status to Ready.
    let generation = resource.metadata.generation;
    update_status(ctx, resource, |status| {
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
        // Clear any previous "Reconciling" or "Degraded" conditions.
        status
            .conditions
            .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Degraded");
        status.observed_generation = generation;
        status.last_reconcile_time = Some(crate::crd::now_rfc3339());
        status.change_summary = Some(summary);
    })
    .await?;

    Ok(Action::requeue(requeue_interval))
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

    let mut status = resource.status.clone().unwrap_or_default();

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

        assert_eq!(summary.roles_created, 1);
        assert_eq!(summary.grants_added, 1);
    }
}
