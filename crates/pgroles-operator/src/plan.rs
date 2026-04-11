//! Plan lifecycle management for `PostgresPolicyPlan` resources.
//!
//! Handles creating, deduplicating, approving, executing, and cleaning up
//! reconciliation plans. Plans represent computed SQL change sets that may
//! require explicit approval before execution against a database.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::{Client, Resource, ResourceExt};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::crd::{
    ChangeSummary, CrdReconciliationMode, LABEL_DATABASE_IDENTITY, LABEL_POLICY,
    PLAN_APPROVED_ANNOTATION, PLAN_REJECTED_ANNOTATION, PlanPhase, PlanReference, PolicyCondition,
    PolicyPlanRef, PostgresPolicy, PostgresPolicyPlan, PostgresPolicyPlanSpec,
    PostgresPolicyPlanStatus, SqlRef,
};
use crate::reconciler::ReconcileError;

/// Maximum inline SQL size in plan status before spilling to a ConfigMap.
const MAX_INLINE_SQL_BYTES: usize = 16 * 1024;

/// ConfigMap data key for the SQL content.
const SQL_CONFIGMAP_KEY: &str = "plan.sql";

/// Default maximum number of historical plans to retain per policy.
const DEFAULT_MAX_PLANS: usize = 10;

// ---------------------------------------------------------------------------
// Plan approval check
// ---------------------------------------------------------------------------

/// Result of checking a plan's approval annotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanApprovalState {
    Pending,
    Approved,
    Rejected,
}

/// Check the approval state of a plan by inspecting its annotations.
///
/// Rejection takes priority over approval: if both annotations are set,
/// the plan is considered rejected.
pub fn check_plan_approval(plan: &PostgresPolicyPlan) -> PlanApprovalState {
    let annotations = plan.metadata.annotations.as_ref();

    let rejected = annotations
        .and_then(|a| a.get(PLAN_REJECTED_ANNOTATION))
        .map(|v| v == "true")
        .unwrap_or(false);

    if rejected {
        return PlanApprovalState::Rejected;
    }

    let approved = annotations
        .and_then(|a| a.get(PLAN_APPROVED_ANNOTATION))
        .map(|v| v == "true")
        .unwrap_or(false);

    if approved {
        return PlanApprovalState::Approved;
    }

    PlanApprovalState::Pending
}

// ---------------------------------------------------------------------------
// Plan creation
// ---------------------------------------------------------------------------

/// Create or deduplicate a `PostgresPolicyPlan` for the given policy and changes.
///
/// Returns the name of the plan resource (either existing or newly created).
///
/// This function:
/// 1. Renders the full executable SQL from the changes
/// 2. Computes SHA-256 of the full SQL (before any redaction/truncation)
/// 3. Checks for an existing Pending plan with the same hash (dedup)
/// 4. Marks any existing Pending plan with a different hash as Superseded
/// 5. Creates the new plan resource with ownerReferences
/// 6. Creates a ConfigMap for large SQL, or stores inline
/// 7. Updates the plan status
#[allow(clippy::too_many_arguments)]
pub async fn create_or_update_plan(
    client: &Client,
    policy: &PostgresPolicy,
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
    inspect_config: &pgroles_inspect::InspectConfig,
    reconciliation_mode: CrdReconciliationMode,
    database_identity: &str,
    change_summary: &ChangeSummary,
) -> Result<String, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();
    let generation = policy.metadata.generation.unwrap_or(0);

    // 1. Render the full executable SQL (not redacted).
    let full_sql = render_full_sql(changes, sql_context);

    // 2. Compute SHA-256 hash of the full SQL.
    let sql_hash = compute_sql_hash(&full_sql);

    // 3. Render redacted SQL for display (passwords masked).
    let redacted_sql = render_redacted_sql(changes, sql_context);

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    // 4. List existing plans for this policy.
    let label_selector = format!("{LABEL_POLICY}={policy_name}");
    let existing_plans = plans_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;

    // 5. Check for duplicate pending plan with same hash.
    for plan in &existing_plans {
        if let Some(ref status) = plan.status
            && status.phase == PlanPhase::Pending
            && status.sql_hash.as_deref() == Some(&sql_hash)
        {
            // Identical plan already exists — return early.
            let plan_name = plan.name_any();
            info!(
                plan = %plan_name,
                policy = %policy_name,
                "existing pending plan has identical SQL hash, skipping creation"
            );
            return Ok(plan_name);
        }
    }

    // 6. Mark any existing Pending plans as Superseded.
    for plan in &existing_plans {
        if let Some(ref status) = plan.status
            && status.phase == PlanPhase::Pending
        {
            let plan_name = plan.name_any();
            info!(
                plan = %plan_name,
                policy = %policy_name,
                "marking existing pending plan as Superseded"
            );
            let superseded_status = PostgresPolicyPlanStatus {
                phase: PlanPhase::Superseded,
                ..status.clone()
            };
            let patch = serde_json::json!({ "status": superseded_status });
            plans_api
                .patch_status(
                    &plan_name,
                    &PatchParams::apply("pgroles-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;
        }
    }

    // 7. Generate a unique plan name using a timestamp.
    let plan_name = generate_plan_name(&policy_name);

    // 8. Build ownerReference pointing to the parent policy.
    let owner_ref = build_owner_reference(policy);

    // 9. Create the plan resource.
    let plan = PostgresPolicyPlan::new(
        &plan_name,
        PostgresPolicyPlanSpec {
            policy_ref: PolicyPlanRef {
                name: policy_name.clone(),
            },
            policy_generation: generation,
            reconciliation_mode,
            owned_roles: inspect_config.managed_roles.clone(),
            owned_schemas: inspect_config.managed_schemas.clone(),
            managed_database_identity: database_identity.to_string(),
        },
    );
    let mut plan = plan;
    plan.metadata.namespace = Some(namespace.clone());
    plan.metadata.owner_references = Some(vec![owner_ref.clone()]);
    plan.metadata.labels = Some(BTreeMap::from([
        (LABEL_POLICY.to_string(), policy_name.clone()),
        (
            LABEL_DATABASE_IDENTITY.to_string(),
            sanitize_label_value(database_identity),
        ),
    ]));

    let created_plan = plans_api.create(&PostParams::default(), &plan).await?;
    let plan_name = created_plan.name_any();

    // 10. Handle SQL storage: inline or ConfigMap.
    let (sql_inline, sql_ref) = if redacted_sql.len() <= MAX_INLINE_SQL_BYTES {
        (Some(redacted_sql), None)
    } else {
        // Create a ConfigMap for the full redacted SQL.
        let configmap_name = format!("{plan_name}-sql");
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(configmap_name.clone()),
                namespace: Some(namespace.clone()),
                owner_references: Some(vec![build_plan_owner_reference(&created_plan)]),
                labels: Some(BTreeMap::from([(
                    LABEL_POLICY.to_string(),
                    policy_name.clone(),
                )])),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                SQL_CONFIGMAP_KEY.to_string(),
                redacted_sql,
            )])),
            ..Default::default()
        };

        let configmaps_api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
        configmaps_api
            .create(&PostParams::default(), &configmap)
            .await?;

        (
            None,
            Some(SqlRef {
                name: configmap_name,
                key: SQL_CONFIGMAP_KEY.to_string(),
            }),
        )
    };

    // 11. Update plan status.
    let plan_status = PostgresPolicyPlanStatus {
        phase: PlanPhase::Pending,
        conditions: vec![
            PolicyCondition {
                condition_type: "Computed".to_string(),
                status: "True".to_string(),
                reason: Some("PlanComputed".to_string()),
                message: Some(format!(
                    "Plan computed with {} change(s)",
                    change_summary.total
                )),
                last_transition_time: Some(crate::crd::now_rfc3339()),
            },
            PolicyCondition {
                condition_type: "Approved".to_string(),
                status: "False".to_string(),
                reason: Some("PendingApproval".to_string()),
                message: Some("Plan awaiting approval".to_string()),
                last_transition_time: Some(crate::crd::now_rfc3339()),
            },
        ],
        change_summary: Some(change_summary.clone()),
        sql_ref,
        sql_inline,
        computed_at: Some(crate::crd::now_rfc3339()),
        applied_at: None,
        last_error: None,
        sql_hash: Some(sql_hash),
    };

    let status_patch = serde_json::json!({ "status": plan_status });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&status_patch),
        )
        .await?;

    info!(
        plan = %plan_name,
        policy = %policy_name,
        changes = change_summary.total,
        "created new plan"
    );

    Ok(plan_name)
}

// ---------------------------------------------------------------------------
// Plan execution
// ---------------------------------------------------------------------------

/// Execute an approved plan against the database.
///
/// Reads SQL from inline status or the referenced ConfigMap, executes it in
/// a transaction, and updates the plan status to Applied or Failed.
pub async fn execute_plan(
    client: &Client,
    plan: &PostgresPolicyPlan,
    pool: &sqlx::PgPool,
    sql_context: &pgroles_core::sql::SqlContext,
    changes: &[pgroles_core::diff::Change],
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    // Update phase to Applying.
    update_plan_phase(&plans_api, &plan_name, PlanPhase::Applying).await?;

    // Execute the SQL in a transaction using the original changes (not stored SQL).
    // This ensures we use the actual executable SQL including real passwords,
    // not the redacted version stored in the plan.
    let result = execute_changes_in_transaction(pool, changes, sql_context).await;

    match result {
        Ok(statements_executed) => {
            // Update plan status to Applied.
            let mut applied_status = plan.status.clone().unwrap_or_default();
            applied_status.phase = PlanPhase::Applied;
            applied_status.applied_at = Some(crate::crd::now_rfc3339());
            applied_status.last_error = None;
            set_plan_condition(
                &mut applied_status.conditions,
                "Approved",
                "True",
                "Approved",
                "Plan approved and executed",
            );

            let patch = serde_json::json!({ "status": applied_status });
            plans_api
                .patch_status(
                    &plan_name,
                    &PatchParams::apply("pgroles-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;

            info!(
                plan = %plan_name,
                statements = statements_executed,
                "plan executed successfully"
            );
            Ok(())
        }
        Err(err) => {
            // Update plan status to Failed.
            let error_message = err.to_string();
            let mut failed_status = plan.status.clone().unwrap_or_default();
            failed_status.phase = PlanPhase::Failed;
            failed_status.last_error = Some(error_message);

            let patch = serde_json::json!({ "status": failed_status });
            if let Err(status_err) = plans_api
                .patch_status(
                    &plan_name,
                    &PatchParams::apply("pgroles-operator"),
                    &Patch::Merge(&patch),
                )
                .await
            {
                tracing::warn!(
                    plan = %plan_name,
                    %status_err,
                    "failed to update plan status to Failed"
                );
            }

            Err(err)
        }
    }
}

/// Execute SQL changes in a database transaction.
///
/// Returns the number of statements executed on success.
async fn execute_changes_in_transaction(
    pool: &sqlx::PgPool,
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
) -> Result<usize, ReconcileError> {
    let mut transaction = pool.begin().await?;
    let mut statements_executed = 0usize;

    for change in changes {
        let is_sensitive = matches!(change, pgroles_core::diff::Change::SetPassword { .. });
        for sql in pgroles_core::sql::render_statements_with_context(change, sql_context) {
            if is_sensitive {
                tracing::debug!("executing: ALTER ROLE ... PASSWORD [REDACTED]");
            } else {
                tracing::debug!(%sql, "executing");
            }
            sqlx::query(&sql).execute(transaction.as_mut()).await?;
            statements_executed += 1;
        }
    }

    transaction.commit().await?;
    Ok(statements_executed)
}

// ---------------------------------------------------------------------------
// Plan cleanup / retention
// ---------------------------------------------------------------------------

/// Clean up old plans for a policy, retaining at most `max_plans` terminal plans.
///
/// Terminal plans are those in Applied, Failed, Superseded, or Rejected phase.
/// Pending and Approved plans are never cleaned up by this function.
pub async fn cleanup_old_plans(
    client: &Client,
    policy: &PostgresPolicy,
    max_plans: Option<usize>,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();
    let max_plans = max_plans.unwrap_or(DEFAULT_MAX_PLANS);

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let label_selector = format!("{LABEL_POLICY}={policy_name}");
    let existing_plans = plans_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;

    // Collect terminal plans sorted by creation timestamp (oldest first).
    let mut terminal_plans: Vec<&PostgresPolicyPlan> = existing_plans
        .iter()
        .filter(|plan| {
            plan.status
                .as_ref()
                .map(|s| {
                    matches!(
                        s.phase,
                        PlanPhase::Applied
                            | PlanPhase::Failed
                            | PlanPhase::Superseded
                            | PlanPhase::Rejected
                    )
                })
                .unwrap_or(false)
        })
        .collect();

    if terminal_plans.len() <= max_plans {
        return Ok(());
    }

    // Sort by creation timestamp ascending (oldest first).
    terminal_plans.sort_by(|a, b| {
        let a_time = a.metadata.creation_timestamp.as_ref();
        let b_time = b.metadata.creation_timestamp.as_ref();
        a_time.cmp(&b_time)
    });

    let plans_to_delete = terminal_plans.len() - max_plans;
    for plan in terminal_plans.into_iter().take(plans_to_delete) {
        let plan_name = plan.name_any();
        info!(
            plan = %plan_name,
            policy = %policy_name,
            "cleaning up old plan"
        );
        if let Err(err) = plans_api.delete(&plan_name, &Default::default()).await {
            tracing::warn!(
                plan = %plan_name,
                %err,
                "failed to delete old plan during cleanup"
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render the full executable SQL from changes (including real passwords).
pub(crate) fn render_full_sql(
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
) -> String {
    changes
        .iter()
        .flat_map(|change| pgroles_core::sql::render_statements_with_context(change, sql_context))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render redacted SQL for display (passwords replaced with [REDACTED]).
fn render_redacted_sql(
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
) -> String {
    changes
        .iter()
        .flat_map(|change| {
            if let pgroles_core::diff::Change::SetPassword { name, .. } = change {
                vec![format!(
                    "ALTER ROLE {} PASSWORD '[REDACTED]';",
                    pgroles_core::sql::quote_ident(name)
                )]
            } else {
                pgroles_core::sql::render_statements_with_context(change, sql_context)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compute SHA-256 hash of the SQL string as a hex digest.
pub(crate) fn compute_sql_hash(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate a plan name from policy name and current timestamp.
///
/// Format: `{policy-name}-plan-{YYYYMMDD-HHMMSS}-{millis}{random}`
///
/// A millisecond and random suffix is appended to avoid collisions when the
/// operator retries within the same second.
fn generate_plan_name(policy_name: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let timestamp = format_timestamp_compact();
    let millis = now.subsec_millis();
    let random_suffix: u32 = rand::random::<u32>() % 1000;
    let suffix = format!("{millis:03}{random_suffix:03}");
    // Kubernetes names must be <= 253 chars and DNS-compatible.
    // Truncate policy name if needed to leave room for suffix.
    let max_prefix_len = 253 - "-plan-".len() - timestamp.len() - "-".len() - suffix.len();
    let prefix = if policy_name.len() > max_prefix_len {
        &policy_name[..max_prefix_len]
    } else {
        policy_name
    };
    format!("{prefix}-plan-{timestamp}-{suffix}")
}

/// Format the current UTC time as `YYYYMMDD-HHMMSS`.
fn format_timestamp_compact() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (year, month, day) = crate::crd::days_to_date(secs / 86400);
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    format!("{year:04}{month:02}{day:02}-{hours:02}{minutes:02}{seconds:02}")
}

/// Sanitize a string for use as a Kubernetes label value.
///
/// Label values must be <= 63 chars and match `[a-z0-9A-Z._-]*`.
fn sanitize_label_value(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(63)
        .collect();
    sanitized
}

/// Build an OwnerReference pointing from a plan to its parent policy.
fn build_owner_reference(policy: &PostgresPolicy) -> OwnerReference {
    OwnerReference {
        api_version: PostgresPolicy::api_version(&()).to_string(),
        kind: PostgresPolicy::kind(&()).to_string(),
        name: policy.name_any(),
        uid: policy.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Build an OwnerReference pointing from a ConfigMap to its parent plan.
fn build_plan_owner_reference(plan: &PostgresPolicyPlan) -> OwnerReference {
    OwnerReference {
        api_version: PostgresPolicyPlan::api_version(&()).to_string(),
        kind: PostgresPolicyPlan::kind(&()).to_string(),
        name: plan.name_any(),
        uid: plan.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Update the phase field on a plan's status.
async fn update_plan_phase(
    plans_api: &Api<PostgresPolicyPlan>,
    plan_name: &str,
    phase: PlanPhase,
) -> Result<(), ReconcileError> {
    let patch = serde_json::json!({
        "status": {
            "phase": phase
        }
    });
    plans_api
        .patch_status(
            plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

/// Set or update a condition in a conditions list.
fn set_plan_condition(
    conditions: &mut Vec<PolicyCondition>,
    condition_type: &str,
    status: &str,
    reason: &str,
    message: &str,
) {
    let condition = PolicyCondition {
        condition_type: condition_type.to_string(),
        status: status.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(crate::crd::now_rfc3339()),
    };
    if let Some(existing) = conditions
        .iter_mut()
        .find(|c| c.condition_type == condition_type)
    {
        *existing = condition;
    } else {
        conditions.push(condition);
    }
}

/// Update the parent policy's `current_plan_ref` in status.
pub async fn update_policy_plan_ref(
    client: &Client,
    policy: &PostgresPolicy,
    plan_name: &str,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_api: Api<PostgresPolicy> = Api::namespaced(client.clone(), &namespace);

    let patch = serde_json::json!({
        "status": {
            "current_plan_ref": PlanReference {
                name: plan_name.to_string(),
            }
        }
    });

    policy_api
        .patch_status(
            &policy.name_any(),
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

/// Look up the current pending plan for a policy, if any.
pub async fn get_current_pending_plan(
    client: &Client,
    policy: &PostgresPolicy,
) -> Result<Option<PostgresPolicyPlan>, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let label_selector = format!("{LABEL_POLICY}={policy_name}");
    let existing_plans = plans_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;

    // Find the most recent pending plan (by creation time).
    let mut pending_plans: Vec<PostgresPolicyPlan> = existing_plans
        .into_iter()
        .filter(|plan| {
            plan.status
                .as_ref()
                .map(|s| s.phase == PlanPhase::Pending)
                .unwrap_or(false)
        })
        .collect();

    pending_plans.sort_by(|a, b| {
        let a_time = a.metadata.creation_timestamp.as_ref();
        let b_time = b.metadata.creation_timestamp.as_ref();
        b_time.cmp(&a_time) // newest first
    });

    Ok(pending_plans.into_iter().next())
}

/// Look up the most recent plan for a policy in a given phase.
pub async fn get_plan_by_phase(
    client: &Client,
    policy: &PostgresPolicy,
    target_phase: PlanPhase,
) -> Result<Option<PostgresPolicyPlan>, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let label_selector = format!("{LABEL_POLICY}={policy_name}");
    let existing_plans = plans_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;

    let mut matching_plans: Vec<PostgresPolicyPlan> = existing_plans
        .into_iter()
        .filter(|plan| {
            plan.status
                .as_ref()
                .map(|s| s.phase == target_phase)
                .unwrap_or(false)
        })
        .collect();

    matching_plans.sort_by(|a, b| {
        let a_time = a.metadata.creation_timestamp.as_ref();
        let b_time = b.metadata.creation_timestamp.as_ref();
        b_time.cmp(&a_time) // newest first
    });

    Ok(matching_plans.into_iter().next())
}

/// Mark a plan as Failed with a given error message.
pub async fn mark_plan_failed(
    client: &Client,
    plan: &PostgresPolicyPlan,
    error_message: &str,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let mut status = plan.status.clone().unwrap_or_default();
    status.phase = PlanPhase::Failed;
    status.last_error = Some(error_message.to_string());

    let patch = serde_json::json!({ "status": status });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    info!(
        plan = %plan_name,
        "marked stuck Applying plan as Failed"
    );

    Ok(())
}

/// Mark a plan as Approved (by the operator, for auto-approval flows).
pub async fn mark_plan_approved(
    client: &Client,
    plan: &PostgresPolicyPlan,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let mut status = plan.status.clone().unwrap_or_default();
    status.phase = PlanPhase::Approved;
    set_plan_condition(
        &mut status.conditions,
        "Approved",
        "True",
        "AutoApproved",
        "Plan auto-approved by policy approval mode",
    );

    let patch = serde_json::json!({ "status": status });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

/// Mark a plan as Rejected.
pub async fn mark_plan_rejected(
    client: &Client,
    plan: &PostgresPolicyPlan,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let mut status = plan.status.clone().unwrap_or_default();
    status.phase = PlanPhase::Rejected;
    set_plan_condition(
        &mut status.conditions,
        "Approved",
        "False",
        "Rejected",
        "Plan rejected via annotation",
    );

    let patch = serde_json::json!({ "status": status });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

/// Mark a plan as Superseded (database state changed since approval).
pub async fn mark_plan_superseded(
    client: &Client,
    plan: &PostgresPolicyPlan,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let mut status = plan.status.clone().unwrap_or_default();
    status.phase = PlanPhase::Superseded;
    set_plan_condition(
        &mut status.conditions,
        "Approved",
        "False",
        "Superseded",
        "Database state changed since plan was approved",
    );

    let patch = serde_json::json!({ "status": status });
    plans_api
        .patch_status(
            &plan_name,
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
    use crate::crd::CrdReconciliationMode;

    fn test_plan(
        name: &str,
        phase: PlanPhase,
        annotations: Option<BTreeMap<String, String>>,
    ) -> PostgresPolicyPlan {
        let mut plan = PostgresPolicyPlan::new(
            name,
            PostgresPolicyPlanSpec {
                policy_ref: PolicyPlanRef {
                    name: "test-policy".to_string(),
                },
                policy_generation: 1,
                reconciliation_mode: CrdReconciliationMode::Authoritative,
                owned_roles: vec!["role-a".to_string()],
                owned_schemas: vec!["public".to_string()],
                managed_database_identity: "default/db/DATABASE_URL".to_string(),
            },
        );
        plan.metadata.namespace = Some("default".to_string());
        plan.metadata.annotations = annotations;
        plan.status = Some(PostgresPolicyPlanStatus {
            phase,
            ..Default::default()
        });
        plan
    }

    #[test]
    fn check_plan_approval_pending_when_no_annotations() {
        let plan = test_plan("plan-1", PlanPhase::Pending, None);
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Pending);
    }

    #[test]
    fn check_plan_approval_approved_with_annotation() {
        let annotations =
            BTreeMap::from([(PLAN_APPROVED_ANNOTATION.to_string(), "true".to_string())]);
        let plan = test_plan("plan-1", PlanPhase::Pending, Some(annotations));
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Approved);
    }

    #[test]
    fn check_plan_approval_rejected_with_annotation() {
        let annotations =
            BTreeMap::from([(PLAN_REJECTED_ANNOTATION.to_string(), "true".to_string())]);
        let plan = test_plan("plan-1", PlanPhase::Pending, Some(annotations));
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Rejected);
    }

    #[test]
    fn check_plan_approval_rejected_wins_over_approved() {
        let annotations = BTreeMap::from([
            (PLAN_APPROVED_ANNOTATION.to_string(), "true".to_string()),
            (PLAN_REJECTED_ANNOTATION.to_string(), "true".to_string()),
        ]);
        let plan = test_plan("plan-1", PlanPhase::Pending, Some(annotations));
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Rejected);
    }

    #[test]
    fn check_plan_approval_non_true_value_is_pending() {
        let annotations =
            BTreeMap::from([(PLAN_APPROVED_ANNOTATION.to_string(), "false".to_string())]);
        let plan = test_plan("plan-1", PlanPhase::Pending, Some(annotations));
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Pending);
    }

    #[test]
    fn compute_sql_hash_is_deterministic() {
        let sql = "CREATE ROLE test LOGIN;\nGRANT SELECT ON ALL TABLES IN SCHEMA public TO test;";
        let hash1 = compute_sql_hash(sql);
        let hash2 = compute_sql_hash(sql);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex digest is 64 chars
    }

    #[test]
    fn compute_sql_hash_differs_for_different_sql() {
        let hash1 = compute_sql_hash("CREATE ROLE a;");
        let hash2 = compute_sql_hash("CREATE ROLE b;");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn generate_plan_name_has_expected_format() {
        let name = generate_plan_name("my-policy");
        assert!(name.starts_with("my-policy-plan-"));
        // Should be "my-policy-plan-YYYYMMDD-HHMMSS-MMMRRR"
        let suffix = name.strip_prefix("my-policy-plan-").unwrap();
        // YYYYMMDD-HHMMSS-MMMRRR = 15 + 1 + 6 = 22 chars
        assert_eq!(suffix.len(), 22);
        assert_eq!(&suffix[8..9], "-");
        assert_eq!(&suffix[15..16], "-");
    }

    #[test]
    fn generate_plan_name_is_unique_across_calls() {
        let name1 = generate_plan_name("my-policy");
        let name2 = generate_plan_name("my-policy");
        // With millisecond + random suffix, collisions are extremely unlikely
        // (this test may very rarely fail, but demonstrates the intent).
        assert_ne!(name1, name2);
    }

    #[test]
    fn sanitize_label_value_replaces_slashes() {
        let sanitized = sanitize_label_value("default/db-creds/DATABASE_URL");
        assert!(!sanitized.contains('/'));
        assert_eq!(sanitized, "default_db-creds_DATABASE_URL");
    }

    #[test]
    fn sanitize_label_value_truncates_to_63_chars() {
        let long_value = "a".repeat(100);
        let sanitized = sanitize_label_value(&long_value);
        assert!(sanitized.len() <= 63);
    }

    #[test]
    fn render_redacted_sql_masks_passwords() {
        let changes = vec![
            pgroles_core::diff::Change::CreateRole {
                name: "app".to_string(),
                state: pgroles_core::model::RoleState {
                    login: true,
                    ..pgroles_core::model::RoleState::default()
                },
            },
            pgroles_core::diff::Change::SetPassword {
                name: "app".to_string(),
                password: "super_secret".to_string(),
            },
        ];
        let ctx = pgroles_core::sql::SqlContext::default();
        let redacted = render_redacted_sql(&changes, &ctx);

        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("super_secret"));
        assert!(redacted.contains("CREATE ROLE"));
    }

    #[test]
    fn render_full_sql_includes_passwords() {
        let changes = vec![pgroles_core::diff::Change::SetPassword {
            name: "app".to_string(),
            password: "super_secret".to_string(),
        }];
        let ctx = pgroles_core::sql::SqlContext::default();
        let full = render_full_sql(&changes, &ctx);

        assert!(full.contains("super_secret") || full.contains("SCRAM-SHA-256"));
    }
}
