//! Plan lifecycle management for `PostgresPolicyPlan` resources.
//!
//! Handles creating, deduplicating, approving, executing, and cleaning up
//! reconciliation plans. Plans represent computed SQL change sets that may
//! require explicit approval before execution against a database.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::{Client, Resource, ResourceExt};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::crd::{
    ChangeSummary, CrdReconciliationMode, LABEL_DATABASE_IDENTITY, LABEL_PLAN, LABEL_POLICY,
    PLAN_APPROVED_ANNOTATION, PLAN_REJECTED_ANNOTATION, PlanPhase, PlanReference, PolicyCondition,
    PolicyPlanRef, PostgresPolicy, PostgresPolicyPlan, PostgresPolicyPlanSpec,
    PostgresPolicyPlanStatus, SqlCompression, SqlRef,
};
use crate::reconciler::ReconcileError;

/// Result of plan creation — distinguishes genuinely new plans from
/// deduplication hits so callers can decide whether to emit events.
#[derive(Debug, Clone)]
pub enum PlanCreationResult {
    /// A new plan was created with the given name.
    Created(String),
    /// An existing plan with the same hash was found (deduplication).
    Deduplicated(String),
}

impl PlanCreationResult {
    /// Return the plan name regardless of variant.
    pub fn plan_name(&self) -> &str {
        match self {
            PlanCreationResult::Created(name) | PlanCreationResult::Deduplicated(name) => name,
        }
    }

    /// True when a new plan was actually created.
    pub fn is_created(&self) -> bool {
        matches!(self, PlanCreationResult::Created(_))
    }
}

/// Maximum inline SQL size in plan status before spilling to a ConfigMap.
const MAX_INLINE_SQL_BYTES: usize = 16 * 1024;

/// ConfigMap binaryData key for gzip-compressed SQL content.
const SQL_CONFIGMAP_GZIP_KEY: &str = "plan.sql.gz";

/// Conservative stored-byte ceiling for SQL ConfigMaps. Kubernetes caps
/// ConfigMap data at 1 MiB; this leaves room for metadata and future labels.
const MAX_CONFIGMAP_SQL_BYTES: usize = 900 * 1024;

/// Stale status-less plan and orphan ConfigMap grace period.
const ORPHAN_GRACE_SECS: i64 = 60;

/// Best-effort cleanup should never block a fresh reconcile for long.
const CLEANUP_TIMEOUT_SECS: u64 = 5;

/// Default maximum number of historical plans to retain per policy.
const DEFAULT_MAX_PLANS: usize = 10;

/// How recently a Failed plan must have been created (in seconds) for the
/// dedup check to consider it a match. Plans older than this are ignored so
/// that retries after the user fixes the environment are not blocked.
const FAILED_PLAN_DEDUP_WINDOW_SECS: i64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
enum PlanSqlArtifact {
    Inline(String),
    CompressedConfigMap {
        configmap_name: String,
        key: String,
        compressed_sql: Vec<u8>,
    },
    TruncatedInline(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedPlanSql {
    artifact: PlanSqlArtifact,
    redacted_sql_hash: String,
    original_bytes: usize,
    stored_bytes: usize,
}

impl PreparedPlanSql {
    fn sql_ref(&self) -> Option<SqlRef> {
        match &self.artifact {
            PlanSqlArtifact::CompressedConfigMap {
                configmap_name,
                key,
                ..
            } => Some(SqlRef {
                name: configmap_name.clone(),
                key: key.clone(),
                compression: Some(SqlCompression::Gzip),
            }),
            PlanSqlArtifact::Inline(_) | PlanSqlArtifact::TruncatedInline(_) => None,
        }
    }

    fn sql_inline(&self) -> Option<String> {
        match &self.artifact {
            PlanSqlArtifact::Inline(sql) | PlanSqlArtifact::TruncatedInline(sql) => {
                Some(sql.clone())
            }
            PlanSqlArtifact::CompressedConfigMap { .. } => None,
        }
    }

    fn is_truncated(&self) -> bool {
        matches!(self.artifact, PlanSqlArtifact::TruncatedInline(_))
    }
}

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
/// 4. Persists the SQL preview artifact, if needed
/// 5. Creates the new plan resource with ownerReferences
/// 6. Updates the plan status
/// 7. Marks any older Pending plans with a different hash as Superseded
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
) -> Result<PlanCreationResult, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();
    let generation = policy.metadata.generation.unwrap_or(0);

    // 1. Render the full executable SQL (not redacted).
    let full_sql = render_full_sql(changes, sql_context);

    // 2. Compute SHA-256 hash of the full SQL.
    let sql_hash = compute_sql_hash(&full_sql);

    // 3. Count SQL statements (after wildcard expansion).
    let sql_statement_count = full_sql.lines().filter(|l| !l.trim().is_empty()).count() as i64;

    // 4. Render redacted SQL for display (passwords masked).
    let redacted_sql = render_redacted_sql(changes, sql_context);

    cleanup_old_plans_best_effort(client, policy, None).await;

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    // 4. List existing plans for this policy.
    let label_selector = format!("{LABEL_POLICY}={}", sanitize_label_value(&policy_name));
    let existing_plans = plans_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;

    // 5. Check for duplicate pending plan with same hash.
    for plan in &existing_plans {
        if let Some(ref status) = plan.status
            && status.phase == PlanPhase::Pending
            && status.sql_hash.as_deref() == Some(&sql_hash)
        {
            // Identical plan already exists — return early (deduplicated).
            let plan_name = plan.name_any();
            info!(
                plan = %plan_name,
                policy = %policy_name,
                "existing pending plan has identical SQL hash, skipping creation"
            );
            return Ok(PlanCreationResult::Deduplicated(plan_name));
        }
    }

    // 5b. Check for recently-failed plan with the same hash. If a plan with
    // this exact SQL already failed within the dedup window, creating another
    // identical one is pointless — it would produce the same error. The window
    // ensures we don't block retries after the user fixes the environment.
    //
    // Uses `status.failed_at` (not `creation_timestamp`) so that plans which
    // waited for approval before failing are measured from the failure time.
    let now_ts = now_epoch_secs();
    for plan in &existing_plans {
        if let Some(ref status) = plan.status
            && status.phase == PlanPhase::Failed
            && status.sql_hash.as_deref() == Some(&sql_hash)
        {
            let failed_ts = status
                .failed_at
                .as_deref()
                .and_then(parse_rfc3339_epoch_secs)
                .unwrap_or(0);
            if failed_ts > 0 && now_ts - failed_ts < FAILED_PLAN_DEDUP_WINDOW_SECS {
                let plan_name = plan.name_any();
                info!(
                    plan = %plan_name,
                    policy = %policy_name,
                    age_secs = now_ts - failed_ts,
                    "recently-failed plan has identical SQL hash, skipping creation"
                );
                return Ok(PlanCreationResult::Deduplicated(plan_name));
            }
        }
    }

    // 6. Generate a plan name using timestamp plus SQL hash. The hash suffix
    // makes same-second retries after content persistence failures idempotent.
    let plan_name = generate_plan_name(&policy_name, &sql_hash);
    let prepared_sql = prepare_plan_sql(&plan_name, &redacted_sql)?;

    // 7. Persist SQL content before materialising the visible plan resource.
    let sql_configmap_name = create_plan_sql_configmap(
        client,
        policy,
        &namespace,
        &policy_name,
        database_identity,
        &prepared_sql,
    )
    .await?;

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
        (LABEL_POLICY.to_string(), sanitize_label_value(&policy_name)),
        (
            LABEL_DATABASE_IDENTITY.to_string(),
            sanitize_label_value(database_identity),
        ),
    ]));

    // Annotations for quick visibility in kubectl describe / Lens.
    let sql_preview = redacted_sql.lines().take(5).collect::<Vec<_>>().join("\n");
    let summary_text = format!(
        "{}R {}G {}D {}DP {}M",
        change_summary.roles_created + change_summary.roles_altered,
        change_summary.grants_added,
        change_summary.default_privileges_set,
        change_summary.roles_dropped,
        change_summary.members_added,
    );
    plan.metadata.annotations = Some(BTreeMap::from([
        ("pgroles.io/sql-preview".to_string(), sql_preview),
        ("pgroles.io/summary".to_string(), summary_text),
        (
            "pgroles.io/sql-hash".to_string(),
            sql_hash[..12].to_string(),
        ),
        (
            "pgroles.io/redacted-sql-hash".to_string(),
            prepared_sql.redacted_sql_hash[..12].to_string(),
        ),
        (
            "pgroles.io/sql-original-bytes".to_string(),
            prepared_sql.original_bytes.to_string(),
        ),
        (
            "pgroles.io/sql-stored-bytes".to_string(),
            prepared_sql.stored_bytes.to_string(),
        ),
    ]));

    let (created_plan, created_new_plan) =
        match plans_api.create(&PostParams::default(), &plan).await {
            Ok(plan) => (plan, true),
            Err(kube::Error::Api(api_err)) if api_err.code == 409 => {
                let existing = plans_api.get(&plan_name).await?;
                if !should_patch_existing_plan_status(&existing) {
                    return Ok(PlanCreationResult::Deduplicated(existing.name_any()));
                }
                (existing, false)
            }
            Err(err) => {
                if let Some(configmap_name) = sql_configmap_name.as_deref() {
                    delete_configmap_best_effort(client, &namespace, configmap_name).await;
                }
                return Err(err.into());
            }
        };
    let plan_name = created_plan.name_any();

    // 11. Update plan status.
    let computed_message = if prepared_sql.is_truncated() {
        format!(
            "Plan computed with {} change(s); SQL preview truncated because compressed SQL exceeded Kubernetes ConfigMap limits",
            change_summary.total
        )
    } else {
        format!("Plan computed with {} change(s)", change_summary.total)
    };
    let plan_status = PostgresPolicyPlanStatus {
        phase: PlanPhase::Pending,
        conditions: vec![
            PolicyCondition {
                condition_type: "Computed".to_string(),
                status: "True".to_string(),
                reason: Some("PlanComputed".to_string()),
                message: Some(computed_message),
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
        sql_ref: prepared_sql.sql_ref(),
        sql_inline: prepared_sql.sql_inline(),
        sql_truncated: prepared_sql.is_truncated(),
        computed_at: Some(crate::crd::now_rfc3339()),
        applied_at: None,
        last_error: None,
        sql_hash: Some(sql_hash),
        applying_since: None,
        failed_at: None,
        sql_statements: Some(sql_statement_count),
        redacted_sql_hash: Some(prepared_sql.redacted_sql_hash.clone()),
        sql_original_bytes: Some(prepared_sql.original_bytes as i64),
        sql_stored_bytes: Some(prepared_sql.stored_bytes as i64),
    };

    let status_patch = serde_json::json!({ "status": plan_status });
    if let Err(err) = plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&status_patch),
        )
        .await
    {
        if created_new_plan {
            delete_plan_best_effort(&plans_api, &plan_name).await;
        }
        if let Some(configmap_name) = sql_configmap_name.as_deref() {
            delete_configmap_best_effort(client, &namespace, configmap_name).await;
        }
        return Err(err.into());
    }

    // 12. Mark any existing Pending plans as Superseded after the new plan is
    // fully visible. This avoids losing the current actionable plan if SQL
    // persistence fails before the replacement is materialised.
    for plan in &existing_plans {
        if let Some(ref status) = plan.status
            && status.phase == PlanPhase::Pending
            && plan.name_any() != plan_name
        {
            let old_plan_name = plan.name_any();
            info!(
                plan = %old_plan_name,
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
                    &old_plan_name,
                    &PatchParams::apply("pgroles-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;
        }
    }

    info!(
        plan = %plan_name,
        policy = %policy_name,
        changes = change_summary.total,
        "created new plan"
    );

    Ok(PlanCreationResult::Created(plan_name))
}

// ---------------------------------------------------------------------------
// Plan execution
// ---------------------------------------------------------------------------

/// Execute an approved plan against the database.
///
/// Re-renders executable SQL from the reconciler's in-memory changes, executes
/// it in a transaction, and updates the plan status to Applied or Failed.
/// Persisted SQL on the plan is a redacted review artifact only; apply must not
/// read it because large plans may store only a truncated preview.
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
            failed_status.failed_at = Some(crate::crd::now_rfc3339());

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

fn prepare_plan_sql(
    plan_name: &str,
    redacted_sql: &str,
) -> Result<PreparedPlanSql, ReconcileError> {
    let original_bytes = redacted_sql.len();
    let redacted_sql_hash = compute_sql_hash(redacted_sql);

    if original_bytes <= MAX_INLINE_SQL_BYTES {
        return Ok(PreparedPlanSql {
            artifact: PlanSqlArtifact::Inline(redacted_sql.to_string()),
            redacted_sql_hash,
            original_bytes,
            stored_bytes: original_bytes,
        });
    }

    let compressed_sql = gzip_bytes(redacted_sql.as_bytes())?;
    if compressed_sql.len() <= MAX_CONFIGMAP_SQL_BYTES {
        let stored_bytes = compressed_sql.len();
        return Ok(PreparedPlanSql {
            artifact: PlanSqlArtifact::CompressedConfigMap {
                configmap_name: format!("{plan_name}-sql"),
                key: SQL_CONFIGMAP_GZIP_KEY.to_string(),
                compressed_sql,
            },
            redacted_sql_hash,
            original_bytes,
            stored_bytes,
        });
    }

    let truncated = truncate_utf8(
        redacted_sql,
        MAX_INLINE_SQL_BYTES,
        "\n-- truncated: compressed SQL preview exceeded Kubernetes ConfigMap limits --",
    );
    let stored_bytes = truncated.len();
    Ok(PreparedPlanSql {
        artifact: PlanSqlArtifact::TruncatedInline(truncated),
        redacted_sql_hash,
        original_bytes,
        stored_bytes,
    })
}

fn gzip_bytes(bytes: &[u8]) -> Result<Vec<u8>, ReconcileError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .map_err(|err| ReconcileError::PlanSqlStorage(err.to_string()))?;
    encoder
        .finish()
        .map_err(|err| ReconcileError::PlanSqlStorage(err.to_string()))
}

fn truncate_utf8(text: &str, max_bytes: usize, marker: &str) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }

    let target_len = max_bytes.saturating_sub(marker.len());
    let mut end = target_len.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = text[..end].to_string();
    truncated.push_str(marker);
    truncated
}

async fn create_plan_sql_configmap(
    client: &Client,
    policy: &PostgresPolicy,
    namespace: &str,
    policy_name: &str,
    database_identity: &str,
    prepared_sql: &PreparedPlanSql,
) -> Result<Option<String>, ReconcileError> {
    let PlanSqlArtifact::CompressedConfigMap {
        configmap_name,
        key: _,
        compressed_sql: _,
    } = &prepared_sql.artifact
    else {
        return Ok(None);
    };

    let configmap = build_plan_sql_configmap_object(
        policy,
        namespace,
        policy_name,
        database_identity,
        prepared_sql,
    )?;

    let configmaps_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    match configmaps_api
        .create(&PostParams::default(), &configmap)
        .await
    {
        Ok(_) => Ok(Some(configmap_name.clone())),
        Err(kube::Error::Api(api_err)) if api_err.code == 409 => {
            let existing = configmaps_api.get(configmap_name).await?;
            validate_existing_sql_configmap(&existing, prepared_sql)?;
            Ok(Some(configmap_name.clone()))
        }
        Err(err) => Err(err.into()),
    }
}

fn build_plan_sql_configmap_object(
    policy: &PostgresPolicy,
    namespace: &str,
    policy_name: &str,
    database_identity: &str,
    prepared_sql: &PreparedPlanSql,
) -> Result<ConfigMap, ReconcileError> {
    let PlanSqlArtifact::CompressedConfigMap {
        configmap_name,
        key,
        compressed_sql,
    } = &prepared_sql.artifact
    else {
        return Err(ReconcileError::PlanSqlStorage(
            "cannot build ConfigMap for inline plan SQL".to_string(),
        ));
    };

    Ok(ConfigMap {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(configmap_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![build_owner_reference(policy)]),
            labels: Some(BTreeMap::from([
                (LABEL_POLICY.to_string(), sanitize_label_value(policy_name)),
                (
                    LABEL_DATABASE_IDENTITY.to_string(),
                    sanitize_label_value(database_identity),
                ),
                (
                    LABEL_PLAN.to_string(),
                    plan_label_value(configmap_plan_name(configmap_name)),
                ),
            ])),
            annotations: Some(BTreeMap::from([
                ("pgroles.io/sql-compression".to_string(), "gzip".to_string()),
                (
                    "pgroles.io/redacted-sql-hash".to_string(),
                    prepared_sql.redacted_sql_hash.clone(),
                ),
                (
                    "pgroles.io/sql-original-bytes".to_string(),
                    prepared_sql.original_bytes.to_string(),
                ),
                (
                    "pgroles.io/sql-stored-bytes".to_string(),
                    prepared_sql.stored_bytes.to_string(),
                ),
            ])),
            ..Default::default()
        },
        binary_data: Some(BTreeMap::from([(
            key.clone(),
            ByteString(compressed_sql.clone()),
        )])),
        ..Default::default()
    })
}

fn configmap_plan_name(configmap_name: &str) -> &str {
    configmap_name
        .strip_suffix("-sql")
        .unwrap_or(configmap_name)
}

fn plan_label_value(plan_name: &str) -> String {
    compute_sql_hash(plan_name)[..32].to_string()
}

fn validate_existing_sql_configmap(
    configmap: &ConfigMap,
    prepared_sql: &PreparedPlanSql,
) -> Result<(), ReconcileError> {
    let Some(annotations) = configmap.metadata.annotations.as_ref() else {
        return Err(ReconcileError::PlanSqlStorage(format!(
            "existing ConfigMap {} is missing SQL storage annotations",
            configmap.name_any()
        )));
    };
    let hash_matches = annotations
        .get("pgroles.io/redacted-sql-hash")
        .map(|hash| hash == &prepared_sql.redacted_sql_hash)
        .unwrap_or(false);
    if hash_matches {
        Ok(())
    } else {
        Err(ReconcileError::PlanSqlStorage(format!(
            "existing ConfigMap {} does not match computed SQL preview hash",
            configmap.name_any()
        )))
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

/// Best-effort cleanup wrapper used on hot reconciliation paths. Cleanup should
/// reduce leaked resources, never block otherwise valid reconciliation.
pub async fn cleanup_old_plans_best_effort(
    client: &Client,
    policy: &PostgresPolicy,
    max_plans: Option<usize>,
) {
    match tokio::time::timeout(
        Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        cleanup_old_plans(client, policy, max_plans),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(%err, "failed to clean up old plans"),
        Err(_) => tracing::warn!(
            timeout_secs = CLEANUP_TIMEOUT_SECS,
            "timed out cleaning up old plans"
        ),
    }
}

/// Clean up old plans for a policy, retaining at most `max_plans` terminal plans.
///
/// Terminal plans are those in Applied, Failed, Superseded, or Rejected phase;
/// Pending, Approved, and Applying plans are retained. Status-less plans and
/// SQL ConfigMaps older than a short grace period are treated as stale orphans.
pub async fn cleanup_old_plans(
    client: &Client,
    policy: &PostgresPolicy,
    max_plans: Option<usize>,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();
    let max_plans = max_plans.unwrap_or(DEFAULT_MAX_PLANS);

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let label_selector = format!("{LABEL_POLICY}={}", sanitize_label_value(&policy_name));
    let existing_plans = plans_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;
    let now_ts = now_epoch_secs();

    for plan in existing_plans
        .iter()
        .filter(|plan| is_stale_statusless_plan(plan, now_ts))
    {
        let plan_name = plan.name_any();
        info!(
            plan = %plan_name,
            policy = %policy_name,
            "cleaning up stale status-less plan"
        );
        if let Err(err) = plans_api.delete(&plan_name, &DeleteParams::default()).await {
            tracing::warn!(
                plan = %plan_name,
                %err,
                "failed to delete stale status-less plan during cleanup"
            );
        }
    }

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

    if terminal_plans.len() > max_plans {
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
            if let Err(err) = plans_api.delete(&plan_name, &DeleteParams::default()).await {
                tracing::warn!(
                    plan = %plan_name,
                    %err,
                    "failed to delete old plan during cleanup"
                );
            }
        }
    }

    cleanup_orphan_sql_configmaps(
        client,
        &namespace,
        &policy_name,
        &existing_plans.items,
        now_ts,
    )
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn cleanup_orphan_sql_configmaps(
    client: &Client,
    namespace: &str,
    policy_name: &str,
    existing_plans: &[PostgresPolicyPlan],
    now_ts: i64,
) -> Result<(), ReconcileError> {
    let configmaps_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let label_selector = format!("{LABEL_POLICY}={}", sanitize_label_value(policy_name));
    let configmaps = configmaps_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;
    let known_plan_labels: BTreeSet<String> = existing_plans
        .iter()
        .map(|plan| plan_label_value(&plan.name_any()))
        .collect();
    let known_plan_names: BTreeSet<String> =
        existing_plans.iter().map(ResourceExt::name_any).collect();

    for configmap in configmaps {
        if !is_orphan_sql_configmap(&configmap, &known_plan_names, &known_plan_labels, now_ts) {
            continue;
        }

        let configmap_name = configmap.name_any();
        info!(
            configmap = %configmap_name,
            policy = %policy_name,
            "cleaning up orphan plan SQL ConfigMap"
        );
        if let Err(err) = configmaps_api
            .delete(&configmap_name, &DeleteParams::default())
            .await
        {
            tracing::warn!(
                configmap = %configmap_name,
                %err,
                "failed to delete orphan plan SQL ConfigMap during cleanup"
            );
        }
    }

    Ok(())
}

fn is_orphan_sql_configmap(
    configmap: &ConfigMap,
    known_plan_names: &BTreeSet<String>,
    known_plan_labels: &BTreeSet<String>,
    now_ts: i64,
) -> bool {
    let Some(labels) = configmap.metadata.labels.as_ref() else {
        return false;
    };
    if !labels.contains_key(LABEL_POLICY) || !is_stale_object(configmap, now_ts) {
        return false;
    }
    if known_plan_names.contains(configmap_plan_name(&configmap.name_any())) {
        return false;
    }
    labels
        .get(LABEL_PLAN)
        .map(|plan_label| !known_plan_labels.contains(plan_label))
        .unwrap_or(true)
}

fn should_patch_existing_plan_status(plan: &PostgresPolicyPlan) -> bool {
    plan.status
        .as_ref()
        .map(|status| status.phase == PlanPhase::Pending)
        .unwrap_or(true)
}

fn is_stale_statusless_plan(plan: &PostgresPolicyPlan, now_ts: i64) -> bool {
    plan.status.is_none() && is_stale_object(plan, now_ts)
}

fn is_stale_object<K>(resource: &K, now_ts: i64) -> bool
where
    K: Resource,
{
    resource
        .meta()
        .creation_timestamp
        .as_ref()
        .map(|timestamp| now_ts.saturating_sub(timestamp.0.as_second()) > ORPHAN_GRACE_SECS)
        .unwrap_or(false)
}

async fn delete_plan_best_effort(plans_api: &Api<PostgresPolicyPlan>, plan_name: &str) {
    if let Err(err) = plans_api.delete(plan_name, &DeleteParams::default()).await {
        tracing::warn!(
            plan = %plan_name,
            %err,
            "failed to roll back plan after status update failure"
        );
    }
}

async fn delete_configmap_best_effort(client: &Client, namespace: &str, configmap_name: &str) {
    let configmaps_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    if let Err(err) = configmaps_api
        .delete(configmap_name, &DeleteParams::default())
        .await
    {
        tracing::warn!(
            configmap = %configmap_name,
            %err,
            "failed to roll back plan SQL ConfigMap"
        );
    }
}

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
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a string should succeed");
    }
    hex
}

/// Generate a plan name from policy name, current timestamp, and SQL hash.
///
/// Format: `{policy-name}-plan-{YYYYMMDD-HHMMSS}-{hash-prefix}`
///
/// The hash suffix makes retries within the same second idempotent if SQL
/// content persistence succeeds but plan creation fails.
fn generate_plan_name(policy_name: &str, sql_hash: &str) -> String {
    let timestamp = format_timestamp_compact();
    let suffix = &sql_hash[..12.min(sql_hash.len())];
    // Kubernetes names must be <= 253 chars and DNS-compatible.
    // Reserve 4 chars for the potential "-sql" ConfigMap suffix.
    let max_name_len = 253 - 4; // 249
    let max_prefix_len = max_name_len - "-plan-".len() - timestamp.len() - "-".len() - suffix.len();
    let prefix = if policy_name.len() > max_prefix_len {
        policy_name
            .char_indices()
            .take_while(|(idx, ch)| idx + ch.len_utf8() <= max_prefix_len)
            .map(|(_, ch)| ch)
            .collect::<String>()
    } else {
        policy_name.to_string()
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

/// Current time as Unix epoch seconds (for dedup window checks).
fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Parse an RFC 3339 timestamp string to Unix epoch seconds.
/// Returns `None` if parsing fails.
fn parse_rfc3339_epoch_secs(rfc3339: &str) -> Option<i64> {
    // Use jiff (already a transitive dep via k8s-openapi) for RFC 3339 parsing.
    rfc3339
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_second())
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

/// Update the phase field on a plan's status.
///
/// When transitioning to `Applying`, also sets `applying_since` for stuck
/// plan detection.
async fn update_plan_phase(
    plans_api: &Api<PostgresPolicyPlan>,
    plan_name: &str,
    phase: PlanPhase,
) -> Result<(), ReconcileError> {
    let mut patch_value = serde_json::json!({ "status": { "phase": phase } });
    if phase == PlanPhase::Applying {
        patch_value["status"]["applying_since"] = serde_json::json!(crate::crd::now_rfc3339());
    }
    plans_api
        .patch_status(
            plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch_value),
        )
        .await?;
    Ok(())
}

/// Set or update a condition in a conditions list.
///
/// Preserves `last_transition_time` when the status value is unchanged
/// (only reason/message changed), matching Kubernetes condition conventions.
fn set_plan_condition(
    conditions: &mut Vec<PolicyCondition>,
    condition_type: &str,
    status: &str,
    reason: &str,
    message: &str,
) {
    let transition_time = if let Some(existing) = conditions
        .iter()
        .find(|c| c.condition_type == condition_type)
    {
        if existing.status == status {
            existing.last_transition_time.clone()
        } else {
            Some(crate::crd::now_rfc3339())
        }
    } else {
        Some(crate::crd::now_rfc3339())
    };

    let condition = PolicyCondition {
        condition_type: condition_type.to_string(),
        status: status.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: transition_time,
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

/// Look up the current actionable plan for a policy, if any.
///
/// An actionable plan is one in `Pending` or `Approved` phase — i.e. a plan
/// that the reconciler should evaluate for approval/execution.
pub async fn get_current_actionable_plan(
    client: &Client,
    policy: &PostgresPolicy,
) -> Result<Option<PostgresPolicyPlan>, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let label_selector = format!("{LABEL_POLICY}={}", sanitize_label_value(&policy_name));
    let existing_plans = plans_api
        .list(&ListParams::default().labels(&label_selector))
        .await?;

    // Find the most recent actionable plan (Pending or Approved, by creation time).
    let mut pending_plans: Vec<PostgresPolicyPlan> = existing_plans
        .into_iter()
        .filter(|plan| {
            plan.status
                .as_ref()
                .map(|s| matches!(s.phase, PlanPhase::Pending | PlanPhase::Approved))
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
    let label_selector = format!("{LABEL_POLICY}={}", sanitize_label_value(&policy_name));
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
    status.failed_at = Some(crate::crd::now_rfc3339());

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

/// Mark a plan as Approved.
///
/// Callers provide `reason` and `message` to distinguish auto-approval from
/// manual approval in the plan's conditions.
pub async fn mark_plan_approved(
    client: &Client,
    plan: &PostgresPolicyPlan,
    reason: &str,
    message: &str,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let mut status = plan.status.clone().unwrap_or_default();
    status.phase = PlanPhase::Approved;
    set_plan_condition(&mut status.conditions, "Approved", "True", reason, message);

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
    use base64::Engine as _;
    use flate2::read::GzDecoder;
    use std::io::Read;

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
    fn compute_sql_hash_matches_pinned_fixture() {
        assert_eq!(
            compute_sql_hash("CREATE ROLE app LOGIN;"),
            "12a9743285d98ce73cfa9c840e943fc627d1fcbce22c5206fda1b21c84c1ac9c"
        );
    }

    #[test]
    fn generate_plan_name_has_expected_format() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let name = generate_plan_name("my-policy", hash);
        assert!(name.starts_with("my-policy-plan-"));
        assert!(name.ends_with("-abcdef012345"));
        let suffix = name.strip_prefix("my-policy-plan-").unwrap();
        // YYYYMMDD-HHMMSS-hashprefix = 15 + 1 + 12 = 28 chars
        assert_eq!(suffix.len(), 28);
        assert_eq!(&suffix[8..9], "-");
        assert_eq!(&suffix[15..16], "-");
    }

    #[test]
    fn generate_plan_name_is_idempotent_for_same_hash_in_same_second() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let name1 = generate_plan_name("my-policy", hash);
        let name2 = generate_plan_name("my-policy", hash);
        assert_eq!(name1, name2);
    }

    #[test]
    fn generate_plan_name_truncates_on_utf8_boundary() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let name = generate_plan_name(&"é".repeat(140), hash);
        assert!(name.len() <= 249);
        assert!(name.ends_with("-abcdef012345"));
    }

    #[test]
    fn plan_label_value_is_stable_and_label_safe_for_long_names() {
        let plan_name = "very-long-policy-name-".repeat(20);
        let label = plan_label_value(&plan_name);
        assert_eq!(label, plan_label_value(&plan_name));
        assert_eq!(label.len(), 32);
        assert!(label.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn existing_non_pending_plan_status_is_not_repatched_on_create_conflict() {
        let approved = test_plan("plan-1", PlanPhase::Approved, None);
        let applying = test_plan("plan-1", PlanPhase::Applying, None);
        let applied = test_plan("plan-1", PlanPhase::Applied, None);

        assert!(!should_patch_existing_plan_status(&approved));
        assert!(!should_patch_existing_plan_status(&applying));
        assert!(!should_patch_existing_plan_status(&applied));
    }

    #[test]
    fn existing_pending_or_statusless_plan_can_be_patched_on_create_conflict() {
        let pending = test_plan("plan-1", PlanPhase::Pending, None);
        let mut statusless = pending.clone();
        statusless.status = None;

        assert!(should_patch_existing_plan_status(&pending));
        assert!(should_patch_existing_plan_status(&statusless));
    }

    #[test]
    fn prepare_plan_sql_keeps_small_sql_inline() {
        let prepared = prepare_plan_sql("plan-1", "CREATE ROLE app LOGIN;").unwrap();

        assert!(matches!(prepared.artifact, PlanSqlArtifact::Inline(_)));
        assert_eq!(
            prepared.sql_inline(),
            Some("CREATE ROLE app LOGIN;".to_string())
        );
        assert!(prepared.sql_ref().is_none());
        assert!(!prepared.is_truncated());
    }

    #[test]
    fn prepare_plan_sql_compresses_large_brownfield_sized_sql() {
        let sql = brownfield_sized_sql();
        assert!(sql.len() > 1_048_576);

        let prepared = prepare_plan_sql("policy-plan-20260506-000000-abcdef012345", &sql).unwrap();

        let PlanSqlArtifact::CompressedConfigMap {
            key,
            compressed_sql,
            ..
        } = &prepared.artifact
        else {
            panic!("expected compressed ConfigMap artifact");
        };
        assert_eq!(key, SQL_CONFIGMAP_GZIP_KEY);
        assert!(compressed_sql.len() < MAX_CONFIGMAP_SQL_BYTES);
        assert_eq!(gunzip(compressed_sql), sql);
        assert_eq!(
            prepared.sql_ref().unwrap().compression,
            Some(SqlCompression::Gzip)
        );
        assert_eq!(prepared.original_bytes, sql.len());
        assert_eq!(prepared.stored_bytes, compressed_sql.len());
    }

    #[test]
    fn configmap_binary_data_serializes_with_one_base64_layer() {
        let sql = brownfield_sized_sql();
        let prepared = prepare_plan_sql("policy-plan-20260506-000000-abcdef012345", &sql).unwrap();
        let PlanSqlArtifact::CompressedConfigMap {
            key,
            compressed_sql,
            ..
        } = &prepared.artifact
        else {
            panic!("expected compressed ConfigMap artifact");
        };
        let configmap = ConfigMap {
            binary_data: Some(BTreeMap::from([(
                key.clone(),
                ByteString(compressed_sql.clone()),
            )])),
            ..Default::default()
        };

        let encoded = serde_json::to_value(&configmap).unwrap()["binaryData"][key]
            .as_str()
            .unwrap()
            .to_string();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();

        assert_eq!(decoded, *compressed_sql);
        assert_eq!(gunzip(&decoded), sql);
    }

    #[test]
    fn prepare_plan_sql_truncates_when_compressed_sql_is_still_too_large() {
        let sql = deterministic_incompressible_sql(1_400_000);
        let prepared = prepare_plan_sql("policy-plan-20260506-000000-abcdef012345", &sql).unwrap();

        let PlanSqlArtifact::TruncatedInline(preview) = &prepared.artifact else {
            panic!("expected truncated inline artifact");
        };
        assert!(preview.len() <= MAX_INLINE_SQL_BYTES);
        assert!(preview.contains("truncated"));
        assert!(prepared.sql_ref().is_none());
        assert!(prepared.is_truncated());
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
    fn stale_policy_sql_configmap_without_plan_label_is_orphan() {
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                labels: Some(BTreeMap::from([(
                    LABEL_POLICY.to_string(),
                    sanitize_label_value("test-policy"),
                )])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::new(),
            &BTreeSet::new(),
            ORPHAN_GRACE_SECS + 1
        ));
    }

    #[test]
    fn stale_policy_sql_configmap_with_current_plan_name_is_not_orphan() {
        let plan_name = "test-policy-plan-20260506-000000-abcdef012345";
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("{plan_name}-sql")),
                labels: Some(BTreeMap::from([
                    (
                        LABEL_POLICY.to_string(),
                        sanitize_label_value("test-policy"),
                    ),
                    (
                        LABEL_PLAN.to_string(),
                        sanitize_label_value("legacy-colliding-label"),
                    ),
                ])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(!is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::from([plan_name.to_string()]),
            &BTreeSet::new(),
            ORPHAN_GRACE_SECS + 1
        ));
    }

    #[test]
    fn stale_policy_sql_configmap_with_known_hash_plan_label_is_not_orphan() {
        let plan_name = "test-policy-plan-20260506-000000-abcdef012345";
        let plan_label = plan_label_value(plan_name);
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("different-plan-sql".to_string()),
                labels: Some(BTreeMap::from([
                    (
                        LABEL_POLICY.to_string(),
                        sanitize_label_value("test-policy"),
                    ),
                    (LABEL_PLAN.to_string(), plan_label.clone()),
                ])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(!is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::new(),
            &BTreeSet::from([plan_label]),
            ORPHAN_GRACE_SECS + 1
        ));
    }

    #[test]
    fn stale_policy_sql_configmap_with_only_legacy_colliding_label_is_orphan() {
        let plan_name =
            "very-long-policy-name-that-would-have-collided-plan-20260506-000000-abcdef012345";
        let legacy_label = sanitize_label_value(plan_name);
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("deleted-historical-plan-sql".to_string()),
                labels: Some(BTreeMap::from([
                    (
                        LABEL_POLICY.to_string(),
                        sanitize_label_value("test-policy"),
                    ),
                    (LABEL_PLAN.to_string(), legacy_label.clone()),
                ])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::new(),
            &BTreeSet::new(),
            ORPHAN_GRACE_SECS + 1
        ));
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

    #[test]
    fn now_epoch_secs_returns_plausible_value() {
        let now = now_epoch_secs();
        // Should be after 2025-01-01 and before 2100-01-01.
        let y2025 = 1_735_689_600_i64;
        let y2100 = 4_102_444_800_i64;
        assert!(
            now > y2025 && now < y2100,
            "epoch secs {now} should be between 2025 and 2100"
        );
    }

    fn brownfield_sized_sql() -> String {
        let mut sql = String::new();
        for schema in 0..33 {
            for profile in ["reader", "writer", "owner", "cdc"] {
                let role = format!("schema_{schema}_{profile}");
                sql.push_str(&format!(
                    "CREATE ROLE \"{role}\" LOGIN;\nCOMMENT ON ROLE \"{role}\" IS 'Generated from profile {profile} for brownfield migration schema {schema} with cdc ownership directives and review metadata';\n"
                ));
                for relkind in ["TABLES", "SEQUENCES", "FUNCTIONS"] {
                    sql.push_str(&format!(
                        "GRANT SELECT ON ALL {relkind} IN SCHEMA \"schema_{schema}\" TO \"{role}\";\n"
                    ));
                }
                for owner in 0..20 {
                    sql.push_str(&format!(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE \"owner_{owner}\" IN SCHEMA \"schema_{schema}\" GRANT SELECT ON TABLES TO \"{role}\";\n"
                    ));
                }
            }
        }
        for member in 0..70 {
            sql.push_str(&format!(
                "GRANT \"group_{member}\" TO \"service_login_{}\";\n",
                member % 20
            ));
        }
        while sql.len() <= 1_100_000 {
            sql.push_str("-- brownfield migration padding for large plan regression\n");
        }
        sql
    }

    fn deterministic_incompressible_sql(target_bytes: usize) -> String {
        let mut state = 0x1234_5678_u64;
        let mut sql = String::with_capacity(target_bytes);
        while sql.len() < target_bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = (state % 62) as u8;
            let ch = match value {
                0..=9 => b'0' + value,
                10..=35 => b'a' + (value - 10),
                _ => b'A' + (value - 36),
            };
            sql.push(ch as char);
            if sql.len().is_multiple_of(120) {
                sql.push('\n');
            }
        }
        sql
    }

    fn gunzip(bytes: &[u8]) -> String {
        let mut decoder = GzDecoder::new(bytes);
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        decoded
    }
}
