//! Ephemeral PostgreSQL membership access reconciliation.
//!
//! Durable database policy remains in `PostgresPolicy`. These controllers
//! resolve immutable, bounded membership bundles and apply only the scoped
//! membership edges while sharing the ordinary database locks.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event as FinalizerEvent};
use kube::{Api, Resource, ResourceExt};

use crate::context::{ContextError, OperatorContext};
use crate::crd::{
    ChangeSummary, DatabaseIdentity, EPHEMERAL_BUNDLE_ENCODING_V1, EphemeralAccessCondition,
    EphemeralAccessPolicy, EphemeralAccessPolicyStatus, EphemeralAccessRequest,
    EphemeralAccessRequestPhase, EphemeralAccessRequestStatus, EphemeralApprovalMode, PlanOrigin,
    PlanPhase, PlanScope, PolicyCondition, PolicyMode, PolicyPlanRef, PostgresPolicy,
    PostgresPolicyPlan, PostgresPolicyPlanSpec, PostgresPolicyPlanStatus, ResolvedEphemeralAccess,
    ResolvedEphemeralMembership, ScopedPlanOperation,
};
use crate::reconciler::ReconcileError;

const ACCESS_POLICY_FINALIZER: &str = "ephemeralaccesspolicy.pgroles.io/finalizer";
const ACCESS_REQUEST_FINALIZER: &str = "ephemeralaccessrequest.pgroles.io/finalizer";
const DEFAULT_CLUSTER_MAXIMUM: &str = "24h";
const DEFAULT_CLUSTER_PENDING_MAXIMUM: &str = "1h";
const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Delete every ephemeral access policy attached to a target policy.
///
/// Called from the target's finalizer so the target remains available while
/// access-policy and request finalizers perform scoped revocation.
pub(crate) async fn delete_access_policies_for_target(
    target: &PostgresPolicy,
    ctx: &OperatorContext,
) -> Result<usize, ReconcileError> {
    let namespace = target.namespace().ok_or(ReconcileError::NoNamespace)?;
    let access_policies: Api<EphemeralAccessPolicy> =
        Api::namespaced(ctx.kube_client.clone(), &namespace);
    let target_name = target.name_any();
    let attached: Vec<_> = access_policies
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|policy| policy.spec.postgres_policy_ref.name == target_name)
        .collect();

    for policy in &attached {
        if policy.meta().deletion_timestamp.is_none() {
            match access_policies
                .delete(&policy.name_any(), &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    Ok(attached.len())
}

#[derive(Debug, thiserror::Error)]
pub enum EphemeralError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("database/controller error: {0}")]
    Reconcile(#[from] ReconcileError),
    #[error("context error: {0}")]
    Context(#[from] Box<ContextError>),
    #[error("invalid ephemeral access resource: {0}")]
    Invalid(String),
    #[error("waiting for {0} request(s) to be revoked")]
    PendingCleanup(usize),
}

pub async fn reconcile_access_policy(
    resource: Arc<EphemeralAccessPolicy>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, finalizer::Error<EphemeralError>> {
    let namespace = resource
        .namespace()
        .unwrap_or_else(|| "default".to_string());
    let api: Api<EphemeralAccessPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    finalizer::finalizer(&api, ACCESS_POLICY_FINALIZER, resource, |event| async {
        match event {
            FinalizerEvent::Apply(policy) => reconcile_access_policy_apply(&policy, &ctx).await,
            FinalizerEvent::Cleanup(policy) => reconcile_access_policy_cleanup(&policy, &ctx).await,
        }
    })
    .await
}

pub fn access_policy_error_policy(
    _resource: Arc<EphemeralAccessPolicy>,
    error: &finalizer::Error<EphemeralError>,
    _ctx: Arc<OperatorContext>,
) -> Action {
    tracing::warn!(%error, "ephemeral access policy reconciliation failed");
    Action::requeue(RETRY_DELAY)
}

async fn reconcile_access_policy_apply(
    policy: &EphemeralAccessPolicy,
    ctx: &OperatorContext,
) -> Result<Action, EphemeralError> {
    let namespace = policy
        .namespace()
        .ok_or_else(|| EphemeralError::Invalid("resource has no namespace".to_string()))?;
    let maximum = parse_duration(&policy.spec.maximum_duration)?;
    let cluster_maximum =
        cluster_duration("EPHEMERAL_ACCESS_MAXIMUM_DURATION", DEFAULT_CLUSTER_MAXIMUM)?;
    if maximum > cluster_maximum {
        return update_access_policy_failure(
            policy,
            ctx,
            "DurationExceedsClusterMaximum",
            &format!(
                "maximumDuration {} exceeds cluster maximum {}",
                policy.spec.maximum_duration,
                format_duration(cluster_maximum)
            ),
        )
        .await;
    }
    let pending_ttl = parse_duration(&policy.spec.pending_request_ttl)?;
    let cluster_pending_maximum = cluster_duration(
        "EPHEMERAL_ACCESS_MAX_PENDING_TTL",
        DEFAULT_CLUSTER_PENDING_MAXIMUM,
    )?;
    if pending_ttl > cluster_pending_maximum {
        return update_access_policy_failure(
            policy,
            ctx,
            "DurationExceedsClusterMaximum",
            "pendingRequestTTL exceeds the cluster maximum",
        )
        .await;
    }
    if let Some(default_duration) = &policy.spec.default_duration
        && parse_duration(default_duration)? > maximum
    {
        return update_access_policy_failure(
            policy,
            ctx,
            "InvalidDuration",
            "defaultDuration must not exceed maximumDuration",
        )
        .await;
    }
    if policy.spec.memberships.is_empty() {
        return update_access_policy_failure(
            policy,
            ctx,
            "EmptyBundle",
            "at least one membership is required",
        )
        .await;
    }

    let policies: Api<PostgresPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let target = match policies.get(&policy.spec.postgres_policy_ref.name).await {
        Ok(target) => target,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return update_access_policy_failure(
                policy,
                ctx,
                "TargetNotFound",
                "referenced PostgresPolicy does not exist",
            )
            .await;
        }
        Err(error) => return Err(error.into()),
    };
    if target.spec.mode != PolicyMode::Apply {
        return update_access_policy_failure(
            policy,
            ctx,
            "TargetNotApplyMode",
            "ephemeral access requires a PostgresPolicy in apply mode",
        )
        .await;
    }

    let expanded = pgroles_core::manifest::expand_manifest(&target.spec.to_policy_manifest())
        .map_err(ReconcileError::from)?;
    let roles: BTreeMap<_, _> = expanded
        .roles
        .iter()
        .map(|role| (role.name.as_str(), role))
        .collect();
    let mut resolved_roles = BTreeSet::new();
    for membership in &policy.spec.memberships {
        let Some(role) = roles.get(membership.role.as_str()) else {
            return update_access_policy_failure(
                policy,
                ctx,
                "RoleNotFound",
                &format!(
                    "role {} is not in the expanded target policy",
                    membership.role
                ),
            )
            .await;
        };
        if role.external {
            return update_access_policy_failure(
                policy,
                ctx,
                "ExternalTargetRole",
                &format!("role {} is externally managed", membership.role),
            )
            .await;
        }
        if !resolved_roles.insert(membership.role.clone()) {
            return update_access_policy_failure(
                policy,
                ctx,
                "DuplicateMembership",
                &format!("role {} appears more than once", membership.role),
            )
            .await;
        }
    }

    let mut status = policy.status.clone().unwrap_or_default();
    status.observed_generation = policy.metadata.generation;
    status.resolved_roles = resolved_roles.into_iter().collect();
    set_condition(
        &mut status.conditions,
        access_condition("Accepted", true, "Accepted", "Access policy is valid"),
    );
    set_condition(
        &mut status.conditions,
        access_condition("ResolvedRefs", true, "Resolved", "Target roles resolved"),
    );
    patch_access_policy_status(policy, ctx, &status).await?;
    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn update_access_policy_failure(
    policy: &EphemeralAccessPolicy,
    ctx: &OperatorContext,
    reason: &str,
    message: &str,
) -> Result<Action, EphemeralError> {
    let mut status = policy.status.clone().unwrap_or_default();
    status.observed_generation = policy.metadata.generation;
    status.resolved_roles.clear();
    set_condition(
        &mut status.conditions,
        access_condition("Accepted", false, reason, message),
    );
    patch_access_policy_status(policy, ctx, &status).await?;
    Ok(Action::requeue(Duration::from_secs(60)))
}

async fn patch_access_policy_status(
    policy: &EphemeralAccessPolicy,
    ctx: &OperatorContext,
    status: &EphemeralAccessPolicyStatus,
) -> Result<(), kube::Error> {
    let namespace = policy.namespace().unwrap_or_else(|| "default".to_string());
    let api: Api<EphemeralAccessPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    api.patch_status(
        &policy.name_any(),
        &PatchParams::apply("pgroles-operator"),
        &Patch::Merge(serde_json::json!({
            "metadata": { "resourceVersion": policy.resource_version() },
            "status": status,
        })),
    )
    .await?;
    Ok(())
}

async fn reconcile_access_policy_cleanup(
    policy: &EphemeralAccessPolicy,
    ctx: &OperatorContext,
) -> Result<Action, EphemeralError> {
    let namespace = policy
        .namespace()
        .ok_or_else(|| EphemeralError::Invalid("resource has no namespace".to_string()))?;
    let requests: Api<EphemeralAccessRequest> =
        Api::namespaced(ctx.kube_client.clone(), &namespace);
    let policy_uid = policy.uid().unwrap_or_default();
    let mut remaining = 0usize;
    for request in requests.list(&ListParams::default()).await? {
        let resolved_match = request
            .status
            .as_ref()
            .and_then(|status| status.resolved_access.as_ref())
            .is_some_and(|resolved| resolved.access_policy_uid == policy_uid);
        let unresolved_match = request
            .status
            .as_ref()
            .and_then(|status| status.resolved_access.as_ref())
            .is_none()
            && request.spec.access_policy_ref.name == policy.name_any();
        if resolved_match || unresolved_match {
            remaining += 1;
            if request.meta().deletion_timestamp.is_none() {
                match requests
                    .delete(&request.name_any(), &DeleteParams::default())
                    .await
                {
                    Ok(_) => {}
                    Err(kube::Error::Api(error)) if error.code == 404 => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    if remaining > 0 {
        return Err(EphemeralError::PendingCleanup(remaining));
    }
    Ok(Action::await_change())
}

fn access_condition(
    condition_type: &str,
    status: bool,
    reason: &str,
    message: &str,
) -> EphemeralAccessCondition {
    EphemeralAccessCondition {
        condition_type: condition_type.to_string(),
        status: if status { "True" } else { "False" }.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(crate::crd::now_rfc3339()),
        bundle_hash: None,
        granted_duration: None,
    }
}

fn set_condition(
    conditions: &mut Vec<EphemeralAccessCondition>,
    mut condition: EphemeralAccessCondition,
) {
    if let Some(existing) = conditions
        .iter()
        .find(|existing| existing.condition_type == condition.condition_type)
        && existing.status == condition.status
        && existing.reason == condition.reason
        && existing.message == condition.message
        && existing.bundle_hash == condition.bundle_hash
        && existing.granted_duration == condition.granted_duration
    {
        condition.last_transition_time = existing.last_transition_time.clone();
    }
    conditions.retain(|existing| existing.condition_type != condition.condition_type);
    conditions.push(condition);
}

fn parse_duration(value: &str) -> Result<Duration, EphemeralError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(EphemeralError::Invalid(
            "duration must not be empty".to_string(),
        ));
    }
    let mut total = 0u64;
    let mut number = String::new();
    for character in value.chars() {
        if character.is_ascii_digit() {
            number.push(character);
            continue;
        }
        let amount: u64 = number
            .parse()
            .map_err(|_| EphemeralError::Invalid(format!("invalid duration {value:?}")))?;
        number.clear();
        let multiplier = match character {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => {
                return Err(EphemeralError::Invalid(format!(
                    "invalid duration unit {character:?}"
                )));
            }
        };
        total = total
            .checked_add(amount * multiplier)
            .ok_or_else(|| EphemeralError::Invalid("duration is too large".to_string()))?;
    }
    if !number.is_empty() {
        total = total
            .checked_add(
                number
                    .parse()
                    .map_err(|_| EphemeralError::Invalid(format!("invalid duration {value:?}")))?,
            )
            .ok_or_else(|| EphemeralError::Invalid("duration is too large".to_string()))?;
    }
    if total == 0 {
        return Err(EphemeralError::Invalid(
            "duration must be greater than zero".to_string(),
        ));
    }
    Ok(Duration::from_secs(total))
}

fn cluster_duration(variable: &str, default: &str) -> Result<Duration, EphemeralError> {
    parse_duration(&std::env::var(variable).unwrap_or_else(|_| default.to_string()))
}

fn format_duration(duration: Duration) -> String {
    format!("{}s", duration.as_secs())
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn timestamp_from_epoch(seconds: u64) -> String {
    let days = seconds / 86_400;
    let remaining = seconds % 86_400;
    let (year, month, day) = crate::crd::days_to_date(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remaining / 3600,
        (remaining % 3600) / 60,
        remaining % 60
    )
}

fn parse_timestamp(value: &str) -> Option<u64> {
    value
        .parse::<jiff::Timestamp>()
        .ok()
        .and_then(|timestamp| u64::try_from(timestamp.as_second()).ok())
}

pub async fn reconcile_access_request(
    resource: Arc<EphemeralAccessRequest>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, finalizer::Error<EphemeralError>> {
    let namespace = resource
        .namespace()
        .unwrap_or_else(|| "default".to_string());
    let api: Api<EphemeralAccessRequest> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    finalizer::finalizer(&api, ACCESS_REQUEST_FINALIZER, resource, |event| async {
        match event {
            FinalizerEvent::Apply(request) => reconcile_access_request_apply(&request, &ctx).await,
            FinalizerEvent::Cleanup(request) => {
                reconcile_access_request_cleanup(&request, &ctx).await
            }
        }
    })
    .await
}

pub fn access_request_error_policy(
    _resource: Arc<EphemerAccessRequestAlias>,
    error: &finalizer::Error<EphemeralError>,
    _ctx: Arc<OperatorContext>,
) -> Action {
    tracing::warn!(%error, "ephemeral access request reconciliation failed");
    Action::requeue(RETRY_DELAY)
}

// Keep the public error-policy signature readable without repeating a long type
// in generated rustdoc.
type EphemerAccessRequestAlias = EphemeralAccessRequest;

async fn reconcile_access_request_apply(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
) -> Result<Action, EphemeralError> {
    let mut status = request.status.clone().unwrap_or_default();

    if status.resolved_access.is_none() {
        let (resolved, approval_deadline, mode, suspended) = resolve_request(request, ctx).await?;
        if suspended {
            return Err(EphemeralError::Invalid(
                "access policy is suspended".to_string(),
            ));
        }
        status.resolved_access = Some(resolved.clone());
        status.approval_expires_at = Some(timestamp_from_epoch(approval_deadline));
        status.phase = match mode {
            EphemeralApprovalMode::Automatic => EphemeralAccessRequestPhase::Applying,
            EphemeralApprovalMode::Required => EphemeralAccessRequestPhase::PendingApproval,
        };
        set_condition(
            &mut status.conditions,
            access_condition(
                "Resolved",
                true,
                "AccessPolicyResolved",
                "Immutable access bundle resolved",
            ),
        );
        if mode == EphemeralApprovalMode::Automatic {
            persist_activation_deadline(&mut status, &resolved)?;
        }
        patch_request_status(request, ctx, &status).await?;
        audit_transition(request, None, &status, "Resolved");
        return Ok(Action::requeue(Duration::ZERO));
    }

    let resolved = status
        .resolved_access
        .clone()
        .ok_or_else(|| EphemeralError::Invalid("resolved access disappeared".to_string()))?;
    if !resolved.has_valid_bundle_hash() {
        return Err(EphemeralError::Invalid(
            "resolved bundle hash does not match its canonical payload".to_string(),
        ));
    }

    if matches!(
        status.phase,
        EphemeralAccessRequestPhase::Ended
            | EphemeralAccessRequestPhase::Revoked
            | EphemeralAccessRequestPhase::Cancelled
            | EphemeralAccessRequestPhase::Denied
            | EphemeralAccessRequestPhase::ApprovalExpired
            | EphemeralAccessRequestPhase::Failed
    ) {
        return Ok(Action::await_change());
    }

    if decision_condition(&status, "Denied").is_some() {
        if status.phase == EphemeralAccessRequestPhase::Active
            || (status.phase == EphemeralAccessRequestPhase::Applying
                && request_has_scoped_activation_plan(&ctx.kube_client, request, &resolved, true)
                    .await?)
        {
            apply_scoped_memberships(request, ctx, &resolved, ScopedPlanOperation::Revoke).await?;
            status.ended_at = Some(crate::crd::now_rfc3339());
        }
        transition_request(
            request,
            ctx,
            &mut status,
            EphemeralAccessRequestPhase::Denied,
            "Denied",
        )
        .await?;
        return Ok(Action::await_change());
    }

    let (mode, suspended) = if matches!(
        status.phase,
        EphemeralAccessRequestPhase::PendingApproval | EphemeralAccessRequestPhase::Applying
    ) {
        let (current_resolved, _, mode, suspended) = resolve_request(request, ctx).await?;
        let changed = current_resolved.access_policy_uid != resolved.access_policy_uid
            || current_resolved.target_policy_uid != resolved.target_policy_uid
            || current_resolved.compute_bundle_hash() != resolved.bundle_hash
            || current_resolved.granted_duration != resolved.granted_duration;
        if changed || (suspended && status.phase == EphemeralAccessRequestPhase::Applying) {
            if status.phase == EphemeralAccessRequestPhase::Applying
                && request_has_scoped_activation_plan(&ctx.kube_client, request, &resolved, true)
                    .await?
            {
                apply_scoped_memberships(request, ctx, &resolved, ScopedPlanOperation::Revoke)
                    .await?;
                status.ended_at = Some(crate::crd::now_rfc3339());
            }
            transition_request(
                request,
                ctx,
                &mut status,
                EphemeralAccessRequestPhase::Cancelled,
                if changed {
                    "AccessPolicyChanged"
                } else {
                    "AccessPolicySuspended"
                },
            )
            .await?;
            return Ok(Action::await_change());
        }
        (mode, suspended)
    } else {
        (EphemeralApprovalMode::Automatic, false)
    };

    if status.phase == EphemeralAccessRequestPhase::PendingApproval {
        let approval_deadline = status
            .approval_expires_at
            .as_deref()
            .and_then(parse_timestamp)
            .ok_or_else(|| EphemeralError::Invalid("invalid approval deadline".to_string()))?;
        if now_epoch_secs() >= approval_deadline {
            transition_request(
                request,
                ctx,
                &mut status,
                EphemeralAccessRequestPhase::ApprovalExpired,
                "ApprovalExpired",
            )
            .await?;
            return Ok(Action::await_change());
        }
        if suspended {
            return Ok(Action::requeue(Duration::from_secs(
                approval_deadline
                    .saturating_sub(now_epoch_secs())
                    .min(RETRY_DELAY.as_secs())
                    .max(1),
            )));
        }
        let Some(approved) = decision_condition(&status, "Approved") else {
            return Ok(Action::requeue(Duration::from_secs(
                approval_deadline
                    .saturating_sub(now_epoch_secs())
                    .min(RETRY_DELAY.as_secs())
                    .max(1),
            )));
        };
        if mode != EphemeralApprovalMode::Required
            || approved.bundle_hash.as_deref() != Some(resolved.bundle_hash.as_str())
            || approved.granted_duration.as_deref() != Some(resolved.granted_duration.as_str())
        {
            return Err(EphemeralError::Invalid(
                "approval does not attest to the resolved bundle hash and duration".to_string(),
            ));
        }
        persist_activation_deadline(&mut status, &resolved)?;
        transition_request(
            request,
            ctx,
            &mut status,
            EphemeralAccessRequestPhase::Applying,
            "ApprovedBundleApplying",
        )
        .await?;
        return Ok(Action::requeue(Duration::ZERO));
    }

    match status.phase {
        EphemeralAccessRequestPhase::Applying => {
            apply_scoped_memberships(request, ctx, &resolved, ScopedPlanOperation::Activate)
                .await?;
            set_condition(
                &mut status.conditions,
                access_condition(
                    "Applied",
                    true,
                    "MembershipsGranted",
                    "Ephemeral memberships are active",
                ),
            );
            transition_request(
                request,
                ctx,
                &mut status,
                EphemeralAccessRequestPhase::Active,
                "MembershipsGranted",
            )
            .await?;
            let expires_at = status
                .expires_at
                .as_deref()
                .and_then(parse_timestamp)
                .unwrap_or_else(now_epoch_secs);
            Ok(Action::requeue(Duration::from_secs(
                expires_at.saturating_sub(now_epoch_secs()).max(1),
            )))
        }
        EphemeralAccessRequestPhase::Active => {
            let expires_at = status
                .expires_at
                .as_deref()
                .and_then(parse_timestamp)
                .ok_or_else(|| EphemeralError::Invalid("invalid access expiry".to_string()))?;
            if now_epoch_secs() < expires_at {
                return Ok(Action::requeue(Duration::from_secs(
                    expires_at.saturating_sub(now_epoch_secs()).max(1),
                )));
            }
            transition_request(
                request,
                ctx,
                &mut status,
                EphemeralAccessRequestPhase::Revoking,
                "AccessExpired",
            )
            .await?;
            Ok(Action::requeue(Duration::ZERO))
        }
        EphemeralAccessRequestPhase::Revoking => {
            let retained =
                apply_scoped_memberships(request, ctx, &resolved, ScopedPlanOperation::Revoke)
                    .await?;
            status.retained_memberships = retained;
            status.ended_at = Some(crate::crd::now_rfc3339());
            let reason = if status.retained_memberships.is_empty() {
                "MembershipsRevoked"
            } else {
                "MembershipBecamePermanent"
            };
            transition_request(
                request,
                ctx,
                &mut status,
                EphemeralAccessRequestPhase::Ended,
                reason,
            )
            .await?;
            Ok(Action::await_change())
        }
        _ => Ok(Action::requeue(RETRY_DELAY)),
    }
}

fn persist_activation_deadline(
    status: &mut EphemeralAccessRequestStatus,
    resolved: &ResolvedEphemeralAccess,
) -> Result<(), EphemeralError> {
    if status.activated_at.is_some() && status.expires_at.is_some() {
        return Ok(());
    }
    let now = now_epoch_secs();
    let duration = parse_duration(&resolved.granted_duration)?;
    status.activated_at = Some(timestamp_from_epoch(now));
    status.expires_at = Some(timestamp_from_epoch(now + duration.as_secs()));
    Ok(())
}

fn decision_condition<'a>(
    status: &'a EphemeralAccessRequestStatus,
    condition_type: &str,
) -> Option<&'a EphemeralAccessCondition> {
    status
        .conditions
        .iter()
        .find(|condition| condition.condition_type == condition_type && condition.status == "True")
}

async fn resolve_request(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
) -> Result<(ResolvedEphemeralAccess, u64, EphemeralApprovalMode, bool), EphemeralError> {
    let namespace = request
        .namespace()
        .ok_or_else(|| EphemeralError::Invalid("resource has no namespace".to_string()))?;
    let policies: Api<EphemeralAccessPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let policy = policies.get(&request.spec.access_policy_ref.name).await?;
    let accepted = policy.status.as_ref().is_some_and(|status| {
        status
            .conditions
            .iter()
            .any(|condition| condition.condition_type == "Accepted" && condition.status == "True")
    });
    if !accepted {
        return Err(EphemeralError::Invalid(
            "access policy is not Accepted".to_string(),
        ));
    }
    if policy.spec.justification.required
        && request
            .spec
            .justification
            .as_deref()
            .is_none_or(|justification| justification.trim().is_empty())
    {
        return Err(EphemeralError::Invalid(
            "justification is required".to_string(),
        ));
    }

    let target_api: Api<PostgresPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let target = target_api
        .get(&policy.spec.postgres_policy_ref.name)
        .await?;
    if target.spec.mode != PolicyMode::Apply {
        return Err(EphemeralError::Invalid(
            "target PostgresPolicy must be in apply mode".to_string(),
        ));
    }
    let expanded_target =
        pgroles_core::manifest::expand_manifest(&target.spec.to_policy_manifest())
            .map_err(ReconcileError::from)?;
    if !expanded_target
        .roles
        .iter()
        .any(|role| role.name == request.spec.subject.role)
    {
        return Err(EphemeralError::Invalid(format!(
            "subject role {} is not in the expanded target policy",
            request.spec.subject.role
        )));
    }
    let requested = match request
        .spec
        .requested_duration
        .as_ref()
        .or(policy.spec.default_duration.as_ref())
    {
        Some(duration) => parse_duration(duration)?,
        None => {
            return Err(EphemeralError::Invalid(
                "requestedDuration or defaultDuration is required".to_string(),
            ));
        }
    };
    if requested > parse_duration(&policy.spec.maximum_duration)? {
        return Err(EphemeralError::Invalid(
            "requested duration exceeds policy maximum".to_string(),
        ));
    }

    let memberships = policy
        .spec
        .memberships
        .iter()
        .map(|membership| ResolvedEphemeralMembership {
            role: membership.role.clone(),
            member: request.spec.subject.role.clone(),
            inherit: membership.inherit,
        })
        .collect::<Vec<_>>();
    let mut resolved = ResolvedEphemeralAccess {
        access_policy_uid: policy.uid().unwrap_or_default(),
        access_policy_generation: policy.metadata.generation.unwrap_or(0),
        target_policy_uid: target.uid().unwrap_or_default(),
        target_policy_generation: target.metadata.generation.unwrap_or(0),
        granted_duration: format_duration(requested),
        bundle_encoding: EPHEMERAL_BUNDLE_ENCODING_V1.to_string(),
        bundle_hash: String::new(),
        memberships,
    };
    resolved.bundle_hash = resolved.compute_bundle_hash();
    let pending_deadline = request
        .status
        .as_ref()
        .and_then(|status| status.approval_expires_at.as_deref())
        .and_then(parse_timestamp)
        .unwrap_or(now_epoch_secs() + parse_duration(&policy.spec.pending_request_ttl)?.as_secs());
    Ok((
        resolved,
        pending_deadline,
        policy.spec.approval.mode,
        policy.spec.suspend || target.spec.suspend,
    ))
}

async fn patch_request_status(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
    status: &EphemeralAccessRequestStatus,
) -> Result<(), kube::Error> {
    let namespace = request.namespace().unwrap_or_else(|| "default".to_string());
    let api: Api<EphemeralAccessRequest> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    api.patch_status(
        &request.name_any(),
        &PatchParams::apply("pgroles-operator"),
        &Patch::Merge(serde_json::json!({
            "metadata": { "resourceVersion": request.resource_version() },
            "status": status,
        })),
    )
    .await?;
    Ok(())
}

async fn transition_request(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
    status: &mut EphemeralAccessRequestStatus,
    phase: EphemeralAccessRequestPhase,
    reason: &str,
) -> Result<(), EphemeralError> {
    let previous = status.phase;
    status.phase = phase;
    status.last_error = None;
    patch_request_status(request, ctx, status).await?;
    audit_transition(request, Some(previous), status, reason);
    Ok(())
}

fn audit_transition(
    request: &EphemeralAccessRequest,
    previous: Option<EphemeralAccessRequestPhase>,
    status: &EphemeralAccessRequestStatus,
    reason: &str,
) {
    let resolved = status.resolved_access.as_ref();
    tracing::info!(
        audit_event = "pgroles.ephemeral_access.lifecycle",
        request_name = %request.name_any(),
        request_uid = %request.uid().unwrap_or_default(),
        access_policy_uid = %resolved.map(|value| value.access_policy_uid.as_str()).unwrap_or(""),
        target_policy_uid = %resolved.map(|value| value.target_policy_uid.as_str()).unwrap_or(""),
        bundle_hash = %resolved.map(|value| value.bundle_hash.as_str()).unwrap_or(""),
        subject = %request.spec.subject.role,
        previous_phase = %previous.map(|value| value.to_string()).unwrap_or_default(),
        phase = %status.phase,
        reason,
        activated_at = %status.activated_at.as_deref().unwrap_or(""),
        expires_at = %status.expires_at.as_deref().unwrap_or(""),
        ended_at = %status.ended_at.as_deref().unwrap_or(""),
        "ephemeral access lifecycle transition"
    );
}

async fn reconcile_access_request_cleanup(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
) -> Result<Action, EphemeralError> {
    if let Some(status) = request.status.as_ref()
        && let Some(resolved) = status.resolved_access.as_ref()
        && matches!(
            status.phase,
            EphemeralAccessRequestPhase::Applying
                | EphemeralAccessRequestPhase::Active
                | EphemeralAccessRequestPhase::Revoking
        )
    {
        apply_scoped_memberships(request, ctx, resolved, ScopedPlanOperation::Revoke).await?;
        let mut ended = status.clone();
        ended.phase = EphemeralAccessRequestPhase::Revoked;
        ended.ended_at = Some(crate::crd::now_rfc3339());
        audit_transition(request, Some(status.phase), &ended, "RequestDeleted");
    }
    Ok(Action::await_change())
}

type MembershipKey = (String, String);

fn membership_key(membership: &ResolvedEphemeralMembership) -> MembershipKey {
    (membership.role.clone(), membership.member.clone())
}

fn graph_membership_key(membership: &pgroles_core::model::MembershipEdge) -> MembershipKey {
    (membership.role.clone(), membership.member.clone())
}

/// Merge currently owned ephemeral edges into an ordinary policy's desired
/// graph. Callers must hold both the in-process and PostgreSQL advisory locks.
pub async fn compose_effective_graph(
    client: &kube::Client,
    policy: &PostgresPolicy,
    desired: &mut pgroles_core::model::RoleGraph,
) -> Result<BTreeSet<String>, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_uid = policy.uid().unwrap_or_default();
    let requests: Api<EphemeralAccessRequest> = Api::namespaced(client.clone(), &namespace);
    let plans: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let scoped_plans = plans.list(&ListParams::default()).await?;
    let mut additional_roles = BTreeSet::new();
    let mut overlays: BTreeMap<MembershipKey, pgroles_core::model::MembershipEdge> =
        BTreeMap::new();

    for request in requests.list(&ListParams::default()).await? {
        let Some(status) = request.status.as_ref() else {
            continue;
        };
        if !matches!(
            status.phase,
            EphemeralAccessRequestPhase::Applying | EphemeralAccessRequestPhase::Active
        ) {
            continue;
        }
        let Some(resolved) = status.resolved_access.as_ref() else {
            continue;
        };
        if status.phase == EphemeralAccessRequestPhase::Applying
            && !scoped_plans
                .items
                .iter()
                .any(|plan| plan_authorizes_activation(plan, &request, resolved, true))
        {
            continue;
        }
        if resolved.target_policy_uid != policy_uid || !resolved.has_valid_bundle_hash() {
            continue;
        }
        for membership in &resolved.memberships {
            if !desired.roles.contains_key(&membership.role)
                || !desired.roles.contains_key(&membership.member)
            {
                return Err(ReconcileError::InvalidSpec(format!(
                    "active ephemeral request {} blocks removal of membership role {} or subject {}",
                    request.name_any(),
                    membership.role,
                    membership.member
                )));
            }
            additional_roles.insert(membership.role.clone());
            additional_roles.insert(membership.member.clone());
            let edge = pgroles_core::model::MembershipEdge {
                role: membership.role.clone(),
                member: membership.member.clone(),
                inherit: membership.inherit,
                admin: false,
            };
            let key = membership_key(membership);
            if let Some(durable) = desired
                .memberships
                .iter()
                .find(|candidate| graph_membership_key(candidate) == key)
            {
                if durable.inherit != edge.inherit || durable.admin {
                    tracing::warn!(
                        role = %edge.role,
                        member = %edge.member,
                        "durable membership now owns an ephemeral key with different options"
                    );
                }
                continue;
            }
            if let Some(existing) = overlays.get(&key)
                && existing != &edge
            {
                return Err(ReconcileError::InvalidSpec(format!(
                    "active ephemeral requests conflict on membership {} -> {}",
                    edge.member, edge.role
                )));
            }
            overlays.insert(key, edge);
        }
    }
    desired.memberships.extend(overlays.into_values());
    Ok(additional_roles)
}

async fn apply_scoped_memberships(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
    resolved: &ResolvedEphemeralAccess,
    operation: ScopedPlanOperation,
) -> Result<Vec<ResolvedEphemeralMembership>, EphemeralError> {
    let namespace = request
        .namespace()
        .ok_or_else(|| EphemeralError::Invalid("resource has no namespace".to_string()))?;
    let access_policies: Api<EphemeralAccessPolicy> =
        Api::namespaced(ctx.kube_client.clone(), &namespace);
    let access_policy = access_policies
        .get(&request.spec.access_policy_ref.name)
        .await?;
    if access_policy.uid().as_deref() != Some(resolved.access_policy_uid.as_str()) {
        return Err(EphemeralError::Invalid(
            "access policy UID no longer matches resolved access".to_string(),
        ));
    }
    let policies: Api<PostgresPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let target = policies
        .get(&access_policy.spec.postgres_policy_ref.name)
        .await?;
    if target.uid().as_deref() != Some(resolved.target_policy_uid.as_str()) {
        return Err(EphemeralError::Invalid(
            "target policy UID no longer matches resolved access".to_string(),
        ));
    }
    let identity = DatabaseIdentity::from_connection(&namespace, &target.spec.connection);
    let pool = ctx
        .get_or_create_pool(&namespace, &target.spec.connection)
        .await
        .map_err(Box::new)?;
    let _database_lock = ctx
        .try_lock_database(identity.as_str())
        .await
        .ok_or_else(|| {
            ReconcileError::LockContention(
                identity.as_str().to_string(),
                "in-process lock held by another reconcile".to_string(),
            )
        })?;
    let advisory_lock = crate::advisory::try_acquire(&pool, identity.as_str())
        .await
        .map_err(ReconcileError::from)?
        .ok_or_else(|| {
            ReconcileError::LockContention(
                identity.as_str().to_string(),
                "PostgreSQL advisory lock held by another reconcile".to_string(),
            )
        })?;

    let result = apply_scoped_memberships_under_lock(
        request,
        ctx,
        resolved,
        operation,
        &target,
        &pool,
        identity.as_str(),
    )
    .await;
    advisory_lock.release().await;
    result
}

async fn apply_scoped_memberships_under_lock(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
    resolved: &ResolvedEphemeralAccess,
    operation: ScopedPlanOperation,
    target: &PostgresPolicy,
    pool: &sqlx::PgPool,
    database_identity: &str,
) -> Result<Vec<ResolvedEphemeralMembership>, EphemeralError> {
    let manifest = target.spec.to_policy_manifest();
    let expanded =
        pgroles_core::manifest::expand_manifest(&manifest).map_err(ReconcileError::from)?;
    let mut durable =
        pgroles_core::model::RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref())
            .map_err(ReconcileError::from)?;
    let durable_memberships = durable.memberships.clone();
    let mut additional_roles =
        compose_effective_graph(&ctx.kube_client, target, &mut durable).await?;
    for membership in &resolved.memberships {
        additional_roles.insert(membership.role.clone());
        additional_roles.insert(membership.member.clone());
    }
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|grant| grant.object.object_type == pgroles_core::manifest::ObjectType::Database);
    let inspect_config =
        pgroles_inspect::InspectConfig::from_expanded(&expanded, has_database_grants)
            .with_additional_roles(additional_roles);
    let inspection = pgroles_inspect::inspect_with_diagnostics(pool, &inspect_config)
        .await
        .map_err(ReconcileError::from)?;
    let current = inspection.graph;

    let request_keys: BTreeSet<_> = resolved.memberships.iter().map(membership_key).collect();
    let current_by_key: BTreeMap<_, _> = current
        .memberships
        .iter()
        .map(|edge| (graph_membership_key(edge), edge))
        .collect();
    let durable_by_key: BTreeMap<_, _> = durable_memberships
        .iter()
        .map(|edge| (graph_membership_key(edge), edge))
        .collect();
    let other_owners = active_owner_keys(
        &ctx.kube_client,
        target,
        Some(request.uid().unwrap_or_default().as_str()),
    )
    .await?;
    let request_has_activation_plan =
        request_has_scoped_activation_plan(&ctx.kube_client, request, resolved, true).await?;

    let mut changes = Vec::new();
    let mut retained = Vec::new();
    match operation {
        ScopedPlanOperation::Activate => {
            for membership in &resolved.memberships {
                let key = membership_key(membership);
                if durable_by_key.contains_key(&key) {
                    return Err(EphemeralError::Invalid(format!(
                        "membership {} -> {} is already durable",
                        membership.member, membership.role
                    )));
                }
                if let Some(existing) = current_by_key.get(&key) {
                    if (other_owners.contains(&key) || request_has_activation_plan)
                        && existing.inherit == membership.inherit
                        && !existing.admin
                    {
                        continue;
                    }
                    return Err(EphemeralError::Invalid(format!(
                        "membership {} -> {} already exists without matching ephemeral ownership",
                        membership.member, membership.role
                    )));
                }
                changes.push(pgroles_core::diff::Change::AddMember {
                    role: membership.role.clone(),
                    member: membership.member.clone(),
                    inherit: membership.inherit,
                    admin: false,
                });
            }
        }
        ScopedPlanOperation::Revoke => {
            for membership in &resolved.memberships {
                let key = membership_key(membership);
                if durable_by_key.contains_key(&key) {
                    retained.push(membership.clone());
                    continue;
                }
                if other_owners.contains(&key) {
                    continue;
                }
                if current_by_key.contains_key(&key) {
                    changes.push(pgroles_core::diff::Change::RemoveMember {
                        role: membership.role.clone(),
                        member: membership.member.clone(),
                    });
                }
            }
        }
    }

    for change in &changes {
        let key = match change {
            pgroles_core::diff::Change::AddMember { role, member, .. }
            | pgroles_core::diff::Change::RemoveMember { role, member } => {
                (role.clone(), member.clone())
            }
            _ => {
                return Err(EphemeralError::Invalid(
                    "scoped plan contained a non-membership change".to_string(),
                ));
            }
        };
        if !request_keys.contains(&key) {
            return Err(EphemeralError::Invalid(
                "scoped plan escaped the approved bundle".to_string(),
            ));
        }
    }

    let sql_context = crate::reconciler::detect_sql_context(pool, &inspect_config).await?;
    let plan = create_scoped_plan(
        request,
        ctx,
        target,
        resolved,
        operation,
        ScopedPlanExecution {
            database_identity,
            changes: &changes,
            sql_context: &sql_context,
        },
    )
    .await?;
    if plan
        .status
        .as_ref()
        .is_some_and(|status| status.phase == PlanPhase::Applied)
    {
        return Ok(retained);
    }
    match crate::plan::execute_changes_in_transaction(pool, &changes, &sql_context).await {
        Ok(statements) => {
            finish_scoped_plan(ctx, &plan, PlanPhase::Applied, None).await?;
            tracing::info!(
                request_uid = %request.uid().unwrap_or_default(),
                bundle_hash = %resolved.bundle_hash,
                operation = ?operation,
                statements,
                "scoped ephemeral membership plan applied"
            );
        }
        Err(error) => {
            finish_scoped_plan(ctx, &plan, PlanPhase::Failed, Some(error.to_string())).await?;
            return Err(error.into());
        }
    }
    Ok(retained)
}

async fn active_owner_keys(
    client: &kube::Client,
    target: &PostgresPolicy,
    exclude_request_uid: Option<&str>,
) -> Result<BTreeSet<MembershipKey>, kube::Error> {
    let namespace = target.namespace().unwrap_or_else(|| "default".to_string());
    let target_uid = target.uid().unwrap_or_default();
    let requests: Api<EphemeralAccessRequest> = Api::namespaced(client.clone(), &namespace);
    let plans: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let scoped_plans = plans.list(&ListParams::default()).await?;
    let mut keys = BTreeSet::new();
    for request in requests.list(&ListParams::default()).await? {
        if exclude_request_uid.is_some_and(|uid| request.uid().as_deref() == Some(uid)) {
            continue;
        }
        let Some(status) = request.status.as_ref() else {
            continue;
        };
        if !matches!(
            status.phase,
            EphemeralAccessRequestPhase::Applying | EphemeralAccessRequestPhase::Active
        ) {
            continue;
        }
        let Some(resolved) = status.resolved_access.as_ref() else {
            continue;
        };
        if status.phase == EphemeralAccessRequestPhase::Applying
            && !scoped_plans
                .items
                .iter()
                .any(|plan| plan_authorizes_activation(plan, &request, resolved, true))
        {
            continue;
        }
        if resolved.target_policy_uid == target_uid && resolved.has_valid_bundle_hash() {
            keys.extend(resolved.memberships.iter().map(membership_key));
        }
    }
    Ok(keys)
}

fn plan_authorizes_activation(
    plan: &PostgresPolicyPlan,
    request: &EphemeralAccessRequest,
    resolved: &ResolvedEphemeralAccess,
    include_applying: bool,
) -> bool {
    let request_uid = request.uid().unwrap_or_default();
    let owned_by_request = plan
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners.iter().any(|owner| {
                owner.controller == Some(true)
                    && owner.kind == "EphemeralAccessRequest"
                    && owner.uid == request_uid
            })
        });
    let matching_origin =
        plan.spec.origin.as_ref().is_some_and(|origin| {
            origin.kind == "EphemeralAccessRequest" && origin.uid == request_uid
        });
    let matching_scope = plan.spec.scope.as_ref().is_some_and(|scope| {
        scope.operation == ScopedPlanOperation::Activate
            && scope.bundle_hash == resolved.bundle_hash
    });
    let usable_phase = plan.status.as_ref().map_or(include_applying, |status| {
        status.phase == PlanPhase::Applied
            || (include_applying && status.phase == PlanPhase::Applying)
    });
    owned_by_request && matching_origin && matching_scope && usable_phase
}

async fn request_has_scoped_activation_plan(
    client: &kube::Client,
    request: &EphemeralAccessRequest,
    resolved: &ResolvedEphemeralAccess,
    include_applying: bool,
) -> Result<bool, kube::Error> {
    let namespace = request.namespace().unwrap_or_else(|| "default".to_string());
    let plans: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    Ok(plans
        .list(&ListParams::default())
        .await?
        .items
        .iter()
        .any(|plan| plan_authorizes_activation(plan, request, resolved, include_applying)))
}

struct ScopedPlanExecution<'a> {
    database_identity: &'a str,
    changes: &'a [pgroles_core::diff::Change],
    sql_context: &'a pgroles_core::sql::SqlContext,
}

async fn create_scoped_plan(
    request: &EphemeralAccessRequest,
    ctx: &OperatorContext,
    target: &PostgresPolicy,
    resolved: &ResolvedEphemeralAccess,
    operation: ScopedPlanOperation,
    execution: ScopedPlanExecution<'_>,
) -> Result<PostgresPolicyPlan, EphemeralError> {
    let namespace = request.namespace().unwrap_or_else(|| "default".to_string());
    let operation_name = match operation {
        ScopedPlanOperation::Activate => "activate",
        ScopedPlanOperation::Revoke => "revoke",
    };
    let suffix = &resolved.bundle_hash.trim_start_matches("sha256:")[..12];
    let prefix = crate::k8s_names::sanitize_dns_label_segment(&request.name_any(), "request");
    let max_prefix = 253usize.saturating_sub(operation_name.len() + suffix.len() + 2);
    let prefix = crate::k8s_names::truncate_name_prefix(&prefix, max_prefix);
    let name = format!("{prefix}-{operation_name}-{suffix}");
    let mut plan = PostgresPolicyPlan::new(
        &name,
        PostgresPolicyPlanSpec {
            policy_ref: PolicyPlanRef {
                name: target.name_any(),
            },
            policy_generation: target.metadata.generation.unwrap_or(0),
            reconciliation_mode: target.spec.reconciliation_mode,
            owned_roles: resolved
                .memberships
                .iter()
                .flat_map(|membership| [membership.role.clone(), membership.member.clone()])
                .collect(),
            owned_schemas: Vec::new(),
            managed_database_identity: execution.database_identity.to_string(),
            origin: Some(PlanOrigin {
                kind: "EphemeralAccessRequest".to_string(),
                name: request.name_any(),
                uid: request.uid().unwrap_or_default(),
            }),
            scope: Some(PlanScope {
                kind: "MembershipBundle".to_string(),
                operation,
                bundle_hash: resolved.bundle_hash.clone(),
            }),
        },
    );
    plan.metadata.namespace = Some(namespace.clone());
    plan.metadata.owner_references = request.controller_owner_ref(&()).map(|owner| vec![owner]);
    let initial_status = PostgresPolicyPlanStatus {
        phase: PlanPhase::Applying,
        conditions: vec![PolicyCondition {
            condition_type: "Scoped".to_string(),
            status: "True".to_string(),
            reason: Some(operation_name.to_string()),
            message: Some("Authorized by EphemeralAccessRequest lifecycle".to_string()),
            last_transition_time: Some(crate::crd::now_rfc3339()),
        }],
        change_summary: Some(scoped_change_summary(execution.changes)),
        sql_inline: Some(pgroles_core::sql::render_all_with_context(
            execution.changes,
            execution.sql_context,
        )),
        computed_at: Some(crate::crd::now_rfc3339()),
        applying_since: Some(crate::crd::now_rfc3339()),
        sql_hash: Some(crate::plan::compute_sql_hash(
            &pgroles_core::sql::render_all_with_context(execution.changes, execution.sql_context),
        )),
        sql_statements: Some(execution.changes.len() as i64),
        ..Default::default()
    };
    let plans: Api<PostgresPolicyPlan> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    match plans.create(&PostParams::default(), &plan).await {
        Ok(created) => Ok(plans
            .patch_status(
                &created.name_any(),
                &PatchParams::apply("pgroles-operator"),
                &Patch::Merge(serde_json::json!({ "status": initial_status })),
            )
            .await?),
        Err(kube::Error::Api(error)) if error.code == 409 => Ok(plans.get(&name).await?),
        Err(error) => Err(error.into()),
    }
}

fn scoped_change_summary(changes: &[pgroles_core::diff::Change]) -> ChangeSummary {
    let mut summary = ChangeSummary::default();
    for change in changes {
        match change {
            pgroles_core::diff::Change::AddMember { .. } => summary.members_added += 1,
            pgroles_core::diff::Change::RemoveMember { .. } => summary.members_removed += 1,
            _ => {}
        }
    }
    summary.total = changes.len() as i32;
    summary
}

async fn finish_scoped_plan(
    ctx: &OperatorContext,
    plan: &PostgresPolicyPlan,
    phase: PlanPhase,
    error: Option<String>,
) -> Result<(), kube::Error> {
    let namespace = plan.namespace().unwrap_or_else(|| "default".to_string());
    let plans: Api<PostgresPolicyPlan> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let mut status = plan.status.clone().unwrap_or_default();
    status.phase = phase.clone();
    status.last_error = error;
    if phase == PlanPhase::Applied {
        status.applied_at = Some(crate::crd::now_rfc3339());
    } else if phase == PlanPhase::Failed {
        status.failed_at = Some(crate::crd::now_rfc3339());
    }
    plans
        .patch_status(
            &plan.name_any(),
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_accepts_compound_values_and_canonicalizes() {
        let duration = parse_duration("1h30m15s").expect("duration should parse");
        assert_eq!(duration, Duration::from_secs(5_415));
        assert_eq!(format_duration(duration), "5415s");
    }

    #[test]
    fn duration_parser_rejects_zero_and_unknown_units() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("5d").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn timestamp_round_trips_epoch_seconds() {
        let timestamp = timestamp_from_epoch(1_735_689_845);
        assert_eq!(parse_timestamp(&timestamp), Some(1_735_689_845));
    }

    #[test]
    fn setting_lifecycle_condition_preserves_decision_condition() {
        let mut conditions = vec![EphemeralAccessCondition {
            condition_type: "Approved".into(),
            status: "True".into(),
            reason: Some("ApprovedByTest".into()),
            message: None,
            last_transition_time: Some("2026-08-11T00:00:00Z".into()),
            bundle_hash: Some("sha256:test".into()),
            granted_duration: Some("1800s".into()),
        }];
        set_condition(
            &mut conditions,
            access_condition("Applied", true, "Applied", "done"),
        );
        assert!(
            conditions
                .iter()
                .any(|condition| condition.condition_type == "Approved")
        );
        assert!(
            conditions
                .iter()
                .any(|condition| condition.condition_type == "Applied")
        );
    }

    #[test]
    fn applying_overlay_requires_request_owned_activation_plan() {
        let mut request = EphemeralAccessRequest::new(
            "request",
            crate::crd::EphemeralAccessRequestSpec {
                access_policy_ref: crate::crd::LocalObjectReference {
                    name: "access".into(),
                },
                subject: crate::crd::EphemeralAccessSubject {
                    role: "alice".into(),
                },
                requested_duration: Some("30m".into()),
                justification: Some("test".into()),
            },
        );
        request.metadata.namespace = Some("default".into());
        request.metadata.uid = Some("request-uid".into());
        let resolved = ResolvedEphemeralAccess {
            access_policy_uid: "access-uid".into(),
            access_policy_generation: 1,
            target_policy_uid: "target-uid".into(),
            target_policy_generation: 1,
            granted_duration: "1800s".into(),
            bundle_encoding: crate::crd::EPHEMERAL_BUNDLE_ENCODING_V1.into(),
            bundle_hash: "sha256:bundle".into(),
            memberships: Vec::new(),
        };
        let mut plan = PostgresPolicyPlan::new(
            "activation",
            PostgresPolicyPlanSpec {
                policy_ref: PolicyPlanRef {
                    name: "target".into(),
                },
                policy_generation: 1,
                reconciliation_mode: crate::crd::CrdReconciliationMode::Authoritative,
                owned_roles: Vec::new(),
                owned_schemas: Vec::new(),
                managed_database_identity: "default/database".into(),
                origin: Some(PlanOrigin {
                    kind: "EphemeralAccessRequest".into(),
                    name: "request".into(),
                    uid: "request-uid".into(),
                }),
                scope: Some(PlanScope {
                    kind: "MembershipBundle".into(),
                    operation: ScopedPlanOperation::Activate,
                    bundle_hash: "sha256:bundle".into(),
                }),
            },
        );

        assert!(!plan_authorizes_activation(
            &plan, &request, &resolved, true
        ));
        plan.metadata.owner_references = request.controller_owner_ref(&()).map(|owner| vec![owner]);
        assert!(plan_authorizes_activation(&plan, &request, &resolved, true));
        assert!(!plan_authorizes_activation(
            &plan, &request, &resolved, false
        ));

        plan.status = Some(PostgresPolicyPlanStatus {
            phase: PlanPhase::Applied,
            ..Default::default()
        });
        assert!(plan_authorizes_activation(
            &plan, &request, &resolved, false
        ));
        plan.spec.scope.as_mut().expect("scope").bundle_hash = "sha256:other".into();
        assert!(!plan_authorizes_activation(
            &plan, &request, &resolved, true
        ));
    }
}
