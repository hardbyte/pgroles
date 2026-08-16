//! Transition-based Kubernetes Events for `PostgresPolicy` resources.
//!
//! Events complement status conditions:
//! - status remains the source of truth for the current state
//! - Events surface notable transitions in `kubectl describe`
//! - OTLP metrics remain the fleet-level observability path

use k8s_openapi::api::core::v1::ObjectReference;
use kube::Resource;
use kube::runtime::events::{Event, EventType, Recorder};

use crate::crd::{
    EphemeralAccessRequest, EphemeralAccessRequestPhase, PolicyCondition, PostgresPolicy,
    PostgresPolicyCandidate, PostgresPolicyPlan, PostgresPolicyStatus,
};

/// Publish a request lifecycle Event on the request object itself.
pub async fn publish_ephemeral_request_event(
    recorder: &Recorder,
    request: &EphemeralAccessRequest,
    phase: EphemeralAccessRequestPhase,
    reason: &str,
    note: String,
) -> Result<(), kube::Error> {
    let reference: ObjectReference = request.object_ref(&());
    let event_type = if matches!(
        phase,
        EphemeralAccessRequestPhase::Failed
            | EphemeralAccessRequestPhase::Denied
            | EphemeralAccessRequestPhase::ApprovalExpired
    ) {
        EventType::Warning
    } else {
        EventType::Normal
    };
    recorder
        .publish(
            &event(event_type, reason, "EphemeralAccessLifecycle", note),
            &reference,
        )
        .await
}

/// Publish Kubernetes Events for notable status transitions.
pub async fn publish_status_events(
    recorder: &Recorder,
    resource: &PostgresPolicy,
    old_status: Option<&PostgresPolicyStatus>,
    new_status: &PostgresPolicyStatus,
) -> Result<(), kube::Error> {
    let reference: ObjectReference = resource.object_ref(&());
    for event in derive_status_events(old_status, new_status) {
        recorder.publish(&event, &reference).await?;
    }
    Ok(())
}

/// Publish a Warning Event on a policy for a condition that has no status
/// representation of its own.
pub async fn publish_policy_warning(
    recorder: &Recorder,
    policy: &PostgresPolicy,
    reason: &str,
    action: &str,
    note: String,
) -> Result<(), kube::Error> {
    let reference: ObjectReference = policy.object_ref(&());
    recorder
        .publish(&event(EventType::Warning, reason, action, note), &reference)
        .await
}

/// Publish a candidate lifecycle Event on the candidate itself.
///
/// On the candidate rather than the policy: a policy may carry many open
/// proposals, and a stream of their transitions on the policy's Event list
/// would bury the policy's own. `reason` is the condition reason the same
/// transition writes, so `kubectl describe` and `kubectl get` agree.
pub async fn publish_candidate_event(
    recorder: &Recorder,
    candidate: &PostgresPolicyCandidate,
    warning: bool,
    reason: &str,
    note: String,
) -> Result<(), kube::Error> {
    let reference: ObjectReference = candidate.object_ref(&());
    let event_type = if warning {
        EventType::Warning
    } else {
        EventType::Normal
    };
    recorder
        .publish(
            &event(event_type, reason, "CandidateLifecycle", note),
            &reference,
        )
        .await
}

/// Publish a plan lifecycle event on the parent policy.
pub async fn publish_plan_event(
    recorder: &Recorder,
    policy: &PostgresPolicy,
    plan: &PostgresPolicyPlan,
    event_type: PlanEventType,
) -> Result<(), kube::Error> {
    let reference: ObjectReference = policy.object_ref(&());
    let plan_name = kube::ResourceExt::name_any(plan);
    let event = match event_type {
        PlanEventType::Created { change_count } => event(
            EventType::Normal,
            "PlanCreated",
            "PlanLifecycle",
            format!("Plan {plan_name} created with {change_count} change(s)"),
        ),
        PlanEventType::Approved => event(
            EventType::Normal,
            "PlanApproved",
            "PlanLifecycle",
            format!("Plan {plan_name} approved"),
        ),
        PlanEventType::Rejected => event(
            EventType::Normal,
            "PlanRejected",
            "PlanLifecycle",
            format!("Plan {plan_name} rejected"),
        ),
        PlanEventType::ApplyStarted => event(
            EventType::Normal,
            "ApplyStarted",
            "PlanLifecycle",
            format!("Executing plan {plan_name}"),
        ),
        PlanEventType::ApplySucceeded => event(
            EventType::Normal,
            "ApplySucceeded",
            "PlanLifecycle",
            format!("Plan {plan_name} applied successfully"),
        ),
        PlanEventType::TargetIdentityChanged { reason, detail } => event(
            EventType::Warning,
            &reason,
            "TargetIdentity",
            format!("Plan {plan_name} cannot execute: {detail}"),
        ),
        PlanEventType::ApplyFailed { error } => event(
            EventType::Warning,
            "ApplyFailed",
            "PlanLifecycle",
            format!("Plan {plan_name} failed: {error}"),
        ),
    };
    recorder.publish(&event, &reference).await
}

/// Types of plan lifecycle events.
pub enum PlanEventType {
    /// A new plan was computed.
    Created { change_count: i32 },
    /// Approval annotation detected on a plan.
    Approved,
    /// Rejection annotation detected on a plan.
    Rejected,
    /// Plan execution has started.
    ApplyStarted,
    /// Plan execution completed successfully.
    ApplySucceeded,
    /// Plan execution failed.
    ApplyFailed { error: String },
    /// The database the plan was approved against is not the one it would now
    /// execute against, or an identity bound at approval can no longer be
    /// read. `reason` is the machine-readable condition reason.
    TargetIdentityChanged { reason: String, detail: String },
}

fn derive_status_events(
    old_status: Option<&PostgresPolicyStatus>,
    new_status: &PostgresPolicyStatus,
) -> Vec<Event> {
    let mut events = Vec::new();

    if transitioned_to_true(old_status, new_status, "Conflict") {
        let note = condition_message(new_status, "Conflict")
            .or_else(|| new_status.last_error.clone())
            .unwrap_or_else(|| "Policy ownership conflict detected".to_string());
        events.push(event(
            EventType::Warning,
            "ConflictDetected",
            "StatusTransition",
            note,
        ));
    }

    if transitioned_from_true(old_status, new_status, "Conflict") {
        events.push(event(
            EventType::Normal,
            "ConflictResolved",
            "StatusTransition",
            "Policy ownership conflict resolved".to_string(),
        ));
    }

    if transitioned_to_true(old_status, new_status, "Paused") {
        let note = condition_message(new_status, "Paused")
            .unwrap_or_else(|| "Reconciliation suspended by spec".to_string());
        events.push(event(
            EventType::Normal,
            "Suspended",
            "StatusTransition",
            note,
        ));
    }

    if transitioned_to_true(old_status, new_status, "Drifted") {
        let note = condition_message(new_status, "Drifted")
            .unwrap_or_else(|| "Planned changes are pending review".to_string());
        events.push(event(
            EventType::Normal,
            "DriftDetected",
            "StatusTransition",
            note,
        ));
    }

    if plan_became_clean(old_status, new_status) {
        let note = condition_message(new_status, "Drifted")
            .unwrap_or_else(|| "Plan computed; database already matches desired state".to_string());
        events.push(event(
            EventType::Normal,
            "PlanClean",
            "StatusTransition",
            note,
        ));
    }

    if ready_became_true(old_status, new_status) && !is_planned_ready(new_status) {
        let reason = if had_ready_condition(old_status) {
            "Recovered"
        } else {
            "Reconciled"
        };
        let note = condition_message(new_status, "Ready")
            .unwrap_or_else(|| "Policy reconciled successfully".to_string());
        events.push(event(EventType::Normal, reason, "StatusTransition", note));
    }

    if transitioned_to_true(
        old_status,
        new_status,
        crate::crd::CONDITION_APPROVAL_IGNORED,
    ) {
        let note = condition_message(new_status, crate::crd::CONDITION_APPROVAL_IGNORED)
            .unwrap_or_else(|| "Plan approval has no effect in observe mode".to_string());
        events.push(event(
            EventType::Warning,
            "ApprovalIgnored",
            "StatusTransition",
            note,
        ));
    }

    if transitioned_to_true(old_status, new_status, crate::crd::CONDITION_APPROVAL_UNSET) {
        let note = condition_message(new_status, crate::crd::CONDITION_APPROVAL_UNSET)
            .unwrap_or_else(|| "spec.approval is not set and is being inferred".to_string());
        events.push(event(
            EventType::Warning,
            "ApprovalUnset",
            "StatusTransition",
            note,
        ));
    }

    if let Some(reason) = noteworthy_failure_reason(old_status, new_status) {
        let note = condition_message(new_status, "Ready")
            .or_else(|| new_status.last_error.clone())
            .unwrap_or_else(|| format!("Policy entered {reason} state"));
        events.push(event(EventType::Warning, reason, "StatusTransition", note));
    }

    events
}

fn event(type_: EventType, reason: &str, action: &str, note: String) -> Event {
    Event {
        type_,
        reason: reason.to_string(),
        note: Some(note),
        action: action.to_string(),
        secondary: None,
    }
}

fn condition<'a>(
    status: &'a PostgresPolicyStatus,
    condition_type: &str,
) -> Option<&'a PolicyCondition> {
    status
        .conditions
        .iter()
        .find(|condition| condition.condition_type == condition_type)
}

fn condition_status<'a>(
    status: Option<&'a PostgresPolicyStatus>,
    condition_type: &str,
) -> Option<&'a str> {
    status
        .and_then(|status| condition(status, condition_type))
        .map(|condition| condition.status.as_str())
}

fn condition_reason<'a>(
    status: Option<&'a PostgresPolicyStatus>,
    condition_type: &str,
) -> Option<&'a str> {
    status
        .and_then(|status| condition(status, condition_type))
        .and_then(|condition| condition.reason.as_deref())
}

fn condition_message(status: &PostgresPolicyStatus, condition_type: &str) -> Option<String> {
    condition(status, condition_type).and_then(|condition| condition.message.clone())
}

fn condition_is_true(status: Option<&PostgresPolicyStatus>, condition_type: &str) -> bool {
    condition_status(status, condition_type) == Some("True")
}

fn transitioned_to_true(
    old_status: Option<&PostgresPolicyStatus>,
    new_status: &PostgresPolicyStatus,
    condition_type: &str,
) -> bool {
    !condition_is_true(old_status, condition_type)
        && condition_is_true(Some(new_status), condition_type)
}

fn transitioned_from_true(
    old_status: Option<&PostgresPolicyStatus>,
    new_status: &PostgresPolicyStatus,
    condition_type: &str,
) -> bool {
    condition_is_true(old_status, condition_type)
        && !condition_is_true(Some(new_status), condition_type)
}

fn was_ready(old_status: Option<&PostgresPolicyStatus>) -> bool {
    condition_is_true(old_status, "Ready")
}

fn had_ready_condition(old_status: Option<&PostgresPolicyStatus>) -> bool {
    old_status
        .and_then(|status| condition(status, "Ready"))
        .is_some()
}

fn ready_became_true(
    old_status: Option<&PostgresPolicyStatus>,
    new_status: &PostgresPolicyStatus,
) -> bool {
    !was_ready(old_status) && condition_is_true(Some(new_status), "Ready")
}

fn is_planned_ready(status: &PostgresPolicyStatus) -> bool {
    condition(status, "Ready").and_then(|ready| ready.reason.as_deref()) == Some("Planned")
}

fn plan_became_clean(
    old_status: Option<&PostgresPolicyStatus>,
    new_status: &PostgresPolicyStatus,
) -> bool {
    if !is_planned_ready(new_status) || condition_is_true(Some(new_status), "Drifted") {
        return false;
    }

    !is_planned_ready_status(old_status) || condition_is_true(old_status, "Drifted")
}

fn is_planned_ready_status(status: Option<&PostgresPolicyStatus>) -> bool {
    status.map(is_planned_ready).unwrap_or(false)
}

fn noteworthy_failure_reason(
    old_status: Option<&PostgresPolicyStatus>,
    new_status: &PostgresPolicyStatus,
) -> Option<&'static str> {
    let ready = condition(new_status, "Ready")?;
    if ready.status != "False" {
        return None;
    }

    let reason = ready.reason.as_deref()?;
    if matches!(reason, "ConflictingPolicy" | "Suspended") {
        return None;
    }

    let mapped_reason = match reason {
        "InvalidSpec" => "InvalidSpec",
        "SecretMissing" | "SecretFetchFailed" => "SecretFetchFailed",
        "DatabaseConnectionFailed" => "DatabaseConnectionFailed",
        "GcpAuthFailed" => "GcpAuthFailed",
        "InsufficientPrivileges" => "InsufficientPrivileges",
        "UnsafeRoleDrops" => "UnsafeRoleDropsBlocked",
        _ => return None,
    };

    let old_ready_status = condition_status(old_status, "Ready");
    let old_ready_reason = condition_reason(old_status, "Ready");

    if old_ready_status == Some("False") && old_ready_reason == Some(reason) {
        None
    } else {
        Some(mapped_reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        PostgresPolicyStatus, conflict_condition, drifted_condition, paused_condition,
        ready_condition,
    };

    fn reasons(events: &[Event]) -> Vec<&str> {
        events.iter().map(|event| event.reason.as_str()).collect()
    }

    #[test]
    fn emits_conflict_detected_when_conflict_condition_becomes_true() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(false, "ConflictingPolicy", "overlap"));
        status.set_condition(conflict_condition("ConflictingPolicy", "overlap"));
        status.last_error = Some("overlap".to_string());

        let events = derive_status_events(None, &status);
        assert_eq!(reasons(&events), vec!["ConflictDetected"]);
    }

    #[test]
    fn emits_conflict_resolved_and_recovered_when_policy_recovers_from_conflict() {
        let mut old_status = PostgresPolicyStatus::default();
        old_status.set_condition(ready_condition(false, "ConflictingPolicy", "overlap"));
        old_status.set_condition(conflict_condition("ConflictingPolicy", "overlap"));

        let mut new_status = PostgresPolicyStatus::default();
        new_status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));

        let events = derive_status_events(Some(&old_status), &new_status);
        assert_eq!(reasons(&events), vec!["ConflictResolved", "Recovered"]);
    }

    #[test]
    fn emits_suspended_when_policy_is_paused() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(paused_condition("Reconciliation suspended by spec"));
        status.set_condition(ready_condition(
            false,
            "Suspended",
            "Reconciliation suspended by spec",
        ));

        let events = derive_status_events(None, &status);
        assert_eq!(reasons(&events), vec!["Suspended"]);
    }

    #[test]
    fn emits_reconciled_on_first_success() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));

        let events = derive_status_events(None, &status);
        assert_eq!(reasons(&events), vec!["Reconciled"]);
    }

    #[test]
    fn emits_recovered_when_transitioning_from_not_ready_to_ready() {
        let mut old_status = PostgresPolicyStatus::default();
        old_status.set_condition(ready_condition(
            false,
            "DatabaseConnectionFailed",
            "database unavailable",
        ));

        let mut new_status = PostgresPolicyStatus::default();
        new_status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));

        let events = derive_status_events(Some(&old_status), &new_status);
        assert_eq!(reasons(&events), vec!["Recovered"]);
    }

    #[test]
    fn emits_secret_fetch_failed_when_missing_secret_first_detected() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(
            false,
            "SecretMissing",
            "Secret \"db\" does not contain key \"DATABASE_URL\"",
        ));
        status.last_error = Some("Secret \"db\" does not contain key \"DATABASE_URL\"".to_string());

        let events = derive_status_events(None, &status);
        assert_eq!(reasons(&events), vec!["SecretFetchFailed"]);
    }

    #[test]
    fn does_not_repeat_same_failure_event_without_transition() {
        let mut old_status = PostgresPolicyStatus::default();
        old_status.set_condition(ready_condition(
            false,
            "DatabaseConnectionFailed",
            "connection refused",
        ));

        let mut new_status = PostgresPolicyStatus::default();
        new_status.set_condition(ready_condition(
            false,
            "DatabaseConnectionFailed",
            "connection refused",
        ));

        let events = derive_status_events(Some(&old_status), &new_status);
        assert!(events.is_empty());
    }

    #[test]
    fn emits_insufficient_privileges_on_failure_transition() {
        let mut old_status = PostgresPolicyStatus::default();
        old_status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));

        let mut new_status = PostgresPolicyStatus::default();
        new_status.set_condition(ready_condition(
            false,
            "InsufficientPrivileges",
            "permission denied to create role",
        ));

        let events = derive_status_events(Some(&old_status), &new_status);
        assert_eq!(reasons(&events), vec!["InsufficientPrivileges"]);
    }

    #[test]
    fn emits_gcp_auth_failed_on_failure_transition() {
        let mut old_status = PostgresPolicyStatus::default();
        old_status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));

        let mut new_status = PostgresPolicyStatus::default();
        new_status.set_condition(ready_condition(
            false,
            "GcpAuthFailed",
            "token request rejected",
        ));

        let events = derive_status_events(Some(&old_status), &new_status);
        assert_eq!(reasons(&events), vec!["GcpAuthFailed"]);
        assert!(matches!(events[0].type_, EventType::Warning));
        assert_eq!(events[0].note.as_deref(), Some("token request rejected"));
    }

    #[test]
    fn emits_approval_ignored_warning_once_on_transition() {
        let mut new_status = PostgresPolicyStatus::default();
        new_status.set_condition(crate::crd::approval_ignored_condition("policy-plan-123"));

        let events = derive_status_events(None, &new_status);
        let ignored = events
            .iter()
            .find(|e| e.reason == "ApprovalIgnored")
            .expect("expected an ApprovalIgnored event");
        assert!(matches!(ignored.type_, EventType::Warning));
        assert!(
            ignored.note.as_deref().is_some_and(
                |note| note.contains("policy-plan-123") && note.contains("mode: apply")
            ),
            "the note should name the plan and the combination that does execute"
        );

        let events = derive_status_events(Some(&new_status), &new_status);
        assert!(
            !reasons(&events).contains(&"ApprovalIgnored"),
            "steady state should not keep re-emitting the warning"
        );
    }

    #[test]
    fn emits_approval_unset_warning_once_on_transition() {
        let mut new_status = PostgresPolicyStatus::default();
        new_status.set_condition(crate::crd::approval_unset_condition(
            crate::crd::ApprovalMode::Auto,
        ));

        let events = derive_status_events(None, &new_status);
        assert!(reasons(&events).contains(&"ApprovalUnset"));
        let approval_event = events
            .iter()
            .find(|e| e.reason == "ApprovalUnset")
            .expect("expected an ApprovalUnset event");
        assert!(matches!(approval_event.type_, EventType::Warning));
        assert!(
            approval_event
                .note
                .as_deref()
                .is_some_and(|note| note.contains("approval: auto")),
            "the event note should carry the remediation, not just the warning"
        );

        // A deprecation nag must not re-fire on every reconcile: with the
        // condition already present, the transition has already been reported.
        let events = derive_status_events(Some(&new_status), &new_status);
        assert!(
            !reasons(&events).contains(&"ApprovalUnset"),
            "steady state should not keep emitting the deprecation event"
        );
    }

    #[test]
    fn emits_drift_detected_for_plan_mode_with_pending_changes() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(true, "Planned", "Plan computed"));
        status.set_condition(drifted_condition(
            true,
            "DriftDetected",
            "2 planned change(s) pending review",
        ));

        let events = derive_status_events(None, &status);
        assert_eq!(reasons(&events), vec!["DriftDetected"]);
    }

    #[test]
    fn emits_plan_clean_when_plan_mode_has_no_pending_changes() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(true, "Planned", "Plan computed"));
        status.set_condition(drifted_condition(false, "InSync", "No pending changes"));

        let events = derive_status_events(None, &status);
        assert_eq!(reasons(&events), vec!["PlanClean"]);
    }
}
