//! Transition-based Kubernetes Events for `PostgresPolicy` resources.
//!
//! Events complement status conditions:
//! - status remains the source of truth for the current state
//! - Events surface notable transitions in `kubectl describe`
//! - OTLP metrics remain the fleet-level observability path

use k8s_openapi::api::core::v1::ObjectReference;
use kube::Resource;
use kube::runtime::events::{Event, EventType, Recorder};

use crate::crd::{PolicyCondition, PostgresPolicy, PostgresPolicyStatus};

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

    if ready_became_true(old_status, new_status) {
        let reason = if had_ready_condition(old_status) {
            "Recovered"
        } else {
            "Reconciled"
        };
        let note = condition_message(new_status, "Ready")
            .unwrap_or_else(|| "Policy reconciled successfully".to_string());
        events.push(event(EventType::Normal, reason, "StatusTransition", note));
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
    use crate::crd::{PostgresPolicyStatus, conflict_condition, paused_condition, ready_condition};

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
}
