//! Testable CLI logic for pgroles.
//!
//! All pure functions that don't require a live database connection live here.
//! The binary (`main.rs`) delegates to these, making validation, plan formatting,
//! and output rendering fully unit-testable.

use std::path::Path;

use anyhow::{Context, Result};

use pgroles_core::diff::{self, Change};
use pgroles_core::manifest::{self, ExpandedManifest, PolicyManifest, RoleRetirement};
use pgroles_core::model::RoleGraph;
use pgroles_core::sql;

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

/// Read a manifest file from disk and return the raw YAML string.
pub fn read_manifest_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest file: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Validation pipeline (pure — no DB)
// ---------------------------------------------------------------------------

/// Parse and validate a YAML string into a `PolicyManifest`.
pub fn parse(yaml: &str) -> Result<PolicyManifest> {
    manifest::parse_manifest(yaml).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Parse, validate, and expand a manifest YAML string into an `ExpandedManifest`.
pub fn parse_and_expand(yaml: &str) -> Result<ExpandedManifest> {
    let policy_manifest = parse(yaml)?;
    manifest::expand_manifest(&policy_manifest).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Full validation: parse, expand, and build a RoleGraph from a manifest string.
/// Returns the expanded manifest and the desired RoleGraph.
pub fn validate_manifest(yaml: &str) -> Result<ValidatedManifest> {
    let policy_manifest = parse(yaml)?;
    let expanded =
        manifest::expand_manifest(&policy_manifest).map_err(|err| anyhow::anyhow!("{err}"))?;

    let default_owner = policy_manifest.default_owner.as_deref();
    let desired = RoleGraph::from_expanded(&expanded, default_owner)
        .map_err(|err| anyhow::anyhow!("{err}"))?;

    Ok(ValidatedManifest {
        manifest: policy_manifest,
        expanded,
        desired,
    })
}

/// The result of successfully validating a manifest.
pub struct ValidatedManifest {
    pub manifest: PolicyManifest,
    pub expanded: ExpandedManifest,
    pub desired: RoleGraph,
}

// ---------------------------------------------------------------------------
// Plan computation (pure — given both role graphs)
// ---------------------------------------------------------------------------

/// Compute the list of changes needed to bring `current` state to `desired` state.
pub fn compute_plan(current: &RoleGraph, desired: &RoleGraph) -> Vec<Change> {
    diff::diff(current, desired)
}

/// Collect the role names that the current plan intends to drop.
pub fn planned_role_drops(changes: &[Change]) -> Vec<String> {
    changes
        .iter()
        .filter_map(|change| match change {
            Change::DropRole { name } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// Insert explicit retirement actions before any matching role drops.
pub fn apply_role_retirements(changes: Vec<Change>, retirements: &[RoleRetirement]) -> Vec<Change> {
    diff::apply_role_retirements(changes, retirements)
}

/// Resolve password sources from environment variables for roles that declare them.
pub fn resolve_passwords(
    expanded: &ExpandedManifest,
) -> Result<std::collections::BTreeMap<String, String>> {
    diff::resolve_passwords(&expanded.roles).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Inject `SetPassword` changes into a plan for roles with resolved passwords.
pub fn inject_password_changes(
    changes: Vec<Change>,
    resolved_passwords: &std::collections::BTreeMap<String, String>,
) -> Vec<Change> {
    diff::inject_password_changes(changes, resolved_passwords)
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

/// Format a plan as SQL statements.
pub fn format_plan_sql(changes: &[Change]) -> String {
    sql::render_all(changes)
}

/// Format a plan as SQL statements using an explicit SQL context.
pub fn format_plan_sql_with_context(changes: &[Change], ctx: &sql::SqlContext) -> String {
    sql::render_all_with_context(changes, ctx)
}

/// Format a plan as JSON for machine consumption.
pub fn format_plan_json(changes: &[Change]) -> Result<String> {
    serde_json::to_string_pretty(changes).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Summary statistics for a plan.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PlanSummary {
    pub roles_created: usize,
    pub roles_altered: usize,
    pub roles_dropped: usize,
    pub comments_changed: usize,
    pub sessions_terminated: usize,
    pub ownerships_reassigned: usize,
    pub owned_objects_dropped: usize,
    pub grants: usize,
    pub revokes: usize,
    pub default_privileges_set: usize,
    pub default_privileges_revoked: usize,
    pub members_added: usize,
    pub members_removed: usize,
    pub passwords_set: usize,
}

impl PlanSummary {
    /// Compute summary statistics from a list of changes.
    pub fn from_changes(changes: &[Change]) -> Self {
        let mut summary = Self::default();
        for change in changes {
            match change {
                Change::CreateRole { .. } => summary.roles_created += 1,
                Change::AlterRole { .. } => summary.roles_altered += 1,
                Change::DropRole { .. } => summary.roles_dropped += 1,
                Change::SetComment { .. } => summary.comments_changed += 1,
                Change::TerminateSessions { .. } => summary.sessions_terminated += 1,
                Change::ReassignOwned { .. } => summary.ownerships_reassigned += 1,
                Change::DropOwned { .. } => summary.owned_objects_dropped += 1,
                Change::Grant { .. } => summary.grants += 1,
                Change::Revoke { .. } => summary.revokes += 1,
                Change::SetDefaultPrivilege { .. } => summary.default_privileges_set += 1,
                Change::RevokeDefaultPrivilege { .. } => summary.default_privileges_revoked += 1,
                Change::AddMember { .. } => summary.members_added += 1,
                Change::RemoveMember { .. } => summary.members_removed += 1,
                Change::SetPassword { .. } => summary.passwords_set += 1,
            }
        }
        summary
    }

    /// Total number of changes in the plan.
    pub fn total(&self) -> usize {
        self.roles_created
            + self.roles_altered
            + self.roles_dropped
            + self.comments_changed
            + self.sessions_terminated
            + self.ownerships_reassigned
            + self.owned_objects_dropped
            + self.grants
            + self.revokes
            + self.default_privileges_set
            + self.default_privileges_revoked
            + self.members_added
            + self.members_removed
            + self.passwords_set
    }

    /// True if the plan has no changes.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// True if the plan has structural drift (excluding password-only changes).
    ///
    /// Password changes always appear in plans because passwords cannot be read
    /// back from PostgreSQL for comparison. This method allows CI gates
    /// (`--exit-code`) to distinguish real drift from password-only changes.
    pub fn has_structural_changes(&self) -> bool {
        self.total() - self.passwords_set > 0
    }
}

impl std::fmt::Display for PlanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return write!(f, "No changes needed. Database is in sync with manifest.");
        }

        writeln!(f, "Plan: {} change(s)", self.total())?;

        let items: Vec<(&str, usize)> = vec![
            ("role(s) to create", self.roles_created),
            ("role(s) to alter", self.roles_altered),
            ("role(s) to drop", self.roles_dropped),
            ("comment(s) to change", self.comments_changed),
            ("session termination step(s)", self.sessions_terminated),
            ("ownership reassignment(s)", self.ownerships_reassigned),
            ("DROP OWNED cleanup step(s)", self.owned_objects_dropped),
            ("grant(s) to add", self.grants),
            ("grant(s) to revoke", self.revokes),
            ("default privilege(s) to set", self.default_privileges_set),
            (
                "default privilege(s) to revoke",
                self.default_privileges_revoked,
            ),
            ("membership(s) to add", self.members_added),
            ("membership(s) to remove", self.members_removed),
            ("password(s) to set", self.passwords_set),
        ];

        for (label, count) in items {
            if count > 0 {
                writeln!(f, "  {count} {label}")?;
            }
        }
        Ok(())
    }
}

/// Format validation results for human-readable output.
pub fn format_validation_result(validated: &ValidatedManifest) -> String {
    let mut output = String::new();
    output.push_str("Manifest is valid.\n");
    output.push_str(&format!(
        "  {} role(s) defined\n",
        validated.expanded.roles.len()
    ));
    output.push_str(&format!(
        "  {} grant(s) defined\n",
        validated.expanded.grants.len()
    ));
    output.push_str(&format!(
        "  {} default privilege(s) defined\n",
        validated.expanded.default_privileges.len()
    ));
    output.push_str(&format!(
        "  {} membership(s) defined\n",
        validated.expanded.memberships.len()
    ));
    output
}

// ---------------------------------------------------------------------------
// Inspect output formatting
// ---------------------------------------------------------------------------

/// Format a RoleGraph as a human-readable summary.
pub fn format_role_graph_summary(graph: &RoleGraph) -> String {
    let mut output = String::new();
    output.push_str(&format!("Roles: {}\n", graph.roles.len()));
    output.push_str(&format!("Grants: {}\n", graph.grants.len()));
    output.push_str(&format!(
        "Default privileges: {}\n",
        graph.default_privileges.len()
    ));
    output.push_str(&format!("Memberships: {}\n", graph.memberships.len()));
    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_MANIFEST: &str = r#"
default_owner: app_owner

roles:
  - name: analytics
    login: true
    comment: "Analytics read-only role"

grants:
  - role: analytics
    privileges: [CONNECT]
    on: { type: database, name: mydb }
"#;

    const PROFILE_MANIFEST: &str = r#"
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
  viewer:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT]
        on: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    profiles: [editor, viewer]
  - name: catalog
    profiles: [viewer]

roles:
  - name: app-service
    login: true

grants:
  - role: app-service
    privileges: [CONNECT]
    on: { type: database, name: mydb }

memberships:
  - role: inventory-editor
    members:
      - name: app-service
"#;

    const INVALID_YAML: &str = r#"
this is: [not: valid yaml: [[
"#;

    const UNDEFINED_PROFILE: &str = r#"
profiles:
  editor:
    grants: []

schemas:
  - name: myschema
    profiles: [nonexistent]
"#;

    // -----------------------------------------------------------------------
    // parse
    // -----------------------------------------------------------------------

    #[test]
    fn parse_valid_manifest() {
        let result = parse(MINIMAL_MANIFEST);
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.default_owner, Some("app_owner".to_string()));
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.roles[0].name, "analytics");
    }

    #[test]
    fn parse_invalid_yaml() {
        let result = parse(INVALID_YAML);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("YAML parse error"), "got: {err_msg}");
    }

    // -----------------------------------------------------------------------
    // parse_and_expand
    // -----------------------------------------------------------------------

    #[test]
    fn expand_profile_manifest() {
        let expanded = parse_and_expand(PROFILE_MANIFEST).unwrap();

        // inventory-editor, inventory-viewer, catalog-viewer, app-service
        assert_eq!(expanded.roles.len(), 4);

        let role_names: Vec<&str> = expanded.roles.iter().map(|r| r.name.as_str()).collect();
        assert!(role_names.contains(&"inventory-editor"));
        assert!(role_names.contains(&"inventory-viewer"));
        assert!(role_names.contains(&"catalog-viewer"));
        assert!(role_names.contains(&"app-service"));
    }

    #[test]
    fn expand_undefined_profile_fails() {
        let result = parse_and_expand(UNDEFINED_PROFILE);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nonexistent"),
            "expected error about 'nonexistent' profile, got: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_manifest
    // -----------------------------------------------------------------------

    #[test]
    fn validate_builds_role_graph() {
        let validated = validate_manifest(PROFILE_MANIFEST).unwrap();

        // Check the desired graph has the expected roles
        assert_eq!(validated.desired.roles.len(), 4);
        assert!(validated.desired.roles.contains_key("inventory-editor"));
        assert!(validated.desired.roles.contains_key("app-service"));

        // Check grants were expanded
        assert!(!validated.desired.grants.is_empty());

        // Check memberships
        assert!(!validated.desired.memberships.is_empty());
    }

    // -----------------------------------------------------------------------
    // compute_plan + format
    // -----------------------------------------------------------------------

    #[test]
    fn plan_from_empty_creates_roles() {
        let validated = validate_manifest(PROFILE_MANIFEST).unwrap();
        let current = RoleGraph::default(); // empty database

        let changes = compute_plan(&current, &validated.desired);
        assert!(!changes.is_empty());

        let summary = PlanSummary::from_changes(&changes);
        assert_eq!(summary.roles_created, 4); // inventory-editor, inventory-viewer, catalog-viewer, app-service
        assert!(summary.grants > 0);
        assert!(!summary.is_empty());
    }

    #[test]
    fn plan_no_changes_when_in_sync() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        // Simulate a DB that already has the desired state
        let current = validated.desired.clone();

        let changes = compute_plan(&current, &validated.desired);
        let summary = PlanSummary::from_changes(&changes);
        assert!(summary.is_empty());
        assert_eq!(summary.total(), 0);
    }

    #[test]
    fn format_plan_sql_produces_sql() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        let current = RoleGraph::default();
        let changes = compute_plan(&current, &validated.desired);

        let sql_output = format_plan_sql(&changes);
        assert!(
            sql_output.contains("CREATE ROLE"),
            "expected CREATE ROLE in: {sql_output}"
        );
        assert!(
            sql_output.contains("\"analytics\""),
            "expected quoted role name in: {sql_output}"
        );
    }

    #[test]
    fn planned_role_drops_only_returns_drop_changes() {
        let changes = vec![
            Change::CreateRole {
                name: "new-role".to_string(),
                state: pgroles_core::model::RoleState::default(),
            },
            Change::DropRole {
                name: "old-role".to_string(),
            },
            Change::DropRole {
                name: "stale-role".to_string(),
            },
        ];

        assert_eq!(
            planned_role_drops(&changes),
            vec!["old-role".to_string(), "stale-role".to_string()]
        );
    }

    #[test]
    fn apply_role_retirements_updates_plan_summary() {
        let changes = apply_role_retirements(
            vec![Change::DropRole {
                name: "legacy-app".to_string(),
            }],
            &[pgroles_core::manifest::RoleRetirement {
                role: "legacy-app".to_string(),
                reassign_owned_to: Some("app-owner".to_string()),
                drop_owned: true,
                terminate_sessions: true,
            }],
        );

        let summary = PlanSummary::from_changes(&changes);
        assert_eq!(summary.roles_dropped, 1);
        assert_eq!(summary.sessions_terminated, 1);
        assert_eq!(summary.ownerships_reassigned, 1);
        assert_eq!(summary.owned_objects_dropped, 1);
        assert_eq!(summary.total(), 4);
    }

    // -----------------------------------------------------------------------
    // PlanSummary display
    // -----------------------------------------------------------------------

    #[test]
    fn plan_summary_display_empty() {
        let summary = PlanSummary::default();
        let display = summary.to_string();
        assert!(display.contains("No changes needed"));
    }

    #[test]
    fn plan_summary_display_with_changes() {
        let summary = PlanSummary {
            roles_created: 2,
            grants: 5,
            members_added: 1,
            ..Default::default()
        };
        let display = summary.to_string();
        assert!(display.contains("8 change(s)"), "got: {display}");
        assert!(display.contains("2 role(s) to create"), "got: {display}");
        assert!(display.contains("5 grant(s) to add"), "got: {display}");
        assert!(display.contains("1 membership(s) to add"), "got: {display}");
        // Should not mention zero-count items
        assert!(!display.contains("to drop"), "got: {display}");
        assert!(!display.contains("to revoke"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // format_validation_result
    // -----------------------------------------------------------------------

    #[test]
    fn validation_result_shows_counts() {
        let validated = validate_manifest(PROFILE_MANIFEST).unwrap();
        let output = format_validation_result(&validated);
        assert!(output.contains("Manifest is valid"), "got: {output}");
        assert!(output.contains("4 role(s)"), "got: {output}");
    }

    // -----------------------------------------------------------------------
    // read_manifest_file
    // -----------------------------------------------------------------------

    #[test]
    fn read_nonexistent_file_fails() {
        let result = read_manifest_file(Path::new("/tmp/nonexistent-pgroles-test.yaml"));
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("failed to read manifest file"),
            "got: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // format_role_graph_summary
    // -----------------------------------------------------------------------

    #[test]
    fn role_graph_summary_format() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        let summary = format_role_graph_summary(&validated.desired);
        assert!(summary.contains("Roles: 1"), "got: {summary}");
    }

    // -----------------------------------------------------------------------
    // format_plan_json
    // -----------------------------------------------------------------------

    #[test]
    fn plan_json_produces_valid_json() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        let current = RoleGraph::default();
        let changes = compute_plan(&current, &validated.desired);

        let json_output = format_plan_json(&changes).unwrap();
        // Should be parseable JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert!(parsed.is_array());
        // Should contain CreateRole
        let text = json_output.to_string();
        assert!(text.contains("CreateRole"), "got: {text}");
        assert!(text.contains("analytics"), "got: {text}");
    }
}
