//! Safety-oriented inspection helpers for destructive operations.
//!
//! These queries are used as a preflight before dropping roles so the caller
//! can refuse obviously unsafe changes by default.

use std::collections::BTreeMap;

use pgroles_core::manifest::RoleRetirement;
use sqlx::PgPool;

const MAX_EXAMPLES: usize = 5;

/// Summary of why dropping a specific role is unsafe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRoleSafetyIssue {
    pub role: String,
    pub owned_object_count: usize,
    pub owned_object_examples: Vec<String>,
    pub shared_owned_object_count: usize,
    pub shared_owned_object_examples: Vec<String>,
    pub external_owned_object_count: usize,
    pub external_owned_object_examples: Vec<String>,
    pub privilege_dependency_count: usize,
    pub privilege_dependency_examples: Vec<String>,
    pub external_privilege_dependency_count: usize,
    pub external_privilege_dependency_examples: Vec<String>,
    pub other_dependency_count: usize,
    pub other_dependency_examples: Vec<String>,
    pub external_other_dependency_count: usize,
    pub external_other_dependency_examples: Vec<String>,
    pub active_session_count: usize,
}

impl DropRoleSafetyIssue {
    pub fn is_empty(&self) -> bool {
        self.owned_object_count == 0
            && self.shared_owned_object_count == 0
            && self.external_owned_object_count == 0
            && self.privilege_dependency_count == 0
            && self.external_privilege_dependency_count == 0
            && self.other_dependency_count == 0
            && self.external_other_dependency_count == 0
            && self.active_session_count == 0
    }
}

/// Report of unsafe role-drop candidates discovered during preflight.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropRoleSafetyReport {
    pub issues: Vec<DropRoleSafetyIssue>,
}

impl DropRoleSafetyReport {
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    /// Remove hazards that are explicitly handled by retirement steps in the
    /// current database.
    pub fn apply_retirements(mut self, retirements: &[RoleRetirement]) -> Self {
        let retirement_by_role: BTreeMap<&str, &RoleRetirement> = retirements
            .iter()
            .map(|retirement| (retirement.role.as_str(), retirement))
            .collect();

        self.issues = self
            .issues
            .into_iter()
            .filter_map(|mut issue| {
                if let Some(retirement) = retirement_by_role.get(issue.role.as_str()) {
                    if retirement.drop_owned {
                        issue.owned_object_count = 0;
                        issue.owned_object_examples.clear();
                        issue.privilege_dependency_count = 0;
                        issue.privilege_dependency_examples.clear();
                    }
                    if retirement.reassign_owned_to.is_some() {
                        issue.owned_object_count = 0;
                        issue.owned_object_examples.clear();
                        issue.shared_owned_object_count = 0;
                        issue.shared_owned_object_examples.clear();
                    }
                }

                (!issue.is_empty()).then_some(issue)
            })
            .collect();

        self
    }
}

impl std::fmt::Display for DropRoleSafetyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.issues.is_empty() {
            return Ok(());
        }

        writeln!(f, "Unsafe role drop(s) detected:")?;
        for issue in &self.issues {
            write!(f, "  role \"{}\"", issue.role)?;
            let mut details = Vec::new();

            push_detail(
                &mut details,
                issue.owned_object_count,
                &issue.owned_object_examples,
                "owns current-database object(s)",
            );
            push_detail(
                &mut details,
                issue.shared_owned_object_count,
                &issue.shared_owned_object_examples,
                "owns shared object(s)",
            );
            push_detail(
                &mut details,
                issue.external_owned_object_count,
                &issue.external_owned_object_examples,
                "owns object(s) in other database(s)",
            );
            push_detail(
                &mut details,
                issue.privilege_dependency_count,
                &issue.privilege_dependency_examples,
                "still has privilege dependency/dependencies in this database or on shared objects",
            );
            push_detail(
                &mut details,
                issue.external_privilege_dependency_count,
                &issue.external_privilege_dependency_examples,
                "still has privilege dependency/dependencies in other database(s)",
            );
            push_detail(
                &mut details,
                issue.other_dependency_count,
                &issue.other_dependency_examples,
                "has other dependency/dependencies in this database or on shared objects",
            );
            push_detail(
                &mut details,
                issue.external_other_dependency_count,
                &issue.external_other_dependency_examples,
                "has other dependency/dependencies in other database(s)",
            );
            if issue.active_session_count > 0 {
                details.push(format!(
                    "has {} active session(s)",
                    issue.active_session_count
                ));
            }

            writeln!(f, ": {}", details.join("; "))?;
        }
        write!(
            f,
            "Use REASSIGN OWNED and DROP OWNED for current-database cleanup, then repeat any required cleanup in each listed database before removing these roles."
        )
    }
}

fn push_detail(details: &mut Vec<String>, count: usize, examples: &[String], label: &str) {
    if count == 0 {
        return;
    }

    let examples = if examples.is_empty() {
        String::new()
    } else {
        format!(" e.g. {}", examples.join(", "))
    };
    details.push(format!("{count} {label}{examples}"));
}

#[derive(Debug, sqlx::FromRow)]
struct DependencyRow {
    role_name: String,
    dependency_type: String,
    dependency_scope: String,
    database_name: Option<String>,
    description: String,
}

#[derive(Debug, sqlx::FromRow)]
struct ActiveSessionRow {
    role_name: String,
    active_sessions: i64,
}

/// Inspect whether dropping the given roles would be obviously unsafe.
///
/// This checks role ownership and dependency references via `pg_shdepend` and
/// active sessions via `pg_stat_activity`. It intentionally errs on the side
/// of caution.
pub async fn inspect_drop_role_safety(
    pool: &PgPool,
    roles: &[String],
) -> Result<DropRoleSafetyReport, sqlx::Error> {
    if roles.is_empty() {
        return Ok(DropRoleSafetyReport::default());
    }

    let role_refs: Vec<&str> = roles.iter().map(|role| role.as_str()).collect();

    let dependencies = sqlx::query_as::<_, DependencyRow>(
        r#"
        WITH current_db AS (
            SELECT oid AS current_db_oid
            FROM pg_database
            WHERE datname = current_database()
        )
        SELECT
            r.rolname AS role_name,
            sd.deptype::text AS dependency_type,
            CASE
                WHEN sd.dbid = 0 THEN 'shared'
                WHEN sd.dbid = (SELECT current_db_oid FROM current_db) THEN 'current'
                ELSE 'other'
            END AS dependency_scope,
            d.datname AS database_name,
            pg_describe_object(sd.classid, sd.objid, sd.objsubid) AS description
        FROM pg_shdepend sd
        JOIN pg_roles r
          ON r.oid = sd.refobjid
        LEFT JOIN pg_database d
          ON d.oid = sd.dbid
        WHERE sd.refclassid = 'pg_authid'::regclass
          AND sd.deptype IN ('o', 'a', 'r', 'i')
          AND r.rolname = ANY($1)
          AND NOT (sd.classid = 'pg_authid'::regclass AND sd.objid = r.oid)
        ORDER BY r.rolname, dependency_scope, dependency_type, description
        "#,
    )
    .bind(&role_refs)
    .fetch_all(pool)
    .await?;

    let active_sessions = sqlx::query_as::<_, ActiveSessionRow>(
        r#"
        SELECT
            usename AS role_name,
            COUNT(*)::bigint AS active_sessions
        FROM pg_stat_activity
        WHERE usename = ANY($1)
          AND pid <> pg_backend_pid()
        GROUP BY usename
        ORDER BY usename
        "#,
    )
    .bind(&role_refs)
    .fetch_all(pool)
    .await?;

    let mut by_role: BTreeMap<String, DropRoleSafetyIssue> = roles
        .iter()
        .cloned()
        .map(|role| {
            (
                role.clone(),
                DropRoleSafetyIssue {
                    role,
                    owned_object_count: 0,
                    owned_object_examples: Vec::new(),
                    shared_owned_object_count: 0,
                    shared_owned_object_examples: Vec::new(),
                    external_owned_object_count: 0,
                    external_owned_object_examples: Vec::new(),
                    privilege_dependency_count: 0,
                    privilege_dependency_examples: Vec::new(),
                    external_privilege_dependency_count: 0,
                    external_privilege_dependency_examples: Vec::new(),
                    other_dependency_count: 0,
                    other_dependency_examples: Vec::new(),
                    external_other_dependency_count: 0,
                    external_other_dependency_examples: Vec::new(),
                    active_session_count: 0,
                },
            )
        })
        .collect();

    for row in dependencies {
        if let Some(issue) = by_role.get_mut(&row.role_name) {
            let example = format_dependency_example(&row);
            match (row.dependency_type.as_str(), row.dependency_scope.as_str()) {
                ("o", "current") => {
                    issue.owned_object_count += 1;
                    push_example(&mut issue.owned_object_examples, example);
                }
                ("o", "shared") => {
                    issue.shared_owned_object_count += 1;
                    push_example(&mut issue.shared_owned_object_examples, example);
                }
                ("o", "other") => {
                    issue.external_owned_object_count += 1;
                    push_example(&mut issue.external_owned_object_examples, example);
                }
                ("a", "other") => {
                    issue.external_privilege_dependency_count += 1;
                    push_example(&mut issue.external_privilege_dependency_examples, example);
                }
                ("a", _) => {
                    issue.privilege_dependency_count += 1;
                    push_example(&mut issue.privilege_dependency_examples, example);
                }
                (_, "other") => {
                    issue.external_other_dependency_count += 1;
                    push_example(&mut issue.external_other_dependency_examples, example);
                }
                _ => {
                    issue.other_dependency_count += 1;
                    push_example(&mut issue.other_dependency_examples, example);
                }
            }
        }
    }

    for row in active_sessions {
        if let Some(issue) = by_role.get_mut(&row.role_name) {
            issue.active_session_count = row.active_sessions.max(0) as usize;
        }
    }

    let issues = by_role
        .into_values()
        .filter(|issue| !issue.is_empty())
        .collect();

    Ok(DropRoleSafetyReport { issues })
}

fn format_dependency_example(row: &DependencyRow) -> String {
    let type_label = match row.dependency_type.as_str() {
        "a" => "privilege",
        "i" => "initial privilege",
        "o" => "owner",
        "r" => "policy",
        _ => "dependency",
    };

    match row.dependency_scope.as_str() {
        "shared" => format!("{type_label} on shared object {}", row.description),
        "other" => format!(
            "{type_label} in database {} on {}",
            row.database_name.as_deref().unwrap_or("<unknown>"),
            row.description
        ),
        _ => format!("{type_label} on {}", row.description),
    }
}

fn push_example(examples: &mut Vec<String>, example: String) {
    if examples.len() < MAX_EXAMPLES {
        examples.push(example);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_issue() -> DropRoleSafetyIssue {
        DropRoleSafetyIssue {
            role: "legacy-app".to_string(),
            owned_object_count: 0,
            owned_object_examples: Vec::new(),
            shared_owned_object_count: 0,
            shared_owned_object_examples: Vec::new(),
            external_owned_object_count: 0,
            external_owned_object_examples: Vec::new(),
            privilege_dependency_count: 0,
            privilege_dependency_examples: Vec::new(),
            external_privilege_dependency_count: 0,
            external_privilege_dependency_examples: Vec::new(),
            other_dependency_count: 0,
            other_dependency_examples: Vec::new(),
            external_other_dependency_count: 0,
            external_other_dependency_examples: Vec::new(),
            active_session_count: 0,
        }
    }

    #[test]
    fn apply_retirements_clears_current_db_cleanup_hazards_when_planned() {
        let mut issue = base_issue();
        issue.owned_object_count = 2;
        issue.owned_object_examples = vec!["owner on table public.widgets".to_string()];
        issue.privilege_dependency_count = 1;
        issue.privilege_dependency_examples = vec!["privilege on table public.widgets".to_string()];

        let filtered = DropRoleSafetyReport {
            issues: vec![issue],
        }
        .apply_retirements(&[RoleRetirement {
            role: "legacy-app".to_string(),
            reassign_owned_to: Some("app-owner".to_string()),
            drop_owned: true,
        }]);

        assert!(filtered.is_empty());
    }

    #[test]
    fn apply_retirements_keep_external_and_shared_hazards() {
        let mut issue = base_issue();
        issue.shared_owned_object_count = 1;
        issue.shared_owned_object_examples =
            vec!["owner on shared object database analytics".to_string()];
        issue.external_privilege_dependency_count = 2;
        issue.external_privilege_dependency_examples =
            vec!["privilege in database reporting on table public.widgets".to_string()];

        let filtered = DropRoleSafetyReport {
            issues: vec![issue],
        }
        .apply_retirements(&[RoleRetirement {
            role: "legacy-app".to_string(),
            reassign_owned_to: None,
            drop_owned: true,
        }]);

        assert_eq!(filtered.issues.len(), 1);
        assert_eq!(filtered.issues[0].shared_owned_object_count, 1);
        assert_eq!(filtered.issues[0].external_privilege_dependency_count, 2);
    }

    #[test]
    fn apply_retirements_keep_active_session_hazards() {
        let mut issue = base_issue();
        issue.owned_object_count = 1;
        issue.owned_object_examples = vec!["owner on table public.widgets".to_string()];
        issue.active_session_count = 3;

        let filtered = DropRoleSafetyReport {
            issues: vec![issue],
        }
        .apply_retirements(&[RoleRetirement {
            role: "legacy-app".to_string(),
            reassign_owned_to: Some("app-owner".to_string()),
            drop_owned: true,
        }]);

        assert_eq!(filtered.issues.len(), 1);
        assert_eq!(filtered.issues[0].active_session_count, 3);
        assert_eq!(filtered.issues[0].owned_object_count, 0);
    }
}
