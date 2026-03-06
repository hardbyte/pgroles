//! Safety-oriented inspection helpers for destructive operations.
//!
//! These queries are used as a preflight before dropping roles so the caller
//! can refuse obviously unsafe changes by default.

use std::collections::BTreeMap;

use sqlx::PgPool;

/// Summary of why dropping a specific role is unsafe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRoleSafetyIssue {
    pub role: String,
    pub owned_object_count: usize,
    pub owned_object_examples: Vec<String>,
    pub active_session_count: usize,
}

impl DropRoleSafetyIssue {
    pub fn is_empty(&self) -> bool {
        self.owned_object_count == 0 && self.active_session_count == 0
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
            if issue.owned_object_count > 0 {
                let examples = if issue.owned_object_examples.is_empty() {
                    String::new()
                } else {
                    format!(" e.g. {}", issue.owned_object_examples.join(", "))
                };
                details.push(format!(
                    "owns {} object(s){}",
                    issue.owned_object_count, examples
                ));
            }
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
            "Reassign or drop owned objects and terminate active sessions before removing these roles."
        )
    }
}

#[derive(Debug, sqlx::FromRow)]
struct OwnedObjectRow {
    role_name: String,
    description: String,
}

#[derive(Debug, sqlx::FromRow)]
struct ActiveSessionRow {
    role_name: String,
    active_sessions: i64,
}

/// Inspect whether dropping the given roles would be obviously unsafe.
///
/// This checks for owned objects via `pg_shdepend` and active sessions via
/// `pg_stat_activity`. It intentionally errs on the side of caution.
pub async fn inspect_drop_role_safety(
    pool: &PgPool,
    roles: &[String],
) -> Result<DropRoleSafetyReport, sqlx::Error> {
    if roles.is_empty() {
        return Ok(DropRoleSafetyReport::default());
    }

    let role_refs: Vec<&str> = roles.iter().map(|role| role.as_str()).collect();

    let owned_objects = sqlx::query_as::<_, OwnedObjectRow>(
        r#"
        SELECT
            r.rolname AS role_name,
            pg_describe_object(sd.classid, sd.objid, sd.objsubid) AS description
        FROM pg_shdepend sd
        JOIN pg_roles r
          ON r.oid = sd.refobjid
        WHERE sd.refclassid = 'pg_authid'::regclass
          AND sd.deptype = 'o'
          AND r.rolname = ANY($1)
          AND NOT (sd.classid = 'pg_authid'::regclass AND sd.objid = r.oid)
        ORDER BY r.rolname, description
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
                    active_session_count: 0,
                },
            )
        })
        .collect();

    for row in owned_objects {
        let issue = by_role.get_mut(&row.role_name).expect("role should exist");
        issue.owned_object_count += 1;
        if issue.owned_object_examples.len() < 5 {
            issue.owned_object_examples.push(row.description);
        }
    }

    for row in active_sessions {
        let issue = by_role.get_mut(&row.role_name).expect("role should exist");
        issue.active_session_count = row.active_sessions.max(0) as usize;
    }

    let issues = by_role
        .into_values()
        .filter(|issue| !issue.is_empty())
        .collect();

    Ok(DropRoleSafetyReport { issues })
}
