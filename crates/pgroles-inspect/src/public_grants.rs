//! Query grants to the PUBLIC pseudo-role from PostgreSQL catalog tables.
//!
//! PostgreSQL grants certain default privileges to PUBLIC (e.g. CONNECT and
//! TEMPORARY on databases, USAGE on the public schema). These grants are
//! represented by NULL grantee entries in ACL arrays.
//!
//! This module provides read-only introspection of PUBLIC grants for
//! informational display. pgroles does not manage PUBLIC grants — they are
//! shown so users can understand the full effective privilege picture.

use std::collections::BTreeSet;

use sqlx::PgPool;

use pgroles_core::manifest::Privilege;

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

/// Grants held by the PUBLIC pseudo-role on the current database.
#[derive(Debug, Clone, Default)]
pub struct PublicGrants {
    /// Privileges granted to PUBLIC on the current database (e.g. CONNECT, TEMPORARY).
    pub database_privileges: BTreeSet<Privilege>,
    /// The name of the current database (for display purposes).
    pub database_name: String,
    /// Schema-level grants to PUBLIC: each entry is (schema_name, privileges).
    pub schema_grants: Vec<(String, BTreeSet<Privilege>)>,
}

impl PublicGrants {
    /// Returns true if there are no PUBLIC grants to display.
    pub fn is_empty(&self) -> bool {
        self.database_privileges.is_empty() && self.schema_grants.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Raw query row
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct PublicAclRow {
    privilege_type: String,
    object_name: String,
    obj_kind: String,
}

/// Map a PostgreSQL ACL privilege character to our `Privilege` enum.
fn acl_char_to_privilege(character: &str) -> Option<Privilege> {
    match character {
        "r" | "SELECT" => Some(Privilege::Select),
        "a" | "INSERT" => Some(Privilege::Insert),
        "w" | "UPDATE" => Some(Privilege::Update),
        "d" | "DELETE" => Some(Privilege::Delete),
        "D" | "TRUNCATE" => Some(Privilege::Truncate),
        "x" | "REFERENCES" => Some(Privilege::References),
        "t" | "TRIGGER" => Some(Privilege::Trigger),
        "X" | "EXECUTE" => Some(Privilege::Execute),
        "U" | "USAGE" => Some(Privilege::Usage),
        "C" | "CREATE" => Some(Privilege::Create),
        "c" | "CONNECT" => Some(Privilege::Connect),
        "T" | "TEMPORARY" => Some(Privilege::Temporary),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Query functions
// ---------------------------------------------------------------------------

/// Fetch grants to PUBLIC on the current database and its schemas.
///
/// Queries:
/// - `pg_database` ACLs for database-level grants (CONNECT, TEMPORARY, CREATE)
/// - `pg_namespace` ACLs for schema-level grants (USAGE, CREATE)
///
/// Only returns grants where the grantee is NULL (i.e. PUBLIC).
pub async fn fetch_public_grants(pool: &PgPool) -> Result<PublicGrants, sqlx::Error> {
    let rows = sqlx::query_as::<_, PublicAclRow>(
        r#"
        -- Database-level PUBLIC grants
        SELECT
            acl.privilege_type,
            db.datname AS object_name,
            'database' AS obj_kind
        FROM pg_database db
        CROSS JOIN LATERAL aclexplode(
            COALESCE(
                db.datacl,
                acldefault('d'::"char", db.datdba)
            )
        ) AS acl
        WHERE db.datname = current_database()
          AND acl.grantee = 0

        UNION ALL

        -- Schema-level PUBLIC grants
        SELECT
            acl.privilege_type,
            n.nspname AS object_name,
            'schema' AS obj_kind
        FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(
            COALESCE(
                n.nspacl,
                acldefault('n'::"char", n.nspowner)
            )
        ) AS acl
        WHERE n.nspname NOT LIKE 'pg_%'
          AND n.nspname <> 'information_schema'
          AND acl.grantee = 0
        ORDER BY obj_kind, object_name
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut grants = PublicGrants::default();

    for row in rows {
        let Some(privilege) = acl_char_to_privilege(&row.privilege_type) else {
            continue;
        };

        match row.obj_kind.as_str() {
            "database" => {
                grants.database_name = row.object_name.clone();
                grants.database_privileges.insert(privilege);
            }
            "schema" => {
                // Find or create the entry for this schema.
                if let Some(entry) = grants
                    .schema_grants
                    .iter_mut()
                    .find(|(name, _)| name == &row.object_name)
                {
                    entry.1.insert(privilege);
                } else {
                    let mut privs = BTreeSet::new();
                    privs.insert(privilege);
                    grants.schema_grants.push((row.object_name.clone(), privs));
                }
            }
            _ => {}
        }
    }

    Ok(grants)
}

/// Format `PublicGrants` as a human-readable string for display.
pub fn format_public_grants(grants: &PublicGrants) -> String {
    if grants.is_empty() {
        return String::new();
    }

    let mut output = String::new();
    output.push_str("\nPUBLIC grants (informational, not managed by pgroles):\n");

    if !grants.database_privileges.is_empty() {
        let privs: Vec<String> = grants
            .database_privileges
            .iter()
            .map(|p| p.to_string())
            .collect();
        output.push_str(&format!("  Database: {}\n", privs.join(", ")));
    }

    for (schema_name, privileges) in &grants.schema_grants {
        let privs: Vec<String> = privileges.iter().map(|p| p.to_string()).collect();
        output.push_str(&format!(
            "  Schema \"{schema_name}\": {}\n",
            privs.join(", ")
        ));
    }

    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_public_grants_formats_as_empty_string() {
        let grants = PublicGrants::default();
        assert!(grants.is_empty());
        assert_eq!(format_public_grants(&grants), "");
    }

    #[test]
    fn format_database_and_schema_grants() {
        let grants = PublicGrants {
            database_name: "mydb".to_string(),
            database_privileges: [Privilege::Connect, Privilege::Temporary]
                .into_iter()
                .collect(),
            schema_grants: vec![(
                "public".to_string(),
                [Privilege::Usage, Privilege::Create].into_iter().collect(),
            )],
        };
        let output = format_public_grants(&grants);
        assert!(output.contains("PUBLIC grants"));
        assert!(output.contains("Database: "));
        assert!(output.contains("CONNECT"));
        assert!(output.contains("TEMPORARY"));
        assert!(output.contains("Schema \"public\""));
        assert!(output.contains("USAGE"));
        assert!(output.contains("CREATE"));
    }

    #[test]
    fn is_empty_with_only_database_grants() {
        let grants = PublicGrants {
            database_name: "mydb".to_string(),
            database_privileges: [Privilege::Connect].into_iter().collect(),
            schema_grants: vec![],
        };
        assert!(!grants.is_empty());
    }
}
