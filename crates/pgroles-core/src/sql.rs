//! SQL generation from [`Change`] operations.
//!
//! Each [`Change`] variant is rendered into one or more PostgreSQL DDL
//! statements. All identifiers are double-quoted to handle names containing
//! hyphens, dots, `@` signs, etc.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::diff::Change;
use crate::manifest::{ObjectType, Privilege};
use crate::model::{RoleAttribute, RoleState};

// ---------------------------------------------------------------------------
// Identifier quoting
// ---------------------------------------------------------------------------

/// Double-quote a PostgreSQL identifier, escaping any embedded double quotes.
///
/// ```
/// use pgroles_core::sql::quote_ident;
/// assert_eq!(quote_ident("simple"), r#""simple""#);
/// assert_eq!(quote_ident("has\"quote"), r#""has""quote""#);
/// assert_eq!(quote_ident("user@example.com"), r#""user@example.com""#);
/// ```
pub fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

// ---------------------------------------------------------------------------
// SQL rendering
// ---------------------------------------------------------------------------

/// Render a single [`Change`] into a SQL statement (including trailing `;`).
pub fn render(change: &Change) -> String {
    render_statements(change).join("\n")
}

/// Render a single [`Change`] into one or more SQL statements.
pub fn render_statements(change: &Change) -> Vec<String> {
    match change {
        Change::CreateRole { name, state } => render_create_role(name, state),
        Change::AlterRole { name, attributes } => render_alter_role(name, attributes),
        Change::SetComment { name, comment } => render_set_comment(name, comment),
        Change::Grant {
            role,
            privileges,
            object_type,
            schema,
            name,
        } => render_grant(
            role,
            privileges,
            *object_type,
            schema.as_deref(),
            name.as_deref(),
        ),
        Change::Revoke {
            role,
            privileges,
            object_type,
            schema,
            name,
        } => render_revoke(
            role,
            privileges,
            *object_type,
            schema.as_deref(),
            name.as_deref(),
        ),
        Change::SetDefaultPrivilege {
            owner,
            schema,
            on_type,
            grantee,
            privileges,
        } => render_set_default_privilege(owner, schema, *on_type, grantee, privileges),
        Change::RevokeDefaultPrivilege {
            owner,
            schema,
            on_type,
            grantee,
            privileges,
        } => render_revoke_default_privilege(owner, schema, *on_type, grantee, privileges),
        Change::AddMember {
            role,
            member,
            inherit,
            admin,
        } => render_add_member(role, member, *inherit, *admin),
        Change::RemoveMember { role, member } => render_remove_member(role, member),
        Change::ReassignOwned { from_role, to_role } => render_reassign_owned(from_role, to_role),
        Change::DropOwned { role } => render_drop_owned(role),
        Change::DropRole { name } => vec![format!("DROP ROLE {};", quote_ident(name))],
    }
}

/// Render all changes into a single SQL script.
pub fn render_all(changes: &[Change]) -> String {
    changes
        .iter()
        .flat_map(render_statements)
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// CREATE ROLE
// ---------------------------------------------------------------------------

fn render_create_role(name: &str, state: &RoleState) -> Vec<String> {
    let mut sql = format!("CREATE ROLE {}", quote_ident(name));
    let mut options = vec![
        bool_option("LOGIN", "NOLOGIN", state.login),
        bool_option("SUPERUSER", "NOSUPERUSER", state.superuser),
        bool_option("CREATEDB", "NOCREATEDB", state.createdb),
        bool_option("CREATEROLE", "NOCREATEROLE", state.createrole),
        bool_option("INHERIT", "NOINHERIT", state.inherit),
        bool_option("REPLICATION", "NOREPLICATION", state.replication),
        bool_option("BYPASSRLS", "NOBYPASSRLS", state.bypassrls),
    ];

    if state.connection_limit != -1 {
        options.push(format!("CONNECTION LIMIT {}", state.connection_limit));
    }

    let _ = write!(sql, " {}", options.join(" "));
    sql.push(';');

    let mut statements = vec![sql];
    if let Some(comment) = &state.comment {
        statements.push(format!(
            "COMMENT ON ROLE {} IS {};",
            quote_ident(name),
            quote_literal(comment)
        ));
    }

    statements
}

fn bool_option(positive: &str, negative: &str, value: bool) -> String {
    if value {
        positive.to_string()
    } else {
        negative.to_string()
    }
}

// ---------------------------------------------------------------------------
// ALTER ROLE
// ---------------------------------------------------------------------------

fn render_alter_role(name: &str, attributes: &[RoleAttribute]) -> Vec<String> {
    let mut options = Vec::new();
    for attr in attributes {
        match attr {
            RoleAttribute::Login(v) => options.push(bool_option("LOGIN", "NOLOGIN", *v)),
            RoleAttribute::Superuser(v) => {
                options.push(bool_option("SUPERUSER", "NOSUPERUSER", *v));
            }
            RoleAttribute::Createdb(v) => {
                options.push(bool_option("CREATEDB", "NOCREATEDB", *v));
            }
            RoleAttribute::Createrole(v) => {
                options.push(bool_option("CREATEROLE", "NOCREATEROLE", *v));
            }
            RoleAttribute::Inherit(v) => options.push(bool_option("INHERIT", "NOINHERIT", *v)),
            RoleAttribute::Replication(v) => {
                options.push(bool_option("REPLICATION", "NOREPLICATION", *v));
            }
            RoleAttribute::Bypassrls(v) => {
                options.push(bool_option("BYPASSRLS", "NOBYPASSRLS", *v));
            }
            RoleAttribute::ConnectionLimit(v) => {
                options.push(format!("CONNECTION LIMIT {v}"));
            }
        }
    }
    vec![format!(
        "ALTER ROLE {} {};",
        quote_ident(name),
        options.join(" ")
    )]
}

// ---------------------------------------------------------------------------
// COMMENT ON ROLE
// ---------------------------------------------------------------------------

fn render_set_comment(name: &str, comment: &Option<String>) -> Vec<String> {
    vec![match comment {
        Some(text) => format!(
            "COMMENT ON ROLE {} IS {};",
            quote_ident(name),
            quote_literal(text)
        ),
        None => format!("COMMENT ON ROLE {} IS NULL;", quote_ident(name)),
    }]
}

// ---------------------------------------------------------------------------
// GRANT / REVOKE
// ---------------------------------------------------------------------------

fn render_grant(
    role: &str,
    privileges: &BTreeSet<Privilege>,
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
) -> Vec<String> {
    let privilege_list = format_privileges(privileges);
    let target = format_object_target(object_type, schema, name);
    vec![format!(
        "GRANT {} ON {} TO {};",
        privilege_list,
        target,
        quote_ident(role)
    )]
}

fn render_revoke(
    role: &str,
    privileges: &BTreeSet<Privilege>,
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
) -> Vec<String> {
    let privilege_list = format_privileges(privileges);
    let target = format_object_target(object_type, schema, name);
    vec![format!(
        "REVOKE {} ON {} FROM {};",
        privilege_list,
        target,
        quote_ident(role)
    )]
}

/// Format the object target for GRANT/REVOKE statements.
///
/// - Schema-level: `SCHEMA "myschema"` — object_type=Schema, name=Some("myschema")
/// - Wildcard: `ALL TABLES IN SCHEMA "myschema"` — name=Some("*")
/// - Specific: `TABLE "myschema"."mytable"` — name=Some("mytable")
/// - Database: `DATABASE "mydb"` — object_type=Database, name=Some("mydb")
fn format_object_target(
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
) -> String {
    let type_keyword = sql_object_type_keyword(object_type);

    match object_type {
        ObjectType::Schema => {
            // Schema grants: name is the schema name itself
            let schema_name = name.unwrap_or("public");
            format!("{type_keyword} {}", quote_ident(schema_name))
        }
        ObjectType::Database => {
            let db_name = name.unwrap_or("postgres");
            format!("{type_keyword} {}", quote_ident(db_name))
        }
        ObjectType::Function => match name {
            Some("*") => {
                let schema_name = schema.unwrap_or("public");
                format!("ALL FUNCTIONS IN SCHEMA {}", quote_ident(schema_name))
            }
            Some(function_name) => format_function_target(schema, function_name),
            None => {
                let schema_name = schema.unwrap_or("public");
                format!("{type_keyword} {}", quote_ident(schema_name))
            }
        },
        _ => {
            match name {
                Some("*") => {
                    // Wildcard: ALL TABLES IN SCHEMA "schema"
                    let plural = sql_object_type_plural(object_type);
                    let schema_name = schema.unwrap_or("public");
                    format!("ALL {plural} IN SCHEMA {}", quote_ident(schema_name))
                }
                Some(obj_name) => {
                    // Specific object: TABLE "schema"."table"
                    let schema_name = schema.unwrap_or("public");
                    format!(
                        "{type_keyword} {}.{}",
                        quote_ident(schema_name),
                        quote_ident(obj_name)
                    )
                }
                None => {
                    // Shouldn't happen for non-schema/database types, but handle gracefully
                    let schema_name = schema.unwrap_or("public");
                    format!("{type_keyword} {}", quote_ident(schema_name))
                }
            }
        }
    }
}

fn format_function_target(schema: Option<&str>, function_name: &str) -> String {
    let schema_name = schema.unwrap_or("public");

    match function_name.rfind('(') {
        Some(paren_idx) if function_name.ends_with(')') => {
            let base_name = &function_name[..paren_idx];
            let args = &function_name[paren_idx..];
            format!(
                "FUNCTION {}.{}{}",
                quote_ident(schema_name),
                quote_ident(base_name),
                args
            )
        }
        _ => format!(
            "FUNCTION {}.{}",
            quote_ident(schema_name),
            quote_ident(function_name)
        ),
    }
}

/// Map ObjectType to the SQL keyword used in GRANT/REVOKE.
fn sql_object_type_keyword(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Table => "TABLE",
        ObjectType::View => "TABLE", // PostgreSQL treats views as tables for GRANT
        ObjectType::MaterializedView => "TABLE", // Same
        ObjectType::Sequence => "SEQUENCE",
        ObjectType::Function => "FUNCTION",
        ObjectType::Schema => "SCHEMA",
        ObjectType::Database => "DATABASE",
        ObjectType::Type => "TYPE",
    }
}

/// Map ObjectType to the SQL plural keyword used in ALL ... IN SCHEMA.
fn sql_object_type_plural(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Table | ObjectType::View | ObjectType::MaterializedView => "TABLES",
        ObjectType::Sequence => "SEQUENCES",
        ObjectType::Function => "FUNCTIONS",
        ObjectType::Type => "TYPES",
        // Schema/Database don't use ALL ... IN SCHEMA syntax
        ObjectType::Schema | ObjectType::Database => "TABLES",
    }
}

/// Format a privilege set as a comma-separated string.
fn format_privileges(privileges: &BTreeSet<Privilege>) -> String {
    privileges
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// ALTER DEFAULT PRIVILEGES
// ---------------------------------------------------------------------------

fn render_set_default_privilege(
    owner: &str,
    schema: &str,
    on_type: ObjectType,
    grantee: &str,
    privileges: &BTreeSet<Privilege>,
) -> Vec<String> {
    let privilege_list = format_privileges(privileges);
    let type_plural = sql_object_type_plural(on_type);
    vec![format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} GRANT {} ON {} TO {};",
        quote_ident(owner),
        quote_ident(schema),
        privilege_list,
        type_plural,
        quote_ident(grantee)
    )]
}

fn render_revoke_default_privilege(
    owner: &str,
    schema: &str,
    on_type: ObjectType,
    grantee: &str,
    privileges: &BTreeSet<Privilege>,
) -> Vec<String> {
    let privilege_list = format_privileges(privileges);
    let type_plural = sql_object_type_plural(on_type);
    vec![format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} REVOKE {} ON {} FROM {};",
        quote_ident(owner),
        quote_ident(schema),
        privilege_list,
        type_plural,
        quote_ident(grantee)
    )]
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

fn render_add_member(role: &str, member: &str, inherit: bool, admin: bool) -> Vec<String> {
    let mut sql = format!("GRANT {} TO {}", quote_ident(role), quote_ident(member));

    // PostgreSQL 16+ supports WITH INHERIT / WITH ADMIN in GRANT ... TO
    let mut options = Vec::new();
    if inherit {
        options.push("INHERIT TRUE");
    } else {
        options.push("INHERIT FALSE");
    }
    if admin {
        options.push("ADMIN TRUE");
    }

    if !options.is_empty() {
        let _ = write!(sql, " WITH {}", options.join(", "));
    }

    sql.push(';');
    vec![sql]
}

fn render_remove_member(role: &str, member: &str) -> Vec<String> {
    vec![format!(
        "REVOKE {} FROM {};",
        quote_ident(role),
        quote_ident(member)
    )]
}

fn render_reassign_owned(from_role: &str, to_role: &str) -> Vec<String> {
    vec![format!(
        "REASSIGN OWNED BY {} TO {};",
        quote_ident(from_role),
        quote_ident(to_role)
    )]
}

fn render_drop_owned(role: &str) -> Vec<String> {
    vec![format!("DROP OWNED BY {};", quote_ident(role))]
}

// ---------------------------------------------------------------------------
// String quoting
// ---------------------------------------------------------------------------

/// Single-quote a SQL string literal, escaping single quotes.
fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_ident_simple() {
        assert_eq!(quote_ident("simple"), "\"simple\"");
    }

    #[test]
    fn quote_ident_with_hyphen() {
        assert_eq!(quote_ident("inventory-editor"), "\"inventory-editor\"");
    }

    #[test]
    fn quote_ident_with_email() {
        assert_eq!(quote_ident("user@example.com"), "\"user@example.com\"");
    }

    #[test]
    fn quote_ident_with_embedded_quotes() {
        assert_eq!(quote_ident("has\"quote"), "\"has\"\"quote\"");
    }

    #[test]
    fn quote_literal_simple() {
        assert_eq!(quote_literal("hello"), "'hello'");
    }

    #[test]
    fn quote_literal_with_embedded_quotes() {
        assert_eq!(quote_literal("it's"), "'it''s'");
    }

    #[test]
    fn render_create_role_basic() {
        let change = Change::CreateRole {
            name: "inventory-editor".to_string(),
            state: RoleState::default(),
        };
        let sql = render(&change);
        assert!(sql.starts_with("CREATE ROLE \"inventory-editor\""));
        assert!(sql.contains("NOLOGIN"));
        assert!(sql.contains("NOSUPERUSER"));
        assert!(sql.contains("INHERIT")); // default is INHERIT
        assert!(sql.ends_with(';'));
    }

    #[test]
    fn render_create_role_with_login_and_comment() {
        let change = Change::CreateRole {
            name: "analytics".to_string(),
            state: RoleState {
                login: true,
                comment: Some("Analytics readonly role".to_string()),
                ..RoleState::default()
            },
        };
        let sql = render(&change);
        assert!(sql.contains("LOGIN"));
        assert!(sql.contains("COMMENT ON ROLE \"analytics\" IS 'Analytics readonly role';"));
    }

    #[test]
    fn render_alter_role() {
        let change = Change::AlterRole {
            name: "r1".to_string(),
            attributes: vec![RoleAttribute::Login(true), RoleAttribute::Createdb(true)],
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"r1\" LOGIN CREATEDB;");
    }

    #[test]
    fn render_drop_role() {
        let change = Change::DropRole {
            name: "old-role".to_string(),
        };
        assert_eq!(render(&change), "DROP ROLE \"old-role\";");
    }

    #[test]
    fn render_grant_schema_usage() {
        let change = Change::Grant {
            role: "inventory-editor".to_string(),
            privileges: BTreeSet::from([Privilege::Usage]),
            object_type: ObjectType::Schema,
            schema: None,
            name: Some("inventory".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT USAGE ON SCHEMA \"inventory\" TO \"inventory-editor\";"
        );
    }

    #[test]
    fn render_grant_all_tables() {
        let change = Change::Grant {
            role: "inventory-editor".to_string(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            object_type: ObjectType::Table,
            schema: Some("inventory".to_string()),
            name: Some("*".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT INSERT, SELECT ON ALL TABLES IN SCHEMA \"inventory\" TO \"inventory-editor\";"
        );
    }

    #[test]
    fn render_grant_specific_table() {
        let change = Change::Grant {
            role: "r1".to_string(),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("users".to_string()),
        };
        let sql = render(&change);
        assert_eq!(sql, "GRANT SELECT ON TABLE \"public\".\"users\" TO \"r1\";");
    }

    #[test]
    fn render_grant_specific_function() {
        let change = Change::Grant {
            role: "r1".to_string(),
            privileges: BTreeSet::from([Privilege::Execute]),
            object_type: ObjectType::Function,
            schema: Some("public".to_string()),
            name: Some("refresh_users(integer, text)".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT EXECUTE ON FUNCTION \"public\".\"refresh_users\"(integer, text) TO \"r1\";"
        );
    }

    #[test]
    fn render_revoke_all_sequences() {
        let change = Change::Revoke {
            role: "inventory-editor".to_string(),
            privileges: BTreeSet::from([Privilege::Usage, Privilege::Select]),
            object_type: ObjectType::Sequence,
            schema: Some("inventory".to_string()),
            name: Some("*".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "REVOKE SELECT, USAGE ON ALL SEQUENCES IN SCHEMA \"inventory\" FROM \"inventory-editor\";"
        );
    }

    #[test]
    fn render_set_default_privilege() {
        let change = Change::SetDefaultPrivilege {
            owner: "app_owner".to_string(),
            schema: "inventory".to_string(),
            on_type: ObjectType::Table,
            grantee: "inventory-editor".to_string(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "ALTER DEFAULT PRIVILEGES FOR ROLE \"app_owner\" IN SCHEMA \"inventory\" GRANT INSERT, SELECT ON TABLES TO \"inventory-editor\";"
        );
    }

    #[test]
    fn render_revoke_default_privilege() {
        let change = Change::RevokeDefaultPrivilege {
            owner: "app_owner".to_string(),
            schema: "inventory".to_string(),
            on_type: ObjectType::Function,
            grantee: "inventory-editor".to_string(),
            privileges: BTreeSet::from([Privilege::Execute]),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "ALTER DEFAULT PRIVILEGES FOR ROLE \"app_owner\" IN SCHEMA \"inventory\" REVOKE EXECUTE ON FUNCTIONS FROM \"inventory-editor\";"
        );
    }

    #[test]
    fn render_add_member_basic() {
        let change = Change::AddMember {
            role: "inventory-editor".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT \"inventory-editor\" TO \"user@example.com\" WITH INHERIT TRUE;"
        );
    }

    #[test]
    fn render_add_member_with_admin() {
        let change = Change::AddMember {
            role: "inventory-editor".to_string(),
            member: "admin@example.com".to_string(),
            inherit: true,
            admin: true,
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT \"inventory-editor\" TO \"admin@example.com\" WITH INHERIT TRUE, ADMIN TRUE;"
        );
    }

    #[test]
    fn render_add_member_no_inherit() {
        let change = Change::AddMember {
            role: "inventory-editor".to_string(),
            member: "noinherit@example.com".to_string(),
            inherit: false,
            admin: false,
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT \"inventory-editor\" TO \"noinherit@example.com\" WITH INHERIT FALSE;"
        );
    }

    #[test]
    fn render_remove_member() {
        let change = Change::RemoveMember {
            role: "inventory-editor".to_string(),
            member: "user@example.com".to_string(),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "REVOKE \"inventory-editor\" FROM \"user@example.com\";"
        );
    }

    #[test]
    fn render_reassign_owned() {
        let change = Change::ReassignOwned {
            from_role: "legacy-owner".to_string(),
            to_role: "app-owner".to_string(),
        };
        assert_eq!(
            render(&change),
            "REASSIGN OWNED BY \"legacy-owner\" TO \"app-owner\";"
        );
    }

    #[test]
    fn render_drop_owned() {
        let change = Change::DropOwned {
            role: "legacy-owner".to_string(),
        };
        assert_eq!(render(&change), "DROP OWNED BY \"legacy-owner\";");
    }

    #[test]
    fn render_set_comment_some() {
        let change = Change::SetComment {
            name: "r1".to_string(),
            comment: Some("A test role".to_string()),
        };
        assert_eq!(render(&change), "COMMENT ON ROLE \"r1\" IS 'A test role';");
    }

    #[test]
    fn render_set_comment_none() {
        let change = Change::SetComment {
            name: "r1".to_string(),
            comment: None,
        };
        assert_eq!(render(&change), "COMMENT ON ROLE \"r1\" IS NULL;");
    }

    /// Full integration: manifest → expand → model → diff → SQL
    #[test]
    fn full_pipeline_manifest_to_sql() {
        use crate::diff::diff;
        use crate::manifest::{expand_manifest, parse_manifest};
        use crate::model::RoleGraph;

        let yaml = r#"
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

schemas:
  - name: inventory
    profiles: [editor]

memberships:
  - role: inventory-editor
    members:
      - name: "user@example.com"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let desired =
            RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap();
        let current = RoleGraph::default();

        let changes = diff(&current, &desired);
        let sql = render_all(&changes);

        // Smoke test: the output should contain key SQL statements
        assert!(sql.contains("CREATE ROLE \"inventory-editor\""));
        assert!(sql.contains("GRANT USAGE ON SCHEMA \"inventory\" TO \"inventory-editor\""));
        assert!(sql.contains("ALL TABLES IN SCHEMA \"inventory\""));
        assert!(sql.contains("ALTER DEFAULT PRIVILEGES"));
        assert!(sql.contains("GRANT \"inventory-editor\" TO \"user@example.com\""));

        // Print for manual inspection during development
        #[cfg(test)]
        {
            eprintln!("--- Generated SQL ---\n{sql}\n--- End ---");
        }
    }
}
