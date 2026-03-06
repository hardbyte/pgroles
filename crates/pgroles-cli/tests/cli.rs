//! CLI integration tests for pgroles.
//!
//! These tests exercise the compiled binary via `assert_cmd`, verifying
//! exit codes, stdout, and stderr for all subcommands. Only the `validate`
//! subcommand can be tested without a live database — the others are
//! `#[ignore]`d for CI integration-test stage.

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::NamedTempFile;

use std::io::Write;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a temp file with the given contents and return it.
/// The file stays alive as long as the returned `NamedTempFile` is in scope.
fn write_temp_manifest(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    file.write_all(content.as_bytes())
        .expect("failed to write temp manifest");
    file.flush().expect("failed to flush temp manifest");
    file
}

fn pgroles_cmd() -> assert_cmd::Command {
    cargo_bin_cmd!("pgroles")
}

// ---------------------------------------------------------------------------
// Manifest fixtures
// ---------------------------------------------------------------------------

const VALID_MINIMAL: &str = r#"
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

const VALID_PROFILES: &str = r#"
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

const EMPTY_MANIFEST: &str = r#"
roles: []
"#;

// =========================================================================
// validate subcommand
// =========================================================================

#[test]
fn validate_valid_minimal_manifest() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid"))
        .stdout(predicate::str::contains("1 role(s) defined"))
        .stdout(predicate::str::contains("1 grant(s) defined"));
}

#[test]
fn validate_valid_profiles_manifest() {
    let manifest_file = write_temp_manifest(VALID_PROFILES);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid"))
        .stdout(predicate::str::contains("4 role(s) defined"));
}

#[test]
fn validate_empty_manifest() {
    let manifest_file = write_temp_manifest(EMPTY_MANIFEST);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid"))
        .stdout(predicate::str::contains("0 role(s) defined"));
}

#[test]
fn validate_invalid_yaml() {
    let manifest_file = write_temp_manifest(INVALID_YAML);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("YAML parse error"));
}

#[test]
fn validate_undefined_profile() {
    let manifest_file = write_temp_manifest(UNDEFINED_PROFILE);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nonexistent"));
}

#[test]
fn validate_nonexistent_file() {
    pgroles_cmd()
        .args([
            "validate",
            "--file",
            "/tmp/nonexistent-pgroles-test-xyz.yaml",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read manifest file"));
}

#[test]
fn validate_default_file_not_found() {
    // Running `pgroles validate` without --file should look for pgroles.yaml
    // in the current directory, which won't exist in a temp dir.
    pgroles_cmd()
        .current_dir(std::env::temp_dir())
        .args(["validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read manifest file"));
}

// =========================================================================
// Global CLI behaviour
// =========================================================================

#[test]
fn no_subcommand_shows_help() {
    // clap should show an error/help message when no subcommand is given.
    pgroles_cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn help_flag() {
    pgroles_cmd()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pgroles"))
        .stdout(predicate::str::contains("validate"))
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("apply"))
        .stdout(predicate::str::contains("inspect"));
}

#[test]
fn version_flag() {
    pgroles_cmd()
        .args(["--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pgroles"));
}

#[test]
fn validate_help() {
    pgroles_cmd()
        .args(["validate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Validate"))
        .stdout(predicate::str::contains("--file"));
}

#[test]
fn diff_help() {
    pgroles_cmd()
        .args(["diff", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"))
        .stdout(predicate::str::contains("--file"))
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn apply_help() {
    pgroles_cmd()
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"))
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn inspect_help() {
    pgroles_cmd()
        .args(["inspect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"));
}

#[test]
fn plan_alias_for_diff() {
    // `plan` should be an alias for `diff` — verify it shows the same help.
    pgroles_cmd()
        .args(["plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"))
        .stdout(predicate::str::contains("--format"));
}

// =========================================================================
// diff/plan subcommand — requires DB (ignored by default)
// =========================================================================

#[test]
fn diff_missing_database_url() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    // No DATABASE_URL env var and no --database-url flag → should fail
    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args(["diff", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("database-url"));
}

#[test]
fn apply_missing_database_url() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args(["apply", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("database-url"));
}

#[test]
fn inspect_missing_database_url() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args(["inspect", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("database-url"));
}

// =========================================================================
// diff/apply/inspect with invalid manifest (should fail before DB connect)
// =========================================================================

#[test]
fn diff_with_invalid_manifest() {
    let manifest_file = write_temp_manifest(INVALID_YAML);

    pgroles_cmd()
        .args([
            "diff",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("YAML parse error"));
}

#[test]
fn apply_with_invalid_manifest() {
    let manifest_file = write_temp_manifest(INVALID_YAML);

    pgroles_cmd()
        .args([
            "apply",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("YAML parse error"));
}

// =========================================================================
// Integration tests requiring a live database — #[ignore]d
// =========================================================================

/// These tests require a running PostgreSQL instance.
/// Set DATABASE_URL before running:
///   DATABASE_URL=postgres://localhost/pgroles_test cargo test -- --ignored
mod live_db {
    use super::*;
    use sqlx::{Executor, PgPool, Row};
    use tokio::runtime::Runtime;

    fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
        Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(future)
    }

    fn database_url() -> String {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
    }

    fn unique_name(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        format!("{prefix}_{nanos}")
    }

    fn execute_sql(sql: &str) {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            pool.execute(sql)
                .await
                .expect("failed to execute setup SQL");
        });
    }

    fn query_membership_flags(role: &str, member: &str) -> (bool, bool) {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query(
                r#"
                SELECT m.admin_option, m.inherit_option
                FROM pg_auth_members m
                JOIN pg_roles gr ON gr.oid = m.roleid
                JOIN pg_roles mr ON mr.oid = m.member
                WHERE gr.rolname = $1 AND mr.rolname = $2
                "#,
            )
            .bind(role)
            .bind(member)
            .fetch_one(&pool)
            .await
            .expect("failed to query membership flags");
            (row.get("admin_option"), row.get("inherit_option"))
        })
    }

    fn query_has_function_privilege(role: &str, signature: &str) -> bool {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query("SELECT has_function_privilege($1, $2, 'EXECUTE') AS allowed")
                .bind(role)
                .bind(signature)
                .fetch_one(&pool)
                .await
                .expect("failed to query function privilege");
            row.get("allowed")
        })
    }

    fn query_drop_role_safety(role: &str) -> pgroles_inspect::DropRoleSafetyReport {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            pgroles_inspect::inspect_drop_role_safety(&pool, &[role.to_string()])
                .await
                .expect("failed to inspect role-drop safety")
        })
    }

    #[test]
    #[ignore]
    fn diff_against_live_db() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();
    }

    #[test]
    #[ignore]
    fn diff_summary_format() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success();
    }

    #[test]
    #[ignore]
    fn apply_dry_run_against_live_db() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--dry-run",
            ])
            .assert()
            .success();
    }

    #[test]
    #[ignore]
    fn inspect_against_live_db() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "inspect",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Roles:"))
            .stdout(predicate::str::contains("Grants:"));
    }

    #[test]
    #[ignore]
    fn wildcard_table_grants_converge_after_apply() {
        let schema = unique_name("wildcard_schema");
        let role = unique_name("wildcard_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            CREATE TABLE "{schema}"."orders" (id integer);
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [SELECT]
    on: {{ type: table, schema: {schema}, name: "*" }}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn specific_function_grants_apply_and_converge() {
        let schema = unique_name("function_schema");
        let role = unique_name("function_role");
        let function_name = "refresh_users";
        let signature = format!(r#""{schema}"."{function_name}"(integer, text)"#);

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE FUNCTION "{schema}"."{function_name}"(integer, text)
            RETURNS integer
            LANGUAGE SQL
            AS $$ SELECT $1; $$;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [EXECUTE]
    on: {{ type: function, schema: {schema}, name: "{function_name}(integer, text)" }}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert!(
            query_has_function_privilege(&role, &signature),
            "role should have EXECUTE privilege on the function"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn membership_option_updates_apply_without_dropping_membership() {
        let group_role = unique_name("group_role");
        let member_role = unique_name("member_role");

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{member_role}";
            DROP ROLE IF EXISTS "{group_role}";
            "#
        ));

        let initial_manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {group_role}
  - name: {member_role}

memberships:
  - role: {group_role}
    members:
      - name: {member_role}
        inherit: true
        admin: false
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                initial_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        let updated_manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {group_role}
  - name: {member_role}

memberships:
  - role: {group_role}
    members:
      - name: {member_role}
        inherit: false
        admin: true
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                updated_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert_eq!(
            query_membership_flags(&group_role, &member_role),
            (true, false),
            "membership should remain present with updated admin/inherit flags"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                updated_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{member_role}";
            DROP ROLE IF EXISTS "{group_role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn drop_role_safety_reports_owned_objects() {
        let schema = unique_name("safety_schema");
        let role = unique_name("safety_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE ROLE "{role}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{role}";
            SET ROLE "{role}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            RESET ROLE;
            "#
        ));

        let report = query_drop_role_safety(&role);
        assert_eq!(report.issues.len(), 1, "expected one unsafe drop issue");
        let issue = &report.issues[0];
        assert_eq!(issue.role, role);
        assert!(
            issue.owned_object_count >= 2,
            "expected owned schema/table to be detected, got {:?}",
            issue
        );
        assert!(
            issue
                .owned_object_examples
                .iter()
                .any(|example| example.contains(&schema)),
            "expected at least one example mentioning the owned schema"
        );

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }
}
