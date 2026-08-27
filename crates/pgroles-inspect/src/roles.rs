//! Query PostgreSQL role attributes from `pg_roles` / `pg_shdescription`.

use sqlx::PgPool;

use pgroles_core::model::RoleState;

/// A row from our role-attributes query.
#[derive(Debug, sqlx::FromRow)]
pub struct RoleRow {
    pub rolname: String,
    pub rolsuper: bool,
    pub rolinherit: bool,
    pub rolcreaterole: bool,
    pub rolcreatedb: bool,
    pub rolcanlogin: bool,
    pub rolreplication: bool,
    pub rolbypassrls: bool,
    pub rolconnlimit: i32,
    /// Comment from pg_shdescription (NULL if none).
    pub comment: Option<String>,
    /// Password expiration from pg_roles.rolvaliduntil (NULL if no expiration).
    pub rolvaliduntil: Option<String>,
    /// Cluster-wide role config defaults from pg_roles.rolconfig, as
    /// `parameter=value` strings (NULL if none). Per-database settings
    /// (`ALTER ROLE ... IN DATABASE`) do not appear here.
    pub rolconfig: Option<Vec<String>>,
}

impl RoleRow {
    /// Convert to the core model's `RoleState`.
    pub fn to_role_state(&self) -> RoleState {
        RoleState {
            login: self.rolcanlogin,
            superuser: self.rolsuper,
            createdb: self.rolcreatedb,
            createrole: self.rolcreaterole,
            inherit: self.rolinherit,
            replication: self.rolreplication,
            bypassrls: self.rolbypassrls,
            connection_limit: self.rolconnlimit,
            comment: self.comment.clone(),
            password_valid_until: self.rolvaliduntil.clone(),
            config: self
                .rolconfig
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(|entry| parse_rolconfig_entry(entry))
                .collect(),
        }
    }
}

/// Parse one `pg_roles.rolconfig` entry (`parameter=value`) into a
/// `(parameter, value)` pair.
///
/// PostgreSQL serializes `GUC_LIST_QUOTE` parameters (search_path, ...) with
/// each list element individually quoted as needed (e.g.
/// `search_path="$user", public`). Those values are canonicalized element-wise
/// so they compare equal to the manifest's desired value, which passes through
/// the same canonicalization. All other parameters are stored verbatim.
fn parse_rolconfig_entry(entry: &str) -> Option<(String, String)> {
    let (parameter, raw_value) = entry.split_once('=')?;
    let parameter = parameter.to_ascii_lowercase();
    let value = if pgroles_core::guc::is_list_quote_parameter(&parameter) {
        pgroles_core::guc::canonicalize_list_guc_value(raw_value)
    } else {
        raw_value.to_string()
    };
    Some((parameter, value))
}

/// Fetch all non-system roles from the database.
///
/// Excludes PostgreSQL internal roles (those starting with `pg_`) and the
/// `postgres` superuser, since we don't want to manage those.
///
/// The `managed_roles` parameter, if provided, filters to only those role names.
/// If `None`, returns all non-system roles.
pub async fn fetch_roles(
    pool: &PgPool,
    managed_roles: Option<&[&str]>,
) -> Result<Vec<RoleRow>, sqlx::Error> {
    // We use pg_roles (a view over pg_authid) because it doesn't require
    // superuser access. We LEFT JOIN pg_shdescription for role comments.
    //
    // pg_shdescription stores shared object comments. For roles, the
    // classoid is pg_authid's OID and objoid is the role's OID.
    match managed_roles {
        Some(names) => {
            sqlx::query_as::<_, RoleRow>(
                r#"
                SELECT
                    r.rolname,
                    r.rolsuper,
                    r.rolinherit,
                    r.rolcreaterole,
                    r.rolcreatedb,
                    r.rolcanlogin,
                    r.rolreplication,
                    r.rolbypassrls,
                    r.rolconnlimit,
                    d.description AS comment,
                    -- 'infinity' means "never expires", which the manifest
                    -- expresses by omitting password_valid_until — and to_char
                    -- renders non-finite timestamps as an empty string, which
                    -- no manifest value can ever equal, so reporting it would
                    -- re-plan an ALTER ROLE forever. Positive infinity
                    -- therefore inspects as "no expiration". Negative infinity
                    -- means "already expired" — the opposite — so it stays a
                    -- distinguishable literal: no manifest value equals it
                    -- either (the validator only accepts finite UTC
                    -- timestamps), so the diff plans one ALTER ROLE to the
                    -- declared state and converges on the next inspection.
                    CASE WHEN r.rolvaliduntil IS NULL
                              OR r.rolvaliduntil = 'infinity'::timestamptz
                         THEN NULL
                         WHEN r.rolvaliduntil = '-infinity'::timestamptz
                         THEN '-infinity'
                         ELSE to_char(r.rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                         END AS rolvaliduntil,
                    r.rolconfig
                FROM pg_roles r
                LEFT JOIN pg_shdescription d
                    ON d.objoid = r.oid
                    AND d.classoid = 'pg_authid'::regclass
                WHERE r.rolname = ANY($1)
                ORDER BY r.rolname
                "#,
            )
            .bind(names)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, RoleRow>(
                r#"
                SELECT
                    r.rolname,
                    r.rolsuper,
                    r.rolinherit,
                    r.rolcreaterole,
                    r.rolcreatedb,
                    r.rolcanlogin,
                    r.rolreplication,
                    r.rolbypassrls,
                    r.rolconnlimit,
                    d.description AS comment,
                    -- 'infinity' means "never expires", which the manifest
                    -- expresses by omitting password_valid_until — and to_char
                    -- renders non-finite timestamps as an empty string, which
                    -- no manifest value can ever equal, so reporting it would
                    -- re-plan an ALTER ROLE forever. Positive infinity
                    -- therefore inspects as "no expiration". Negative infinity
                    -- means "already expired" — the opposite — so it stays a
                    -- distinguishable literal: no manifest value equals it
                    -- either (the validator only accepts finite UTC
                    -- timestamps), so the diff plans one ALTER ROLE to the
                    -- declared state and converges on the next inspection.
                    CASE WHEN r.rolvaliduntil IS NULL
                              OR r.rolvaliduntil = 'infinity'::timestamptz
                         THEN NULL
                         WHEN r.rolvaliduntil = '-infinity'::timestamptz
                         THEN '-infinity'
                         ELSE to_char(r.rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                         END AS rolvaliduntil,
                    r.rolconfig
                FROM pg_roles r
                LEFT JOIN pg_shdescription d
                    ON d.objoid = r.oid
                    AND d.classoid = 'pg_authid'::regclass
                WHERE r.rolname NOT LIKE 'pg_%'
                    AND r.rolname <> 'postgres'
                ORDER BY r.rolname
                "#,
            )
            .fetch_all(pool)
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_row_maps_to_role_state() {
        let row = RoleRow {
            rolname: "analytics".to_string(),
            rolsuper: false,
            rolinherit: false,
            rolcreaterole: true,
            rolcreatedb: false,
            rolcanlogin: true,
            rolreplication: false,
            rolbypassrls: true,
            rolconnlimit: 12,
            comment: Some("analytics login".to_string()),
            rolvaliduntil: Some("2026-12-31T00:00:00Z".to_string()),
            rolconfig: Some(vec![
                "role=combined".to_string(),
                "search_path=\"$user\", public".to_string(),
            ]),
        };

        let state = row.to_role_state();
        assert_eq!(
            state.config.get("role").map(String::as_str),
            Some("combined")
        );
        assert_eq!(
            state.config.get("search_path").map(String::as_str),
            Some("\"$user\", public")
        );
        assert!(state.login);
        assert!(!state.superuser);
        assert!(!state.inherit);
        assert!(state.createrole);
        assert!(!state.createdb);
        assert!(!state.replication);
        assert!(state.bypassrls);
        assert_eq!(state.connection_limit, 12);
        assert_eq!(state.comment.as_deref(), Some("analytics login"));
        assert_eq!(
            state.password_valid_until.as_deref(),
            Some("2026-12-31T00:00:00Z")
        );
    }

    fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Runtime::new()
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
        use sqlx::Executor;

        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            pool.execute(sql)
                .await
                .expect("failed to execute setup SQL");
        });
    }

    struct TestDbCleanup {
        sql: String,
    }

    impl TestDbCleanup {
        fn new(sql: String) -> Self {
            Self { sql }
        }
    }

    impl Drop for TestDbCleanup {
        fn drop(&mut self) {
            execute_sql(&self.sql);
        }
    }

    #[test]
    fn parse_rolconfig_entry_splits_on_first_equals() {
        // GUC values may themselves contain '=' — only the first one is the
        // parameter/value separator. app.motd is not a list parameter, so
        // its value is kept verbatim.
        assert_eq!(
            parse_rolconfig_entry("app.motd=a=b"),
            Some(("app.motd".to_string(), "a=b".to_string()))
        );
        assert_eq!(parse_rolconfig_entry("no_separator"), None);
    }

    #[test]
    fn parse_rolconfig_entry_keeps_non_list_values_verbatim() {
        // Non-list parameters are stored verbatim by PostgreSQL — quotes are
        // part of the value, not serialization.
        assert_eq!(
            parse_rolconfig_entry(r#"app.motd="not unwrapped""#),
            Some(("app.motd".to_string(), r#""not unwrapped""#.to_string()))
        );
    }

    #[test]
    fn parse_rolconfig_entry_canonicalizes_list_parameters() {
        // PostgreSQL serializes GUC_LIST_QUOTE parameters with per-element
        // quoting; parsing canonicalizes so manifest values compare equal.
        assert_eq!(
            parse_rolconfig_entry(r#"search_path="$user", public"#),
            Some(("search_path".to_string(), r#""$user", public"#.to_string()))
        );
        // A single element containing a comma (the single-literal footgun)
        // stays one quoted element — distinct from a two-element list.
        assert_eq!(
            parse_rolconfig_entry(r#"search_path="app, public""#),
            Some(("search_path".to_string(), r#""app, public""#.to_string()))
        );
    }

    #[test]
    fn parse_rolconfig_entry_lowercases_parameter_names() {
        assert_eq!(
            parse_rolconfig_entry("Role=combined"),
            Some(("role".to_string(), "combined".to_string()))
        );
    }

    #[test]
    #[ignore]
    fn fetch_roles_reads_role_config_defaults() {
        let login = unique_name("config_login");
        let group = unique_name("config_group");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP ROLE IF EXISTS "{login}";
            DROP ROLE IF EXISTS "{group}";
            "#
        ));

        // search_path is a GUC_LIST_QUOTE parameter: PostgreSQL stores each
        // element individually quoted as needed (`search_path="$user", public`),
        // which exercises the element-wise canonicalization.
        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{login}";
            DROP ROLE IF EXISTS "{group}";
            CREATE ROLE "{group}" NOLOGIN;
            CREATE ROLE "{login}" LOGIN;
            GRANT "{group}" TO "{login}";
            ALTER ROLE "{login}" SET "role" = '{group}';
            ALTER ROLE "{login}" SET "search_path" = '$user', 'public';
            ALTER ROLE "{login}" SET "app.tenant" = 'acme';
            "#
        ));

        let roles = with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            fetch_roles(&pool, Some(&[login.as_str()]))
                .await
                .expect("failed to fetch scoped roles")
        });

        assert_eq!(roles.len(), 1);
        let config = &roles[0].to_role_state().config;
        assert_eq!(config.get("role").map(String::as_str), Some(group.as_str()));
        assert_eq!(
            config.get("search_path").map(String::as_str),
            Some("\"$user\", public")
        );
        assert_eq!(config.get("app.tenant").map(String::as_str), Some("acme"));
    }

    #[test]
    #[ignore]
    fn fetch_roles_ignores_per_database_config() {
        let login = unique_name("config_dbscoped");
        let _cleanup = TestDbCleanup::new(format!(r#"DROP ROLE IF EXISTS "{login}";"#));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{login}";
            CREATE ROLE "{login}" LOGIN;
            "#
        ));

        let roles = with_runtime(async {
            use sqlx::Executor;

            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let (dbname,): (String,) = sqlx::query_as("SELECT current_database()")
                .fetch_one(&pool)
                .await
                .expect("failed to read current database name");
            pool.execute(
                format!(r#"ALTER ROLE "{login}" IN DATABASE "{dbname}" SET "work_mem" = '64MB';"#)
                    .as_str(),
            )
            .await
            .expect("failed to set per-database config");

            fetch_roles(&pool, Some(&[login.as_str()]))
                .await
                .expect("failed to fetch scoped roles")
        });

        assert_eq!(roles.len(), 1);
        assert!(
            roles[0].to_role_state().config.is_empty(),
            "per-database settings must not appear as managed cluster-wide config"
        );
    }

    #[test]
    #[ignore]
    fn fetch_roles_scopes_to_managed_names() {
        let managed = unique_name("managed_role");
        let extra = unique_name("extra_role");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP ROLE IF EXISTS "{managed}";
            DROP ROLE IF EXISTS "{extra}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{managed}";
            DROP ROLE IF EXISTS "{extra}";
            CREATE ROLE "{managed}" LOGIN;
            CREATE ROLE "{extra}" NOLOGIN;
            "#
        ));

        let roles = with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            fetch_roles(&pool, Some(&[managed.as_str()]))
                .await
                .expect("failed to fetch scoped roles")
        });

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].rolname, managed);
    }

    #[test]
    #[ignore]
    fn fetch_roles_unscoped_excludes_postgres_but_includes_user_roles() {
        let user_role = unique_name("role_inventory");
        let _cleanup = TestDbCleanup::new(format!(r#"DROP ROLE IF EXISTS "{user_role}";"#));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{user_role}";
            CREATE ROLE "{user_role}" LOGIN;
            "#
        ));

        let roles = with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            fetch_roles(&pool, None)
                .await
                .expect("failed to fetch unscoped roles")
        });

        assert!(
            roles.iter().any(|row| row.rolname == user_role),
            "expected unscoped fetch to include the test user role"
        );
        assert!(
            roles.iter().all(|row| row.rolname != "postgres"),
            "expected unscoped fetch to exclude postgres"
        );
    }
}
