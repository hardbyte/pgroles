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
        }
    }
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
                    CASE WHEN r.rolvaliduntil IS NOT NULL
                         THEN to_char(r.rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                         ELSE NULL END AS rolvaliduntil
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
                    CASE WHEN r.rolvaliduntil IS NOT NULL
                         THEN to_char(r.rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                         ELSE NULL END AS rolvaliduntil
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
        };

        let state = row.to_role_state();
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
