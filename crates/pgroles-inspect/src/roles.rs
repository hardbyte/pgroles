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
