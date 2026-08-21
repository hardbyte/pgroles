//! Executor-authority preflight for planned changes.
//!
//! Two failure modes are caught before apply:
//!
//! `ALTER DEFAULT PRIVILEGES FOR ROLE owner` requires the executor to be a
//! member of the owner role (or a superuser). Without that, apply fails
//! mid-transaction with a permission error, so the check only moves the
//! failure earlier and names the owner.
//!
//! `REVOKE ... FROM PUBLIC` is worse than a loud failure: issued by a role
//! without the owner's authority it silently removes nothing, the next
//! inspection still sees the privilege, and the controller re-plans the same
//! revoke forever. Implicit PUBLIC grants are always grantor-owned, so
//! membership in the object owner (which `pg_has_role` reports true for
//! superusers too) is exactly the authority the revoke needs. Role-grantee
//! revokes are deliberately not checked: an executor can hold revoke
//! authority for those without owner membership, and blocking such plans
//! would regress setups that work today.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;

use pgroles_core::diff::Change;
use pgroles_core::manifest::{ObjectType, is_predefined_role, predefined_role_min_version};
use pgroles_core::model::{GrantKey, Grantee, RoleGraph};

/// Maximum number of objects named by an [`AuthorityIssue::PublicRevoke`].
const REVOKE_EXAMPLE_LIMIT: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityIssue {
    /// The executor cannot act as the owner of a planned
    /// `ALTER DEFAULT PRIVILEGES` change.
    DefaultPrivilegeOwner { owner: String, executor: String },

    /// A planned `ALTER DEFAULT PRIVILEGES` names an owner that does not
    /// exist and that this plan does not create.
    MissingDefaultPrivilegeOwner { owner: String },

    /// A planned membership change grants or revokes a predefined (`pg_*`)
    /// role, and the executor lacks ADMIN OPTION on it. In PostgreSQL 16+
    /// this effectively requires a superuser executor or an explicit
    /// `GRANT <pg_role> TO executor WITH ADMIN OPTION`; `CREATEROLE` alone
    /// is not sufficient.
    PredefinedRoleGrant { role: String, executor: String },

    /// A manifest membership names a predefined (`pg_*`) role the connected
    /// server does not have. `min_version` carries the PostgreSQL major
    /// version that introduced the role when it is one we recognize.
    MissingPredefinedRole {
        role: String,
        server_major: u32,
        min_version: Option<u32>,
    },

    /// A planned `REVOKE ... FROM PUBLIC` covers objects whose owners the
    /// executor cannot act as, so the revoke would silently do nothing there.
    PublicRevoke {
        object_type: ObjectType,
        schema: Option<String>,
        executor: String,
        skipped_count: usize,
        /// Up to [`REVOKE_EXAMPLE_LIMIT`] affected objects as
        /// `(name, owner)`.
        examples: Vec<(String, String)>,
    },
}

impl std::fmt::Display for AuthorityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityIssue::DefaultPrivilegeOwner { owner, executor } => write!(
                f,
                "UnsatisfiableDefaultPrivilegeChange: cannot ALTER DEFAULT PRIVILEGES \
                 FOR ROLE \"{owner}\" as executor \"{executor}\"; requires membership \
                 in the owner role or superuser"
            ),
            AuthorityIssue::MissingDefaultPrivilegeOwner { owner } => write!(
                f,
                "UnsatisfiableDefaultPrivilegeChange: default privileges name owner \"{owner}\", \
                 which does not exist and is not created by this plan"
            ),
            AuthorityIssue::PredefinedRoleGrant { role, executor } => write!(
                f,
                "UnsatisfiableMembershipChange: cannot GRANT/REVOKE predefined role \
                 \"{role}\" as executor \"{executor}\"; requires ADMIN OPTION on it — \
                 in PostgreSQL 16+ that means a superuser executor or an explicit \
                 GRANT \"{role}\" TO \"{executor}\" WITH ADMIN OPTION (CREATEROLE is \
                 not sufficient)"
            ),
            AuthorityIssue::MissingPredefinedRole {
                role,
                server_major,
                min_version,
            } => {
                write!(
                    f,
                    "MissingPredefinedRole: manifest declares membership in \"{role}\", \
                     which does not exist on this server (PostgreSQL {server_major})"
                )?;
                if let Some(min_version) = min_version {
                    write!(f, "; it was added in PostgreSQL {min_version}")?;
                }
                Ok(())
            }
            AuthorityIssue::PublicRevoke {
                object_type,
                schema,
                executor,
                skipped_count,
                examples,
            } => {
                let examples = examples
                    .iter()
                    .map(|(name, owner)| format!("\"{name}\" (owner \"{owner}\")"))
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(
                    f,
                    "UnsatisfiableRevoke: cannot revoke PUBLIC privileges on {object_type} \
                     objects{} as executor \"{executor}\"; {skipped_count} object(s) have \
                     owners the executor cannot act as, so the REVOKE would silently \
                     change nothing",
                    match schema {
                        Some(schema) => format!(" in schema \"{schema}\""),
                        None => String::new(),
                    },
                )?;
                if !examples.is_empty() {
                    write!(f, " (examples: {examples})")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ObjectAuthorityRow {
    schema_name: Option<String>,
    object_name: String,
    owner_name: String,
    can_act: bool,
}

/// Check executor authority for the planned changes.
///
/// `current` supplies the per-object PUBLIC state so the ownership check
/// covers exactly the objects an `ON ALL` revoke would have to touch, not
/// every object in the schema.
pub async fn preflight_authority_issues(
    pool: &PgPool,
    changes: &[Change],
    current: &RoleGraph,
) -> Result<Vec<AuthorityIssue>, sqlx::Error> {
    let mut issues = Vec::new();

    let (executor, executor_is_superuser) = {
        let (user, is_superuser): (String, bool) = sqlx::query_as(
            "SELECT r.rolname::text, r.rolsuper FROM pg_roles r WHERE r.rolname = current_user",
        )
        .fetch_one(pool)
        .await?;
        (user, is_superuser)
    };

    // --- Predefined-role membership authority ---
    // Granting or revoking membership in a predefined (`pg_*`) role requires
    // ADMIN OPTION on it. `pg_has_role(..., 'MEMBER WITH ADMIN OPTION')`
    // reports true for superusers, so this is exactly the authority the
    // GRANT/REVOKE needs. A referenced predefined role the server does not
    // have at all is reported with the version that introduced it.
    let predefined_targets: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::AddMember { role, .. } | Change::RemoveMember { role, .. }
                if is_predefined_role(role) =>
            {
                Some(role.clone())
            }
            _ => None,
        })
        .collect();
    if !predefined_targets.is_empty() {
        let target_list: Vec<String> = predefined_targets.iter().cloned().collect();
        let rows: Vec<(String, bool)> = sqlx::query_as(
            r#"
            SELECT r.rolname::text, pg_has_role(current_user, r.oid, 'MEMBER WITH ADMIN OPTION')
            FROM pg_roles r
            WHERE r.rolname = ANY($1)
            "#,
        )
        .bind(&target_list)
        .fetch_all(pool)
        .await?;
        let known: BTreeSet<String> = rows.iter().map(|(role, _)| role.clone()).collect();
        for (role, can_admin) in rows {
            if !can_admin {
                issues.push(AuthorityIssue::PredefinedRoleGrant {
                    role,
                    executor: executor.clone(),
                });
            }
        }
        let missing: Vec<&String> = predefined_targets
            .iter()
            .filter(|role| !known.contains(role.as_str()))
            .collect();
        if !missing.is_empty() {
            let (server_version_num,): (i32,) =
                sqlx::query_as("SELECT current_setting('server_version_num')::int")
                    .fetch_one(pool)
                    .await?;
            let server_major = (server_version_num / 10_000) as u32;
            for role in missing {
                issues.push(AuthorityIssue::MissingPredefinedRole {
                    role: role.clone(),
                    server_major,
                    min_version: predefined_role_min_version(role),
                });
            }
        }
    }

    // --- Default-privilege owner authority ---
    let owners: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::SetDefaultPrivilege { owner, .. }
            | Change::RevokeDefaultPrivilege { owner, .. } => Some(owner.clone()),
            _ => None,
        })
        .collect();
    if !owners.is_empty() {
        let owner_list: Vec<String> = owners.iter().cloned().collect();
        let rows: Vec<(String, bool)> = sqlx::query_as(
            r#"
            SELECT r.rolname::text, pg_has_role(current_user, r.oid, 'USAGE')
            FROM pg_roles r
            WHERE r.rolname = ANY($1)
            "#,
        )
        .bind(&owner_list)
        .fetch_all(pool)
        .await?;
        let known: BTreeSet<String> = rows.iter().map(|(owner, _)| owner.clone()).collect();
        for (owner, can_act) in rows {
            if !can_act {
                issues.push(AuthorityIssue::DefaultPrivilegeOwner {
                    owner,
                    executor: executor.clone(),
                });
            }
        }
        // A non-superuser cannot act as a role merely because the same plan
        // creates it. PostgreSQL's automatic CREATEROLE administration grant
        // does not provide the USAGE authority ALTER DEFAULT PRIVILEGES
        // requires. Reject before the transaction starts; superusers can
        // safely create the owner and alter its defaults atomically.
        let created: BTreeSet<&str> = changes
            .iter()
            .filter_map(|change| match change {
                Change::CreateRole { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        for owner in &owners {
            if known.contains(owner) {
                continue;
            }
            if created.contains(owner.as_str()) && !executor_is_superuser {
                issues.push(AuthorityIssue::DefaultPrivilegeOwner {
                    owner: owner.clone(),
                    executor: executor.clone(),
                });
            } else if !created.contains(owner.as_str()) {
                issues.push(AuthorityIssue::MissingDefaultPrivilegeOwner {
                    owner: owner.clone(),
                });
            }
        }
    }

    // --- PUBLIC revoke ownership ---
    // Collect the objects each planned PUBLIC revoke touches, grouped per
    // (object_type, schema). `AllInSchema` means every object of that type,
    // which is what an `ON ALL` statement actually reaches.
    #[derive(Default)]
    struct RevokeTargets {
        names: BTreeSet<String>,
        all_in_schema: bool,
    }

    let mut targets: BTreeMap<(ObjectType, Option<String>), RevokeTargets> = BTreeMap::new();
    for change in changes {
        let Change::Revoke {
            role: Grantee::Public,
            object_type,
            schema,
            name,
            ..
        } = change
        else {
            continue;
        };
        let entry = targets.entry((*object_type, schema.clone())).or_default();
        match name.as_deref() {
            Some("*") => {
                let range_start = GrantKey {
                    role: Grantee::Public,
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: None,
                };
                for (key, _) in current.grants.range(range_start..).take_while(|(key, _)| {
                    key.role == Grantee::Public
                        && key.object_type == *object_type
                        && key.schema == *schema
                }) {
                    match key.name.as_deref() {
                        // Wildcard normalization collapses per-object PUBLIC
                        // rows into one `"*"` key when the same scope also has
                        // a present wildcard. Narrowing to the remaining
                        // per-object names would then check nothing, so treat
                        // the collapsed key as covering the whole scope.
                        Some("*") => entry.all_in_schema = true,
                        Some(object_name) => {
                            entry.names.insert(object_name.to_string());
                        }
                        None => {}
                    }
                }
            }
            Some(object_name) => {
                entry.names.insert(object_name.to_string());
            }
            None => {}
        }
    }

    for ((object_type, schema), target) in targets {
        if target.names.is_empty() && !target.all_in_schema {
            continue;
        }
        let rows =
            fetch_object_authority(pool, object_type, schema.as_deref(), &target.names).await?;
        let mut blocked: Vec<(String, String)> = rows
            .into_iter()
            .filter(|row| {
                !row.can_act
                    && row.schema_name.as_deref() == schema.as_deref()
                    && (target.all_in_schema || target.names.contains(&row.object_name))
            })
            .map(|row| (row.object_name, row.owner_name))
            .collect();
        if blocked.is_empty() {
            continue;
        }
        blocked.sort();
        issues.push(AuthorityIssue::PublicRevoke {
            object_type,
            schema,
            executor: executor.clone(),
            skipped_count: blocked.len(),
            examples: blocked.into_iter().take(REVOKE_EXAMPLE_LIMIT).collect(),
        });
    }

    Ok(issues)
}

async fn fetch_object_authority(
    pool: &PgPool,
    object_type: ObjectType,
    schema: Option<&str>,
    names: &BTreeSet<String>,
) -> Result<Vec<ObjectAuthorityRow>, sqlx::Error> {
    let schemas: Vec<String> = schema.map(|s| vec![s.to_string()]).unwrap_or_default();
    let names: Vec<String> = names.iter().cloned().collect();
    match object_type {
        ObjectType::Table
        | ObjectType::View
        | ObjectType::MaterializedView
        | ObjectType::Sequence => {
            // Only the relkinds this object type actually names. Selecting
            // every relation would report objects the planned statement cannot
            // reach, and a wildcard target accepts them all.
            let relkinds: Vec<String> = match object_type {
                ObjectType::Table => vec!["r".to_string(), "p".to_string()],
                ObjectType::View => vec!["v".to_string()],
                ObjectType::MaterializedView => vec!["m".to_string()],
                _ => vec!["S".to_string()],
            };
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    n.nspname::text AS schema_name,
                    c.relname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, c.relowner, 'USAGE') AS can_act
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_roles o ON o.oid = c.relowner
                WHERE n.nspname = ANY($1)
                  AND c.relkind::text = ANY($2)
                "#,
            )
            .bind(&schemas)
            .bind(&relkinds)
            .fetch_all(pool)
            .await
        }
        ObjectType::Function => {
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    n.nspname::text AS schema_name,
                    (p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')')::text
                        AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, p.proowner, 'USAGE') AS can_act
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                JOIN pg_roles o ON o.oid = p.proowner
                WHERE n.nspname = ANY($1)
                "#,
            )
            .bind(&schemas)
            .fetch_all(pool)
            .await
        }
        ObjectType::Type => {
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    n.nspname::text AS schema_name,
                    t.typname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, t.typowner, 'USAGE') AS can_act
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                JOIN pg_roles o ON o.oid = t.typowner
                WHERE n.nspname = ANY($1)
                  -- Only user-facing types. Every table carries a composite
                  -- type, and every type carries an array type; neither is
                  -- something a revoke can name.
                  AND (
                    t.typrelid = 0
                    OR (SELECT c.relkind FROM pg_class c WHERE c.oid = t.typrelid) = 'c'
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM pg_type el
                    WHERE el.oid = t.typelem AND el.typarray = t.oid
                  )
                "#,
            )
            .bind(&schemas)
            .fetch_all(pool)
            .await
        }
        ObjectType::Schema => {
            // Schema targets carry the schema in `name`, so `names` holds the
            // schema names and `schemas` is empty. Match against `nspname`.
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    NULL::text AS schema_name,
                    n.nspname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, n.nspowner, 'USAGE') AS can_act
                FROM pg_namespace n
                JOIN pg_roles o ON o.oid = n.nspowner
                WHERE n.nspname = ANY($1)
                "#,
            )
            .bind(&names)
            .fetch_all(pool)
            .await
        }
        ObjectType::Database => {
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    NULL::text AS schema_name,
                    db.datname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, db.datdba, 'USAGE') AS can_act
                FROM pg_database db
                JOIN pg_roles o ON o.oid = db.datdba
                WHERE db.datname = current_database()
                "#,
            )
            .fetch_all(pool)
            .await
        }
    }
}
