//! Executor-authority preflight for planned changes.
//!
//! Two failure modes are caught before apply:
//!
//! `ALTER DEFAULT PRIVILEGES FOR ROLE owner` requires the executor to be a
//! member of the owner role (or a superuser). Without that, apply fails
//! mid-transaction with a permission error, so the check only moves the
//! failure earlier and names the owner.
//!
//! `REVOKE` can be worse than a loud failure: PostgreSQL removes only ACL
//! entries whose grantor the executor can act as, and a REVOKE matching no
//! entry silently removes nothing — the next inspection still sees the
//! privilege, and the controller re-plans the same revoke forever.
//!
//! For `REVOKE ... FROM PUBLIC`, implicit PUBLIC grants are always
//! grantor-owned, so membership in the object owner (which `pg_has_role`
//! reports true for superusers too) is exactly the authority the revoke
//! needs. For ordinary role grantees an owner-membership test would be both
//! too strict (an executor can hold revoke authority via its own grant
//! option) and too loose (owner membership cannot remove an entry a delegate
//! granted onward), so those are checked per ACL entry instead: an entry for
//! the revoked grantee whose *grantor* the executor cannot act as survives
//! the revoke under any grantor selection, and is reported. Entries whose
//! grantor is reachable are trusted to the apply; the operator's post-apply
//! non-convergence detection catches the residue (grantor-selection
//! shadowing) that no preflight can prove.

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

    /// A planned `REVOKE ... FROM <role>` targets ACL entries granted by
    /// grantors the executor cannot act as. PostgreSQL removes only entries
    /// whose grantor the executor can act as, and a REVOKE matching none of
    /// them succeeds silently — no error, no warning — so these entries would
    /// survive and the same drift would re-plan on every run.
    ///
    /// This is the ordinary-grantee sibling of [`AuthorityIssue::PublicRevoke`]
    /// and checks the sharper grantor-level condition: acting as the object's
    /// *owner* is not enough to remove an entry a delegate granted onward via
    /// `WITH GRANT OPTION`. The converse gap remains: an entry whose grantor
    /// *is* actable can still survive when PostgreSQL's grantor selection
    /// prefers another path (e.g. the executor's own grant option shadowing
    /// the owner's), which only the post-apply non-convergence detection
    /// catches.
    ForeignGrantorRevoke {
        object_type: ObjectType,
        schema: Option<String>,
        grantee: String,
        executor: String,
        skipped_count: usize,
        /// Up to [`REVOKE_EXAMPLE_LIMIT`] surviving entries as
        /// `(object name, grantor)`.
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
                 use a superuser executor or an explicit \
                 GRANT \"{role}\" TO \"{executor}\" WITH ADMIN OPTION (since \
                 PostgreSQL 16, CREATEROLE alone is not sufficient)"
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
            AuthorityIssue::ForeignGrantorRevoke {
                object_type,
                schema,
                grantee,
                executor,
                skipped_count,
                examples,
            } => {
                let examples = examples
                    .iter()
                    .map(|(name, grantor)| format!("\"{name}\" (grantor \"{grantor}\")"))
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(
                    f,
                    "UnsatisfiableRevoke: cannot revoke \"{grantee}\" privileges on \
                     {object_type} objects{} as executor \"{executor}\"; {skipped_count} ACL \
                     entr{} granted by grantors the executor cannot act as, so the REVOKE \
                     would succeed while silently leaving them in place — revoke the \
                     delegating grant option (with CASCADE) or run as a role that can act \
                     as the grantor",
                    match schema {
                        Some(schema) => format!(" in schema \"{schema}\""),
                        None => String::new(),
                    },
                    if *skipped_count == 1 {
                        "y was"
                    } else {
                        "ies were"
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

    let (executor, executor_is_superuser, executor_has_createrole) = {
        let (user, is_superuser, has_createrole): (String, bool, bool) = sqlx::query_as(
            "SELECT r.rolname::text, r.rolsuper, r.rolcreaterole \
             FROM pg_roles r WHERE r.rolname = current_user",
        )
        .fetch_one(pool)
        .await?;
        (user, is_superuser, has_createrole)
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
        let (server_version_num,): (i32,) =
            sqlx::query_as("SELECT current_setting('server_version_num')::int")
                .fetch_one(pool)
                .await?;
        let server_major = (server_version_num / 10_000) as u32;

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
        // Before PostgreSQL 16, CREATEROLE alone allowed granting and
        // revoking any non-superuser role, predefined roles included — the
        // ADMIN OPTION requirement is the PG16 semantics change. Requiring it
        // unconditionally would hard-block executors that work fine on 14/15.
        let admin_required = server_major >= 16;
        for (role, can_admin) in rows {
            if !can_admin && (admin_required || !(executor_is_superuser || executor_has_createrole))
            {
                issues.push(AuthorityIssue::PredefinedRoleGrant {
                    role,
                    executor: executor.clone(),
                });
            }
        }
        for role in predefined_targets
            .iter()
            .filter(|role| !known.contains(role.as_str()))
        {
            issues.push(AuthorityIssue::MissingPredefinedRole {
                role: role.clone(),
                server_major,
                min_version: predefined_role_min_version(role),
            });
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

    // --- Ordinary-grantee revoke grantor authority ---
    // The PUBLIC check above asks "can the executor act as the owner?", which
    // approximates the entries an owner made. For ordinary grantees the
    // sharper question is per ACL entry: PostgreSQL's REVOKE removes only
    // entries whose *grantor* the executor can act as, and one matching no
    // entry succeeds silently. An entry a delegate granted onward via
    // `WITH GRANT OPTION` therefore survives even an owner-acting executor's
    // revoke, and the same drift re-plans on every run. Explode the live ACLs
    // of the targeted objects and flag entries for the revoked grantee and
    // privileges whose grantor is out of the executor's reach.
    let mut grantee_targets: BTreeMap<(ObjectType, Option<String>, String), GranteeRevokeTargets> =
        BTreeMap::new();
    for change in changes {
        let Change::Revoke {
            role: Grantee::Role(grantee),
            object_type,
            schema,
            name,
            privileges,
        } = change
        else {
            continue;
        };
        let entry = grantee_targets
            .entry((*object_type, schema.clone(), grantee.clone()))
            .or_default();
        entry
            .privileges
            .extend(privileges.iter().map(|privilege| privilege.to_string()));
        match name.as_deref() {
            Some("*") => {
                let range_start = GrantKey {
                    role: Grantee::Role(grantee.clone()),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: None,
                };
                for (key, _) in current.grants.range(range_start..).take_while(|(key, _)| {
                    key.role == Grantee::Role(grantee.clone())
                        && key.object_type == *object_type
                        && key.schema == *schema
                }) {
                    match key.name.as_deref() {
                        // Same wildcard normalization as the PUBLIC check: a
                        // collapsed `"*"` key covers the whole scope.
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

    for ((object_type, schema, grantee), target) in grantee_targets {
        if target.names.is_empty() && !target.all_in_schema {
            continue;
        }
        let privileges: Vec<String> = target.privileges.iter().cloned().collect();
        let rows = fetch_revoke_grantor_authority(
            pool,
            object_type,
            schema.as_deref(),
            &target.names,
            &grantee,
            &privileges,
        )
        .await?;
        let mut surviving: BTreeSet<(String, String)> = rows
            .into_iter()
            .filter(|row| {
                !row.can_act
                    && row.schema_name.as_deref() == schema.as_deref()
                    && (target.all_in_schema || target.names.contains(&row.object_name))
            })
            .map(|row| (row.object_name, row.grantor_name))
            .collect();
        if surviving.is_empty() {
            continue;
        }
        let skipped_count = surviving.len();
        let examples: Vec<(String, String)> = std::mem::take(&mut surviving)
            .into_iter()
            .take(REVOKE_EXAMPLE_LIMIT)
            .collect();
        issues.push(AuthorityIssue::ForeignGrantorRevoke {
            object_type,
            schema,
            grantee,
            executor: executor.clone(),
            skipped_count,
            examples,
        });
    }

    Ok(issues)
}

/// Objects one planned `(object_type, schema, grantee)` revoke group reaches,
/// plus the union of privilege names being revoked across those objects.
#[derive(Default)]
struct GranteeRevokeTargets {
    names: BTreeSet<String>,
    all_in_schema: bool,
    privileges: BTreeSet<String>,
}

/// A live ACL entry for a revoked grantee: which object carries it, who
/// granted it, and whether the executor can act as that grantor.
#[derive(Debug, sqlx::FromRow)]
struct GrantorAuthorityRow {
    schema_name: Option<String>,
    object_name: String,
    grantor_name: String,
    can_act: bool,
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

/// Fetch the live ACL entries a planned `REVOKE ... FROM <grantee>` group
/// would have to remove, with per-entry grantor actability.
///
/// One query per catalog family, each exploding the object's ACL column and
/// keeping entries for the named grantee and privilege types. `can_act` is
/// `pg_has_role(current_user, grantor, 'USAGE')` — the membership check
/// PostgreSQL's own grantor resolution walks — so a `false` row is an entry
/// the executor's REVOKE cannot remove under any grantor selection.
async fn fetch_revoke_grantor_authority(
    pool: &PgPool,
    object_type: ObjectType,
    schema: Option<&str>,
    names: &BTreeSet<String>,
    grantee: &str,
    privileges: &[String],
) -> Result<Vec<GrantorAuthorityRow>, sqlx::Error> {
    let schemas: Vec<String> = schema.map(|s| vec![s.to_string()]).unwrap_or_default();
    let names: Vec<String> = names.iter().cloned().collect();
    match object_type {
        ObjectType::Table
        | ObjectType::View
        | ObjectType::MaterializedView
        | ObjectType::Sequence => {
            let relkinds: Vec<String> = match object_type {
                ObjectType::Table => vec!["r".to_string(), "p".to_string()],
                ObjectType::View => vec!["v".to_string()],
                ObjectType::MaterializedView => vec!["m".to_string()],
                _ => vec!["S".to_string()],
            };
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    n.nspname::text AS schema_name,
                    c.relname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    pg_has_role(current_user, acl.grantor, 'USAGE') AS can_act
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND c.relkind::text = ANY($2)
                  AND ge.rolname = $3
                  AND acl.privilege_type = ANY($4)
                "#,
            )
            .bind(&schemas)
            .bind(&relkinds)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Function => {
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    n.nspname::text AS schema_name,
                    (p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')')::text
                        AS object_name,
                    gr.rolname::text AS grantor_name,
                    pg_has_role(current_user, acl.grantor, 'USAGE') AS can_act
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                CROSS JOIN LATERAL aclexplode(p.proacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND ge.rolname = $2
                  AND acl.privilege_type = ANY($3)
                "#,
            )
            .bind(&schemas)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Type => {
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    n.nspname::text AS schema_name,
                    t.typname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    pg_has_role(current_user, acl.grantor, 'USAGE') AS can_act
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                CROSS JOIN LATERAL aclexplode(t.typacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND ge.rolname = $2
                  AND acl.privilege_type = ANY($3)
                "#,
            )
            .bind(&schemas)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Schema => {
            // Schema targets carry the schema in `name`, so `names` holds the
            // schema names and the returned schema_name is NULL (matching how
            // the revoke change itself is keyed).
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    NULL::text AS schema_name,
                    n.nspname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    pg_has_role(current_user, acl.grantor, 'USAGE') AS can_act
                FROM pg_namespace n
                CROSS JOIN LATERAL aclexplode(n.nspacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND ge.rolname = $2
                  AND acl.privilege_type = ANY($3)
                "#,
            )
            .bind(&names)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Database => {
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    NULL::text AS schema_name,
                    db.datname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    pg_has_role(current_user, acl.grantor, 'USAGE') AS can_act
                FROM pg_database db
                CROSS JOIN LATERAL aclexplode(db.datacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE db.datname = current_database()
                  AND ge.rolname = $1
                  AND acl.privilege_type = ANY($2)
                "#,
            )
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
    }
}
