//! Query object privileges from PostgreSQL catalog tables.
//!
//! Uses `aclexplode()` to decompose explicit ACL arrays from `pg_class`,
//! `pg_namespace`, `pg_proc`, `pg_type`, and `pg_database`.
//!
//! Managed-state inspection intentionally does not synthesize owner/default ACLs
//! from `acldefault(...)`. Doing so would make implicit owner privileges appear
//! as explicit managed grants, causing drift where the manifest never declared
//! those self-grants. PUBLIC/default visibility is handled separately by the
//! `public_grants` module for informational output.
//!
//! The privilege character mapping:
//!   r = SELECT, a = INSERT, w = UPDATE, d = DELETE, D = TRUNCATE,
//!   x = REFERENCES, t = TRIGGER, X = EXECUTE, U = USAGE, C = CREATE,
//!   c = CONNECT, T = TEMPORARY

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;

use crate::{
    UnsatisfiableWildcardGrant, UnsatisfiableWildcardObject, WildcardGrantPattern,
    WildcardInspectionStats,
};
use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::{GrantKey, GrantState};

/// A raw ACL row returned by our `aclexplode()` queries.
#[derive(Debug, sqlx::FromRow)]
struct AclRow {
    /// The grantee role name. NULL means PUBLIC — we skip those.
    grantee: Option<String>,
    /// The privilege type as a single character (e.g. 'r' for SELECT).
    privilege_type: String,
    /// The schema name (NULL for database-level grants).
    schema_name: Option<String>,
    /// The object name (the schema name itself for schema-level grants).
    object_name: String,
    /// The object type discriminator we embed in the query.
    obj_type: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct GrantabilityRow {
    schema_name: String,
    object_name: String,
    owner_name: String,
    obj_type: String,
    can_select: bool,
    can_insert: bool,
    can_update: bool,
    can_delete: bool,
    can_truncate: bool,
    can_references: bool,
    can_trigger: bool,
    can_execute: bool,
    can_usage: bool,
}

pub(crate) struct PrivilegeInspectionResult {
    pub grants: BTreeMap<GrantKey, GrantState>,
    pub diagnostics: Vec<UnsatisfiableWildcardGrant>,
    pub wildcard_stats: WildcardInspectionStats,
}

struct WildcardScopeFilter {
    schema_names: Vec<String>,
    object_types: Vec<String>,
    need_select: Vec<bool>,
    need_insert: Vec<bool>,
    need_update: Vec<bool>,
    need_delete: Vec<bool>,
    need_truncate: Vec<bool>,
    need_references: Vec<bool>,
    need_trigger: Vec<bool>,
    need_execute: Vec<bool>,
    need_usage: Vec<bool>,
}

impl WildcardScopeFilter {
    fn from_wildcards(wildcard_grants: &[WildcardGrantPattern]) -> Self {
        let mut scopes: BTreeMap<(ObjectType, String), BTreeSet<Privilege>> = BTreeMap::new();

        for wildcard in wildcard_grants {
            if matches!(
                wildcard.object_type,
                ObjectType::Schema | ObjectType::Database
            ) {
                continue;
            }

            scopes
                .entry((wildcard.object_type, wildcard.schema.clone()))
                .or_default()
                .extend(wildcard.privileges.iter().copied());
        }

        let mut filter = Self {
            schema_names: Vec::with_capacity(scopes.len()),
            object_types: Vec::with_capacity(scopes.len()),
            need_select: Vec::with_capacity(scopes.len()),
            need_insert: Vec::with_capacity(scopes.len()),
            need_update: Vec::with_capacity(scopes.len()),
            need_delete: Vec::with_capacity(scopes.len()),
            need_truncate: Vec::with_capacity(scopes.len()),
            need_references: Vec::with_capacity(scopes.len()),
            need_trigger: Vec::with_capacity(scopes.len()),
            need_execute: Vec::with_capacity(scopes.len()),
            need_usage: Vec::with_capacity(scopes.len()),
        };

        for ((object_type, schema), privileges) in scopes {
            filter.schema_names.push(schema);
            filter
                .object_types
                .push(object_type_label(object_type).to_string());
            filter
                .need_select
                .push(privileges.contains(&Privilege::Select));
            filter
                .need_insert
                .push(privileges.contains(&Privilege::Insert));
            filter
                .need_update
                .push(privileges.contains(&Privilege::Update));
            filter
                .need_delete
                .push(privileges.contains(&Privilege::Delete));
            filter
                .need_truncate
                .push(privileges.contains(&Privilege::Truncate));
            filter
                .need_references
                .push(privileges.contains(&Privilege::References));
            filter
                .need_trigger
                .push(privileges.contains(&Privilege::Trigger));
            filter
                .need_execute
                .push(privileges.contains(&Privilege::Execute));
            filter
                .need_usage
                .push(privileges.contains(&Privilege::Usage));
        }

        filter
    }

    fn is_empty(&self) -> bool {
        self.schema_names.is_empty()
    }

    fn len(&self) -> usize {
        self.schema_names.len()
    }

    fn unique_schemas(&self) -> Vec<String> {
        self.schema_names
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn contains(&self, object_type: ObjectType, schema_name: &str) -> bool {
        self.schema_names
            .iter()
            .zip(&self.object_types)
            .any(|(schema, obj_type)| {
                schema == schema_name && obj_type == object_type_label(object_type)
            })
    }
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

/// Map our query's `obj_type` discriminator string to an `ObjectType`.
fn obj_type_str_to_object_type(obj_type: &str) -> Option<ObjectType> {
    match obj_type {
        "table" => Some(ObjectType::Table),
        "view" => Some(ObjectType::View),
        "materialized_view" => Some(ObjectType::MaterializedView),
        "sequence" => Some(ObjectType::Sequence),
        "function" => Some(ObjectType::Function),
        "schema" => Some(ObjectType::Schema),
        "database" => Some(ObjectType::Database),
        "type" => Some(ObjectType::Type),
        _ => None,
    }
}

fn object_type_label(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Table => "table",
        ObjectType::View => "view",
        ObjectType::MaterializedView => "materialized_view",
        ObjectType::Sequence => "sequence",
        ObjectType::Function => "function",
        ObjectType::Schema => "schema",
        ObjectType::Database => "database",
        ObjectType::Type => "type",
    }
}

/// Fetch all object privileges from the database for the given schemas and roles.
///
/// Queries tables/views/sequences via `pg_class`, schemas via `pg_namespace`,
/// functions via `pg_proc`, types via `pg_type`, and (optionally) databases via
/// `pg_database`.
///
/// Returns a map of `GrantKey → GrantState` ready for insertion into a `RoleGraph`.
pub async fn fetch_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<BTreeMap<GrantKey, GrantState>, sqlx::Error> {
    Ok(
        fetch_privileges_with_wildcards(pool, managed_schemas, managed_roles, &[])
            .await?
            .grants,
    )
}

/// Fetch schema-scoped object names grouped by object type.
pub async fn fetch_object_inventory(
    pool: &PgPool,
    managed_schemas: &[&str],
) -> Result<BTreeMap<(ObjectType, String), Vec<String>>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname AS object_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
            END AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY($1)
          AND c.relkind IN ('r', 'p', 'v', 'm')

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname AS object_name,
            'sequence' AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY($1)
          AND c.relkind = 'S'

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            'function' AS obj_type
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = ANY($1)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            t.typname AS object_name,
            'type' AS obj_type
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = ANY($1)
          AND t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'

        ORDER BY schema_name, obj_type, object_name
        "#,
    )
    .bind(managed_schemas)
    .fetch_all(pool)
    .await?;

    let mut inventory = BTreeMap::new();
    for row in rows {
        let Some(object_type) = obj_type_str_to_object_type(&row.obj_type) else {
            continue;
        };
        inventory
            .entry((
                object_type,
                row.schema_name
                    .expect("relation inventory rows always include schema"),
            ))
            .or_insert_with(Vec::new)
            .push(row.object_name);
    }
    Ok(inventory)
}

async fn fetch_object_inventory_for_wildcards(
    pool: &PgPool,
    filter: &WildcardScopeFilter,
) -> Result<BTreeMap<(ObjectType, String), Vec<String>>, sqlx::Error> {
    if filter.is_empty() {
        return Ok(BTreeMap::new());
    }
    let wildcard_schemas = filter.unique_schemas();

    let rows = sqlx::query_as::<_, AclRow>(
        r#"
        WITH wildcard_scope(
            schema_name,
            obj_type,
            need_select,
            need_insert,
            need_update,
            need_delete,
            need_truncate,
            need_references,
            need_trigger,
            need_execute,
            need_usage
        ) AS (
            SELECT *
            FROM unnest(
                $1::text[],
                $2::text[],
                $3::bool[],
                $4::bool[],
                $5::bool[],
                $6::bool[],
                $7::bool[],
                $8::bool[],
                $9::bool[],
                $10::bool[],
                $11::bool[]
            )
        )
        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname AS object_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
            END AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
             END
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname AS object_name,
            'sequence' AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'sequence'
        WHERE c.relkind = 'S'
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            'function' AS obj_type
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'function'
        WHERE n.nspname = ANY($12)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            t.typname AS object_name,
            'type' AS obj_type
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'type'
        WHERE t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'
          AND n.nspname = ANY($12)

        ORDER BY schema_name, obj_type, object_name
        "#,
    )
    .bind(&filter.schema_names)
    .bind(&filter.object_types)
    .bind(&filter.need_select)
    .bind(&filter.need_insert)
    .bind(&filter.need_update)
    .bind(&filter.need_delete)
    .bind(&filter.need_truncate)
    .bind(&filter.need_references)
    .bind(&filter.need_trigger)
    .bind(&filter.need_execute)
    .bind(&filter.need_usage)
    .bind(&wildcard_schemas)
    .fetch_all(pool)
    .await?;

    let mut inventory = BTreeMap::new();
    for row in rows {
        let Some(object_type) = obj_type_str_to_object_type(&row.obj_type) else {
            continue;
        };
        inventory
            .entry((
                object_type,
                row.schema_name
                    .expect("relation inventory rows always include schema"),
            ))
            .or_insert_with(Vec::new)
            .push(row.object_name);
    }
    Ok(inventory)
}

/// Fetch only relation names (tables, views, materialized views) for callers
/// that specifically need relation inventory.
pub async fn fetch_relation_inventory(
    pool: &PgPool,
    managed_schemas: &[&str],
) -> Result<BTreeMap<(ObjectType, String), Vec<String>>, sqlx::Error> {
    Ok(fetch_object_inventory(pool, managed_schemas)
        .await?
        .into_iter()
        .filter(|((object_type, _), _)| {
            matches!(
                object_type,
                ObjectType::Table | ObjectType::View | ObjectType::MaterializedView
            )
        })
        .collect())
}

pub(crate) async fn fetch_privileges_with_wildcards(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
    wildcard_grants: &[WildcardGrantPattern],
) -> Result<PrivilegeInspectionResult, sqlx::Error> {
    let mut grants: BTreeMap<GrantKey, GrantState> = BTreeMap::new();
    let has_wildcards = !wildcard_grants.is_empty();
    let wildcard_scope_filter = WildcardScopeFilter::from_wildcards(wildcard_grants);
    let mut wildcard_stats = WildcardInspectionStats {
        configured_grants: wildcard_grants.len(),
        configured_scopes: wildcard_scope_filter.len(),
        ..WildcardInspectionStats::default()
    };
    let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();

    if has_wildcards {
        for ((object_type, schema_name), object_names) in
            fetch_object_inventory_for_wildcards(pool, &wildcard_scope_filter).await?
        {
            inventory.insert(
                (object_type, schema_name),
                object_names.into_iter().collect(),
            );
        }
    }
    // Run all the independent queries and collect results.
    // We use separate queries per object type rather than one giant UNION
    // because the NULL-ACL handling (acldefault) differs per type.

    let relation_rows = fetch_relation_privileges(pool, managed_schemas, managed_roles).await?;
    let schema_rows = fetch_schema_privileges(pool, managed_schemas, managed_roles).await?;
    let function_rows = fetch_function_privileges(pool, managed_schemas, managed_roles).await?;
    let type_rows = fetch_type_privileges(pool, managed_schemas, managed_roles).await?;

    let all_rows: Vec<AclRow> = relation_rows
        .into_iter()
        .chain(schema_rows)
        .chain(function_rows)
        .chain(type_rows)
        .collect();

    for row in &all_rows {
        if has_wildcards
            && let Some(object_type) = obj_type_str_to_object_type(&row.obj_type)
            && !matches!(object_type, ObjectType::Schema | ObjectType::Database)
            && let Some(schema_name) = &row.schema_name
            && wildcard_scope_filter.contains(object_type, schema_name)
        {
            inventory
                .entry((object_type, schema_name.clone()))
                .or_default()
                .insert(row.object_name.clone());
        }
    }
    wildcard_stats.inventory_objects = inventory.values().map(BTreeSet::len).sum();

    for row in all_rows {
        // Skip PUBLIC grantee (NULL)
        let grantee = match row.grantee {
            Some(ref name) => name,
            None => continue,
        };

        // Skip if the grantee isn't in the managed set
        if !managed_roles.contains(&grantee.as_str()) {
            continue;
        }

        let privilege = match acl_char_to_privilege(&row.privilege_type) {
            Some(privilege) => privilege,
            None => continue,
        };

        let object_type = match obj_type_str_to_object_type(&row.obj_type) {
            Some(object_type) => object_type,
            None => continue,
        };

        // Build the GrantKey.
        // Schema-level grants: object_type=Schema, schema=None, name=Some(schema_name)
        // Database-level grants: object_type=Database, schema=None, name=Some(db_name)
        // Other: object_type, schema=Some(schema_name), name=Some(object_name)
        let (schema, name) = match object_type {
            ObjectType::Schema => (None, Some(row.object_name.clone())),
            ObjectType::Database => (None, Some(row.object_name.clone())),
            _ => (row.schema_name.clone(), Some(row.object_name.clone())),
        };

        let key = GrantKey {
            role: grantee.clone(),
            object_type,
            schema,
            name,
        };

        let entry = grants.entry(key).or_insert_with(|| GrantState {
            privileges: BTreeSet::new(),
        });
        entry.privileges.insert(privilege);
    }

    let unsatisfied_wildcards = if has_wildcards {
        unsatisfied_wildcard_grants(&grants, &inventory, wildcard_grants)
    } else {
        Vec::new()
    };
    wildcard_stats.unsatisfied_grants = unsatisfied_wildcards.len();

    let diagnostics = if unsatisfied_wildcards.is_empty() {
        Vec::new()
    } else {
        let executor = fetch_current_user(pool).await?;
        let grantability_filter = WildcardScopeFilter::from_wildcards(&unsatisfied_wildcards);
        wildcard_stats.unsatisfied_scopes = grantability_filter.len();
        let grantability = fetch_wildcard_grantability(pool, &grantability_filter).await?;
        wildcard_stats.grantability_queries = 1;
        wildcard_stats.grantability_objects = grantability.len();
        detect_unsatisfiable_wildcards(&grants, &grantability, &unsatisfied_wildcards, &executor)
    };

    let grants = if has_wildcards {
        normalize_wildcard_grants(grants, &inventory, wildcard_grants)
    } else {
        grants
    };

    Ok(PrivilegeInspectionResult {
        grants,
        diagnostics,
        wildcard_stats,
    })
}

async fn fetch_current_user(pool: &PgPool) -> Result<String, sqlx::Error> {
    let (user,) = sqlx::query_as::<_, (String,)>("SELECT current_user::text")
        .fetch_one(pool)
        .await?;
    Ok(user)
}

fn unsatisfied_wildcard_grants(
    grants: &BTreeMap<GrantKey, GrantState>,
    inventory: &BTreeMap<(ObjectType, String), BTreeSet<String>>,
    wildcard_grants: &[WildcardGrantPattern],
) -> Vec<WildcardGrantPattern> {
    let mut unsatisfied = Vec::new();

    for wildcard in wildcard_grants {
        let Some(object_names) = inventory.get(&(wildcard.object_type, wildcard.schema.clone()))
        else {
            continue;
        };

        if object_names.is_empty() {
            continue;
        }

        let mut missing_privileges = BTreeSet::new();
        for object_name in object_names {
            let key = GrantKey {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };

            let existing = grants.get(&key);
            for privilege in &wildcard.privileges {
                if !existing.is_some_and(|state| state.privileges.contains(privilege)) {
                    missing_privileges.insert(*privilege);
                }
            }
        }

        if !missing_privileges.is_empty() {
            unsatisfied.push(WildcardGrantPattern {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: wildcard.schema.clone(),
                privileges: missing_privileges,
            });
        }
    }

    unsatisfied
}

async fn fetch_wildcard_grantability(
    pool: &PgPool,
    filter: &WildcardScopeFilter,
) -> Result<BTreeMap<(ObjectType, String, String), GrantabilityRow>, sqlx::Error> {
    if filter.is_empty() {
        return Ok(BTreeMap::new());
    }
    let wildcard_schemas = filter.unique_schemas();

    let rows = sqlx::query_as::<_, GrantabilityRow>(
        r#"
        WITH wildcard_scope(
            schema_name,
            obj_type,
            need_select,
            need_insert,
            need_update,
            need_delete,
            need_truncate,
            need_references,
            need_trigger,
            need_execute,
            need_usage
        ) AS (
            SELECT *
            FROM unnest(
                $1::text[],
                $2::text[],
                $3::bool[],
                $4::bool[],
                $5::bool[],
                $6::bool[],
                $7::bool[],
                $8::bool[],
                $9::bool[],
                $10::bool[],
                $11::bool[]
            )
        )
        SELECT
            n.nspname AS schema_name,
            c.relname AS object_name,
            pg_get_userbyid(c.relowner) AS owner_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
            END AS obj_type,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_select
                 WHEN scope.need_select THEN has_table_privilege(current_user, c.oid, 'SELECT WITH GRANT OPTION')
                 ELSE false END AS can_select,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_insert
                 WHEN scope.need_insert THEN has_table_privilege(current_user, c.oid, 'INSERT WITH GRANT OPTION')
                 ELSE false END AS can_insert,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_update
                 WHEN scope.need_update THEN has_table_privilege(current_user, c.oid, 'UPDATE WITH GRANT OPTION')
                 ELSE false END AS can_update,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_delete
                 WHEN scope.need_delete THEN has_table_privilege(current_user, c.oid, 'DELETE WITH GRANT OPTION')
                 ELSE false END AS can_delete,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_truncate
                 WHEN scope.need_truncate THEN has_table_privilege(current_user, c.oid, 'TRUNCATE WITH GRANT OPTION')
                 ELSE false END AS can_truncate,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_references
                 WHEN scope.need_references THEN has_table_privilege(current_user, c.oid, 'REFERENCES WITH GRANT OPTION')
                 ELSE false END AS can_references,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_trigger
                 WHEN scope.need_trigger THEN has_table_privilege(current_user, c.oid, 'TRIGGER WITH GRANT OPTION')
                 ELSE false END AS can_trigger,
            false AS can_execute,
            false AS can_usage
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
             END
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, c.relowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            n.nspname AS schema_name,
            c.relname AS object_name,
            pg_get_userbyid(c.relowner) AS owner_name,
            'sequence' AS obj_type,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_select
                 WHEN scope.need_select THEN has_sequence_privilege(current_user, c.oid, 'SELECT WITH GRANT OPTION')
                 ELSE false END AS can_select,
            false AS can_insert,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_update
                 WHEN scope.need_update THEN has_sequence_privilege(current_user, c.oid, 'UPDATE WITH GRANT OPTION')
                 ELSE false END AS can_update,
            false AS can_delete,
            false AS can_truncate,
            false AS can_references,
            false AS can_trigger,
            false AS can_execute,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_usage
                 WHEN scope.need_usage THEN has_sequence_privilege(current_user, c.oid, 'USAGE WITH GRANT OPTION')
                 ELSE false END AS can_usage
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'sequence'
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, c.relowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE c.relkind = 'S'
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            pg_get_userbyid(p.proowner) AS owner_name,
            'function' AS obj_type,
            false AS can_select,
            false AS can_insert,
            false AS can_update,
            false AS can_delete,
            false AS can_truncate,
            false AS can_references,
            false AS can_trigger,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_execute
                 WHEN scope.need_execute THEN has_function_privilege(current_user, p.oid, 'EXECUTE WITH GRANT OPTION')
                 ELSE false END AS can_execute,
            false AS can_usage
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'function'
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, p.proowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE n.nspname = ANY($12)

        UNION ALL

        SELECT
            n.nspname AS schema_name,
            t.typname AS object_name,
            pg_get_userbyid(t.typowner) AS owner_name,
            'type' AS obj_type,
            false AS can_select,
            false AS can_insert,
            false AS can_update,
            false AS can_delete,
            false AS can_truncate,
            false AS can_references,
            false AS can_trigger,
            false AS can_execute,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_usage
                 WHEN scope.need_usage THEN has_type_privilege(current_user, t.oid, 'USAGE WITH GRANT OPTION')
                 ELSE false END AS can_usage
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'type'
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, t.typowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'
          AND n.nspname = ANY($12)

        ORDER BY schema_name, obj_type, object_name
        "#,
    )
    .bind(&filter.schema_names)
    .bind(&filter.object_types)
    .bind(&filter.need_select)
    .bind(&filter.need_insert)
    .bind(&filter.need_update)
    .bind(&filter.need_delete)
    .bind(&filter.need_truncate)
    .bind(&filter.need_references)
    .bind(&filter.need_trigger)
    .bind(&filter.need_execute)
    .bind(&filter.need_usage)
    .bind(&wildcard_schemas)
    .fetch_all(pool)
    .await?;

    let mut grantability = BTreeMap::new();
    for row in rows {
        let Some(object_type) = obj_type_str_to_object_type(&row.obj_type) else {
            continue;
        };
        grantability.insert(
            (
                object_type,
                row.schema_name.clone(),
                row.object_name.clone(),
            ),
            row,
        );
    }
    Ok(grantability)
}

fn detect_unsatisfiable_wildcards(
    grants: &BTreeMap<GrantKey, GrantState>,
    grantability: &BTreeMap<(ObjectType, String, String), GrantabilityRow>,
    wildcard_grants: &[WildcardGrantPattern],
    executor: &str,
) -> Vec<UnsatisfiableWildcardGrant> {
    let mut diagnostics = Vec::new();

    for wildcard in wildcard_grants {
        let mut skipped_objects = Vec::new();
        let mut skipped_privileges = BTreeSet::new();

        for ((object_type, schema_name, object_name), row) in grantability {
            if *object_type != wildcard.object_type || schema_name != &wildcard.schema {
                continue;
            }

            let key = GrantKey {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };
            let existing = grants.get(&key);
            let mut missing_non_grantable = BTreeSet::new();
            for privilege in &wildcard.privileges {
                if existing.is_some_and(|state| state.privileges.contains(privilege)) {
                    continue;
                }
                if can_grant(row, *privilege) {
                    continue;
                }
                missing_non_grantable.insert(*privilege);
                skipped_privileges.insert(*privilege);
            }

            if !missing_non_grantable.is_empty() {
                skipped_objects.push(UnsatisfiableWildcardObject {
                    name: object_name.clone(),
                    owner: row.owner_name.clone(),
                    privileges: missing_non_grantable,
                });
            }
        }

        if !skipped_objects.is_empty() {
            diagnostics.push(UnsatisfiableWildcardGrant {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: wildcard.schema.clone(),
                privileges: skipped_privileges,
                executor: executor.to_string(),
                skipped_count: skipped_objects.len(),
                examples: skipped_objects.into_iter().take(5).collect(),
            });
        }
    }

    diagnostics
}

fn can_grant(row: &GrantabilityRow, privilege: Privilege) -> bool {
    match privilege {
        Privilege::Select => row.can_select,
        Privilege::Insert => row.can_insert,
        Privilege::Update => row.can_update,
        Privilege::Delete => row.can_delete,
        Privilege::Truncate => row.can_truncate,
        Privilege::References => row.can_references,
        Privilege::Trigger => row.can_trigger,
        Privilege::Execute => row.can_execute,
        Privilege::Usage => row.can_usage,
        // Database and schema privileges are not object-wildcard grant targets.
        Privilege::Create | Privilege::Connect | Privilege::Temporary => false,
    }
}

/// Insert a vacuously-satisfied wildcard into the grants map. Used when no
/// objects of the target type exist in the schema — the wildcard is satisfied
/// by definition, so we populate the current state with the desired privileges
/// to prevent the diff engine from re-issuing the grant on every reconcile.
fn insert_vacuous_wildcard(
    grants: &mut BTreeMap<GrantKey, GrantState>,
    wildcard: &WildcardGrantPattern,
) {
    let wildcard_key = GrantKey {
        role: wildcard.role.clone(),
        object_type: wildcard.object_type,
        schema: Some(wildcard.schema.clone()),
        name: Some("*".to_string()),
    };
    grants.insert(
        wildcard_key,
        GrantState {
            privileges: wildcard.privileges.clone(),
        },
    );
}

fn normalize_wildcard_grants(
    mut grants: BTreeMap<GrantKey, GrantState>,
    inventory: &BTreeMap<(ObjectType, String), BTreeSet<String>>,
    wildcard_grants: &[WildcardGrantPattern],
) -> BTreeMap<GrantKey, GrantState> {
    for wildcard in wildcard_grants {
        let Some(object_names) = inventory.get(&(wildcard.object_type, wildcard.schema.clone()))
        else {
            // No inventory entry at all — insert vacuous wildcard.
            insert_vacuous_wildcard(&mut grants, wildcard);
            continue;
        };

        if object_names.is_empty() {
            // Inventory entry exists but is empty — same treatment.
            insert_vacuous_wildcard(&mut grants, wildcard);
            continue;
        }
        let mut shared_privileges = all_privileges();

        for object_name in object_names {
            let key = GrantKey {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };

            if let Some(state) = grants.get(&key) {
                shared_privileges.retain(|privilege| state.privileges.contains(privilege));
            } else {
                shared_privileges.clear();
                break;
            }
        }

        if shared_privileges.is_empty() {
            continue;
        }

        let wildcard_key = GrantKey {
            role: wildcard.role.clone(),
            object_type: wildcard.object_type,
            schema: Some(wildcard.schema.clone()),
            name: Some("*".to_string()),
        };

        grants.insert(
            wildcard_key,
            GrantState {
                privileges: shared_privileges.clone(),
            },
        );

        for object_name in object_names {
            let key = GrantKey {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };

            let remove_key = match grants.get_mut(&key) {
                Some(state) => {
                    state
                        .privileges
                        .retain(|privilege| !shared_privileges.contains(privilege));
                    state.privileges.is_empty()
                }
                None => false,
            };

            if remove_key {
                grants.remove(&key);
            }
        }
    }

    grants
}

fn all_privileges() -> BTreeSet<Privilege> {
    [
        Privilege::Select,
        Privilege::Insert,
        Privilege::Update,
        Privilege::Delete,
        Privilege::Truncate,
        Privilege::References,
        Privilege::Trigger,
        Privilege::Execute,
        Privilege::Usage,
        Privilege::Create,
        Privilege::Connect,
        Privilege::Temporary,
    ]
    .into_iter()
    .collect()
}

/// Fetch privileges on tables, views, materialized views, and sequences.
///
/// Uses `pg_class` joined with `pg_namespace`. The `relkind` column determines
/// the object type:
///   'r' = table, 'v' = view, 'm' = materialized view, 'S' = sequence, 'p' = partitioned table
///
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
async fn fetch_relation_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            n.nspname AS schema_name,
            c.relname AS object_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
                WHEN 'S' THEN 'sequence'
            END AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
          AND grantee.rolname = ANY($2)
        ORDER BY n.nspname, c.relname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch privileges on schemas.
///
/// Uses `pg_namespace`. For schema grants, the object_name is the schema name itself.
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
async fn fetch_schema_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            NULL::text AS schema_name,
            n.nspname AS object_name,
            'schema' AS obj_type
        FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(n.nspacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND grantee.rolname = ANY($2)
        ORDER BY n.nspname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch privileges on functions/procedures.
///
/// Uses `pg_proc` joined with `pg_namespace`.
/// Function names can be overloaded, so we include the OID-derived
/// identity signature via `pg_catalog.pg_get_function_identity_arguments()`.
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
async fn fetch_function_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            'function' AS obj_type
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(p.proacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND grantee.rolname = ANY($2)
        ORDER BY n.nspname, p.proname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch privileges on types/domains.
///
/// Uses `pg_type` joined with `pg_namespace`.
/// We filter out internal/array types (typname not starting with '_',
/// typtype not 'p' for pseudo-types).
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
async fn fetch_type_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            n.nspname AS schema_name,
            t.typname AS object_name,
            'type' AS obj_type
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        CROSS JOIN LATERAL aclexplode(t.typacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'
          AND grantee.rolname = ANY($2)
        ORDER BY n.nspname, t.typname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch database-level privileges on the current database.
///
/// Uses `pg_database`. This is separate because it's not schema-scoped; we
/// always query the current database. Only explicit ACLs are inspected.
pub async fn fetch_database_privileges(
    pool: &PgPool,
    managed_roles: &[&str],
) -> Result<BTreeMap<GrantKey, GrantState>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            NULL::text AS schema_name,
            db.datname AS object_name,
            'database' AS obj_type
        FROM pg_database db
        CROSS JOIN LATERAL aclexplode(db.datacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE db.datname = current_database()
          AND grantee.rolname = ANY($1)
        ORDER BY db.datname
        "#,
    )
    .bind(managed_roles)
    .fetch_all(pool)
    .await?;

    let mut grants: BTreeMap<GrantKey, GrantState> = BTreeMap::new();

    for row in rows {
        let grantee = match row.grantee {
            Some(ref name) => name,
            None => continue,
        };

        if !managed_roles.contains(&grantee.as_str()) {
            continue;
        }

        let privilege = match acl_char_to_privilege(&row.privilege_type) {
            Some(privilege) => privilege,
            None => continue,
        };

        let key = GrantKey {
            role: grantee.clone(),
            object_type: ObjectType::Database,
            schema: None,
            name: Some(row.object_name.clone()),
        };

        let entry = grants.entry(key).or_insert_with(|| GrantState {
            privileges: std::collections::BTreeSet::new(),
        });
        entry.privileges.insert(privilege);
    }

    Ok(grants)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WildcardGrantPattern;

    fn grantability_row(object_name: &str, owner_name: &str, can_execute: bool) -> GrantabilityRow {
        GrantabilityRow {
            schema_name: "app".to_string(),
            object_name: object_name.to_string(),
            owner_name: owner_name.to_string(),
            obj_type: "function".to_string(),
            can_select: false,
            can_insert: false,
            can_update: false,
            can_delete: false,
            can_truncate: false,
            can_references: false,
            can_trigger: false,
            can_execute,
            can_usage: false,
        }
    }

    fn execute_wildcard() -> WildcardGrantPattern {
        WildcardGrantPattern {
            role: "app-editor".to_string(),
            object_type: ObjectType::Function,
            schema: "app".to_string(),
            privileges: BTreeSet::from([Privilege::Execute]),
        }
    }

    #[test]
    fn acl_char_mapping_covers_all_privileges() {
        // Standard PostgreSQL ACL characters
        let cases = vec![
            ("r", Privilege::Select),
            ("a", Privilege::Insert),
            ("w", Privilege::Update),
            ("d", Privilege::Delete),
            ("D", Privilege::Truncate),
            ("x", Privilege::References),
            ("t", Privilege::Trigger),
            ("X", Privilege::Execute),
            ("U", Privilege::Usage),
            ("C", Privilege::Create),
            ("c", Privilege::Connect),
            ("T", Privilege::Temporary),
        ];
        for (char, expected) in cases {
            assert_eq!(
                acl_char_to_privilege(char),
                Some(expected),
                "failed for char '{char}'"
            );
        }
        assert_eq!(acl_char_to_privilege("Z"), None);
    }

    #[test]
    fn obj_type_str_mapping_covers_all_types() {
        let cases = vec![
            ("table", ObjectType::Table),
            ("view", ObjectType::View),
            ("materialized_view", ObjectType::MaterializedView),
            ("sequence", ObjectType::Sequence),
            ("function", ObjectType::Function),
            ("schema", ObjectType::Schema),
            ("database", ObjectType::Database),
            ("type", ObjectType::Type),
        ];
        for (type_str, expected) in cases {
            assert_eq!(
                obj_type_str_to_object_type(type_str),
                Some(expected),
                "failed for type_str '{type_str}'"
            );
        }
        assert_eq!(obj_type_str_to_object_type("unknown"), None);
    }

    #[test]
    fn diagnostics_report_missing_non_grantable_wildcard_object() {
        let grants = BTreeMap::new();
        let grantability = BTreeMap::from([
            (
                (ObjectType::Function, "app".to_string(), "f1()".to_string()),
                grantability_row("f1()", "app_owner", true),
            ),
            (
                (ObjectType::Function, "app".to_string(), "f2()".to_string()),
                grantability_row("f2()", "definer", false),
            ),
        ]);

        let diagnostics = detect_unsatisfiable_wildcards(
            &grants,
            &grantability,
            &[execute_wildcard()],
            "app_owner",
        );

        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.role, "app-editor");
        assert_eq!(diagnostic.object_type, ObjectType::Function);
        assert_eq!(diagnostic.schema, "app");
        assert_eq!(diagnostic.executor, "app_owner");
        assert_eq!(diagnostic.skipped_count, 1);
        assert_eq!(diagnostic.privileges, BTreeSet::from([Privilege::Execute]));
        assert_eq!(diagnostic.examples[0].name, "f2()");
        assert_eq!(diagnostic.examples[0].owner, "definer");
        let rendered = diagnostic.to_string();
        assert!(rendered.contains("UnsatisfiableWildcardGrant"));
        assert!(rendered.contains("app_owner"));
        assert!(rendered.contains("f2()"));
        assert!(rendered.contains("EXECUTE"));
    }

    #[test]
    fn diagnostics_ignore_missing_grantable_wildcard_object() {
        let grants = BTreeMap::new();
        let grantability = BTreeMap::from([(
            (ObjectType::Function, "app".to_string(), "f1()".to_string()),
            grantability_row("f1()", "app_owner", true),
        )]);

        let diagnostics = detect_unsatisfiable_wildcards(
            &grants,
            &grantability,
            &[execute_wildcard()],
            "app_owner",
        );

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn diagnostics_ignore_non_grantable_object_that_already_has_privilege() {
        let grants = BTreeMap::from([(
            GrantKey {
                role: "app-editor".to_string(),
                object_type: ObjectType::Function,
                schema: Some("app".to_string()),
                name: Some("f2()".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Execute]),
            },
        )]);
        let grantability = BTreeMap::from([(
            (ObjectType::Function, "app".to_string(), "f2()".to_string()),
            grantability_row("f2()", "definer", false),
        )]);

        let diagnostics = detect_unsatisfiable_wildcards(
            &grants,
            &grantability,
            &[execute_wildcard()],
            "app_owner",
        );

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn unsatisfied_wildcards_are_empty_when_every_object_has_requested_privileges() {
        let grants = BTreeMap::from([
            (
                GrantKey {
                    role: "app-editor".to_string(),
                    object_type: ObjectType::Function,
                    schema: Some("app".to_string()),
                    name: Some("f1()".to_string()),
                },
                GrantState {
                    privileges: BTreeSet::from([Privilege::Execute]),
                },
            ),
            (
                GrantKey {
                    role: "app-editor".to_string(),
                    object_type: ObjectType::Function,
                    schema: Some("app".to_string()),
                    name: Some("f2()".to_string()),
                },
                GrantState {
                    privileges: BTreeSet::from([Privilege::Execute]),
                },
            ),
        ]);
        let inventory = BTreeMap::from([(
            (ObjectType::Function, "app".to_string()),
            BTreeSet::from(["f1()".to_string(), "f2()".to_string()]),
        )]);

        let unsatisfied = unsatisfied_wildcard_grants(&grants, &inventory, &[execute_wildcard()]);

        assert!(unsatisfied.is_empty());
    }

    #[test]
    fn unsatisfied_wildcards_keep_only_missing_privileges() {
        let wildcard = WildcardGrantPattern {
            role: "app-editor".to_string(),
            object_type: ObjectType::Table,
            schema: "app".to_string(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
        };
        let grants = BTreeMap::from([(
            GrantKey {
                role: "app-editor".to_string(),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("widgets".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        )]);
        let inventory = BTreeMap::from([(
            (ObjectType::Table, "app".to_string()),
            BTreeSet::from(["widgets".to_string()]),
        )]);

        let unsatisfied = unsatisfied_wildcard_grants(&grants, &inventory, &[wildcard]);

        assert_eq!(unsatisfied.len(), 1);
        assert_eq!(
            unsatisfied[0].privileges,
            BTreeSet::from([Privilege::Insert])
        );
    }

    #[test]
    fn wildcard_scope_filter_deduplicates_scopes_and_unions_privileges() {
        let filter = WildcardScopeFilter::from_wildcards(&[
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Table,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            WildcardGrantPattern {
                role: "writer".to_string(),
                object_type: ObjectType::Table,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Insert]),
            },
        ]);

        assert_eq!(filter.schema_names, vec!["app"]);
        assert_eq!(filter.object_types, vec!["table"]);
        assert_eq!(filter.need_select, vec![true]);
        assert_eq!(filter.need_insert, vec![true]);
        assert_eq!(filter.need_update, vec![false]);
    }

    #[test]
    fn wildcard_scope_filter_reports_unique_schemas() {
        let filter = WildcardScopeFilter::from_wildcards(&[
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Table,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Function,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Execute]),
            },
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Table,
                schema: "audit".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
        ]);

        assert_eq!(filter.unique_schemas(), vec!["app", "audit"]);
    }

    #[test]
    fn wildcard_normalization_promotes_shared_table_privileges() {
        let mut grants = BTreeMap::new();
        grants.insert(
            GrantKey {
                role: "inventory-editor".to_string(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("widgets".to_string()),
            },
            GrantState {
                privileges: [Privilege::Select, Privilege::Insert].into_iter().collect(),
            },
        );
        grants.insert(
            GrantKey {
                role: "inventory-editor".to_string(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("orders".to_string()),
            },
            GrantState {
                privileges: [Privilege::Select].into_iter().collect(),
            },
        );

        let inventory = BTreeMap::from([(
            (ObjectType::Table, "inventory".to_string()),
            BTreeSet::from(["orders".to_string(), "widgets".to_string()]),
        )]);
        let selectors = vec![WildcardGrantPattern {
            role: "inventory-editor".to_string(),
            object_type: ObjectType::Table,
            schema: "inventory".to_string(),
            privileges: BTreeSet::from([
                Privilege::Select,
                Privilege::Insert,
                Privilege::Update,
                Privilege::Delete,
            ]),
        }];

        let normalized = normalize_wildcard_grants(grants, &inventory, &selectors);

        let wildcard = normalized
            .get(&GrantKey {
                role: "inventory-editor".to_string(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("*".to_string()),
            })
            .expect("wildcard grant should be synthesized");
        assert_eq!(wildcard.privileges, BTreeSet::from([Privilege::Select]));

        let specific = normalized
            .get(&GrantKey {
                role: "inventory-editor".to_string(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("widgets".to_string()),
            })
            .expect("extra object-specific privileges should remain");
        assert_eq!(specific.privileges, BTreeSet::from([Privilege::Insert]));
    }

    #[test]
    fn normalize_wildcard_empty_inventory_inserts_vacuous_wildcard() {
        // When no objects of the wildcard type exist in the schema, the
        // normalizer should insert a wildcard key with all privileges so
        // the diff sees the desired wildcard as already satisfied.
        let grants = BTreeMap::new();
        let inventory = BTreeMap::new(); // empty — no sequences in "accounts"

        let desired_privs =
            BTreeSet::from([Privilege::Select, Privilege::Update, Privilege::Usage]);
        let wildcards = vec![WildcardGrantPattern {
            role: "accounts-editor".to_string(),
            object_type: ObjectType::Sequence,
            schema: "accounts".to_string(),
            privileges: desired_privs.clone(),
        }];

        let result = normalize_wildcard_grants(grants, &inventory, &wildcards);

        let wildcard_key = GrantKey {
            role: "accounts-editor".to_string(),
            object_type: ObjectType::Sequence,
            schema: Some("accounts".to_string()),
            name: Some("*".to_string()),
        };

        let entry = result
            .get(&wildcard_key)
            .expect("vacuous wildcard should be present");
        assert_eq!(
            entry.privileges, desired_privs,
            "vacuous wildcard should have the desired privileges"
        );
    }

    #[test]
    fn normalize_wildcard_empty_set_in_inventory_inserts_vacuous_wildcard() {
        // Same as above but the inventory has the key with an empty set.
        let grants = BTreeMap::new();
        let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();
        inventory.insert(
            (ObjectType::Function, "accounts".to_string()),
            BTreeSet::new(),
        );

        let wildcards = vec![WildcardGrantPattern {
            role: "accounts-editor".to_string(),
            object_type: ObjectType::Function,
            schema: "accounts".to_string(),
            privileges: BTreeSet::from([Privilege::Execute]),
        }];

        let result = normalize_wildcard_grants(grants, &inventory, &wildcards);

        let wildcard_key = GrantKey {
            role: "accounts-editor".to_string(),
            object_type: ObjectType::Function,
            schema: Some("accounts".to_string()),
            name: Some("*".to_string()),
        };

        let entry = result
            .get(&wildcard_key)
            .expect("vacuous wildcard should be present for empty object set");
        assert_eq!(
            entry.privileges,
            BTreeSet::from([Privilege::Execute]),
            "vacuous wildcard should carry the desired privileges"
        );
    }

    #[test]
    fn normalize_wildcard_nonempty_inventory_still_collapses() {
        // Ensure the existing behavior for non-empty inventories is preserved.
        let mut grants = BTreeMap::new();
        grants.insert(
            GrantKey {
                role: "app".to_string(),
                object_type: ObjectType::Sequence,
                schema: Some("public".to_string()),
                name: Some("seq1".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Usage]),
            },
        );
        grants.insert(
            GrantKey {
                role: "app".to_string(),
                object_type: ObjectType::Sequence,
                schema: Some("public".to_string()),
                name: Some("seq2".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([
                    Privilege::Select,
                    Privilege::Usage,
                    Privilege::Update,
                ]),
            },
        );

        let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();
        inventory.insert(
            (ObjectType::Sequence, "public".to_string()),
            BTreeSet::from(["seq1".to_string(), "seq2".to_string()]),
        );

        let wildcards = vec![WildcardGrantPattern {
            role: "app".to_string(),
            object_type: ObjectType::Sequence,
            schema: "public".to_string(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Update, Privilege::Usage]),
        }];

        let result = normalize_wildcard_grants(grants, &inventory, &wildcards);

        let wildcard_key = GrantKey {
            role: "app".to_string(),
            object_type: ObjectType::Sequence,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        };

        let entry = result
            .get(&wildcard_key)
            .expect("wildcard should be present");
        // shared privileges are Select + Usage (the intersection)
        assert!(entry.privileges.contains(&Privilege::Select));
        assert!(entry.privileges.contains(&Privilege::Usage));
        assert!(
            !entry.privileges.contains(&Privilege::Update),
            "Update is not shared across all sequences"
        );
    }

    #[test]
    fn object_inventory_supports_non_relation_wildcards() {
        let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();
        inventory.insert(
            (ObjectType::Function, "public".to_string()),
            BTreeSet::from(["refresh_widgets()".to_string()]),
        );
        inventory.insert(
            (ObjectType::Type, "public".to_string()),
            BTreeSet::from(["widget_status".to_string()]),
        );
        inventory.insert(
            (ObjectType::Sequence, "public".to_string()),
            BTreeSet::from(["widgets_id_seq".to_string()]),
        );

        let wildcards = vec![
            WildcardGrantPattern {
                role: "app".to_string(),
                object_type: ObjectType::Function,
                schema: "public".to_string(),
                privileges: BTreeSet::from([Privilege::Execute]),
            },
            WildcardGrantPattern {
                role: "app".to_string(),
                object_type: ObjectType::Type,
                schema: "public".to_string(),
                privileges: BTreeSet::from([Privilege::Usage]),
            },
            WildcardGrantPattern {
                role: "app".to_string(),
                object_type: ObjectType::Sequence,
                schema: "public".to_string(),
                privileges: BTreeSet::from([Privilege::Usage]),
            },
        ];

        let result = normalize_wildcard_grants(BTreeMap::new(), &inventory, &wildcards);

        assert!(
            !result.contains_key(&GrantKey {
                role: "app".to_string(),
                object_type: ObjectType::Function,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            }),
            "existing function inventory should prevent vacuous wildcard synthesis"
        );
        assert!(
            !result.contains_key(&GrantKey {
                role: "app".to_string(),
                object_type: ObjectType::Type,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            }),
            "existing type inventory should prevent vacuous wildcard synthesis"
        );
        assert!(
            !result.contains_key(&GrantKey {
                role: "app".to_string(),
                object_type: ObjectType::Sequence,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            }),
            "existing sequence inventory should prevent vacuous wildcard synthesis"
        );
    }
}
