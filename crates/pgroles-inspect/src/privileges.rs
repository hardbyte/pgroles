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

use crate::WildcardGrantPattern;
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
    fetch_privileges_with_wildcards(pool, managed_schemas, managed_roles, &[]).await
}

/// Fetch schema-scoped relation names grouped by object type.
pub async fn fetch_relation_inventory(
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
        ORDER BY n.nspname, c.relkind, c.relname
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

pub(crate) async fn fetch_privileges_with_wildcards(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
    wildcard_grants: &[WildcardGrantPattern],
) -> Result<BTreeMap<GrantKey, GrantState>, sqlx::Error> {
    let mut grants: BTreeMap<GrantKey, GrantState> = BTreeMap::new();
    let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();

    for ((object_type, schema_name), object_names) in
        fetch_relation_inventory(pool, managed_schemas).await?
    {
        inventory.insert(
            (object_type, schema_name),
            object_names.into_iter().collect(),
        );
    }

    // Run all the independent queries and collect results.
    // We use separate queries per object type rather than one giant UNION
    // because the NULL-ACL handling (acldefault) differs per type.

    let relation_rows = fetch_relation_privileges(pool, managed_schemas).await?;
    let schema_rows = fetch_schema_privileges(pool, managed_schemas).await?;
    let function_rows = fetch_function_privileges(pool, managed_schemas).await?;
    let type_rows = fetch_type_privileges(pool, managed_schemas).await?;

    let all_rows: Vec<AclRow> = relation_rows
        .into_iter()
        .chain(schema_rows)
        .chain(function_rows)
        .chain(type_rows)
        .collect();

    for row in &all_rows {
        if let Some(object_type) = obj_type_str_to_object_type(&row.obj_type)
            && !matches!(object_type, ObjectType::Schema | ObjectType::Database)
            && let Some(schema_name) = &row.schema_name
        {
            inventory
                .entry((object_type, schema_name.clone()))
                .or_default()
                .insert(row.object_name.clone());
        }
    }

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

    Ok(normalize_wildcard_grants(
        grants,
        &inventory,
        wildcard_grants,
    ))
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
        LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
        ORDER BY n.nspname, c.relname
        "#,
    )
    .bind(managed_schemas)
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
        LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
        ORDER BY n.nspname
        "#,
    )
    .bind(managed_schemas)
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
        LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
        ORDER BY n.nspname, p.proname
        "#,
    )
    .bind(managed_schemas)
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
        LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'
        ORDER BY n.nspname, t.typname
        "#,
    )
    .bind(managed_schemas)
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
        LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE db.datname = current_database()
        ORDER BY db.datname
        "#,
    )
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
}
