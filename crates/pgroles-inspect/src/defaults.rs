//! Query default privileges from `pg_default_acl`.
//!
//! Default privileges control the ACLs automatically applied to newly created
//! objects. They are set via `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>
//! [IN SCHEMA <schema>] GRANT/REVOKE ... ON <type> TO/FROM <grantee>`.
//!
//! The `pg_default_acl` table stores:
//!   - `defaclrole`: OID of the owner role
//!   - `defaclnamespace`: OID of the schema (0 = the owner-wide global layer)
//!   - `defaclobjtype`: char indicating the object type
//!     'r' = relation (table), 'S' = sequence, 'f' = function, 'T' = type, 'n' = schema
//!   - `defaclacl`: the ACL array
//!
//! We use `aclexplode(defaclacl)` to decompose the ACL into individual grants.
//!
//! Two layers are inspected. The schema layer covers explicit rows in managed
//! schemas. The global layer is fetched only for `(owner, type)` pairs the
//! manifest declares with `scope: {type: global}`, and it reports the
//! *effective* default: when no explicit row exists, `acldefault(type, owner)`
//! stands in, so PostgreSQL's built-in `PUBLIC EXECUTE` on routines (and
//! `PUBLIC USAGE` on types) is visible to `ensure: absent` rules. Owner
//! self-entries are excluded in SQL: every `ALTER DEFAULT PRIVILEGES`
//! materializes the owner's implicit self-grant into the explicit row, and
//! reporting it would make authoritative mode revoke the owner's own default
//! on the next reconcile. The accepted blind spot is that an intentional
//! owner-self default change is invisible to pgroles.
//!
//! This is the same underlying fact as the grant-level owner guard (see
//! `privileges::AclRow::owner_name` and `SqlContext::owned_relations`): an
//! ACL entry whose grantee is the object's owner carries inherent privileges,
//! not granted state. Default privileges use SQL-level exclusion because the
//! desired side keys on the owner explicitly; grants tag the entries instead
//! so declared owner grants still converge. The two mechanisms should
//! eventually be unified on tagging.

use std::collections::BTreeMap;

use sqlx::PgPool;

use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::{DefaultPrivKey, DefaultPrivState, DefaultPrivilegeScope, Grantee};

use crate::DefaultPrivScopePattern;

/// A raw row from the `pg_default_acl` + `aclexplode()` queries.
#[derive(Debug, sqlx::FromRow)]
struct DefaultAclRow {
    /// The owner role name (whose newly-created objects get these defaults).
    owner_name: String,
    /// The schema name (NULL for global-layer rows).
    schema_name: Option<String>,
    /// The grantee role name. NULL for PUBLIC (see `is_public`) and for
    /// dangling grantee OIDs.
    grantee: Option<String>,
    /// True when the ACL grantee is OID 0, i.e. PUBLIC.
    is_public: bool,
    /// The privilege character (same mapping as regular ACLs).
    privilege_type: String,
    /// The object type character from `defaclobjtype`.
    obj_type_char: String,
}

/// Map the `defaclobjtype` character to our `ObjectType` enum.
fn defacl_obj_type_to_object_type(character: &str) -> Option<ObjectType> {
    match character {
        "r" => Some(ObjectType::Table),
        "S" => Some(ObjectType::Sequence),
        "f" => Some(ObjectType::Function),
        "T" => Some(ObjectType::Type),
        "n" => Some(ObjectType::Schema),
        _ => None,
    }
}

/// Map a PostgreSQL ACL privilege character to our `Privilege` enum.
///
/// This is the same mapping as in `privileges.rs` — duplicated here to keep
/// the module self-contained. Both modules are internal implementation details.
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

/// Map `ObjectType` to the `defaclobjtype` character.
fn object_type_to_defacl_char(object_type: ObjectType) -> Option<&'static str> {
    match object_type {
        ObjectType::Table => Some("r"),
        ObjectType::Sequence => Some("S"),
        ObjectType::Function => Some("f"),
        ObjectType::Type => Some("T"),
        ObjectType::Schema => Some("n"),
        _ => None,
    }
}

/// Map `ObjectType` to the character `acldefault()` expects.
///
/// This is not the same alphabet as `defaclobjtype`. `acldefault` spells a
/// sequence `s`, and reads `S` as a foreign server, so passing the
/// `pg_default_acl` character straight through returns a foreign server's
/// defaults for sequences instead of erroring.
fn object_type_to_acldefault_char(object_type: ObjectType) -> Option<&'static str> {
    match object_type {
        ObjectType::Sequence => Some("s"),
        other => object_type_to_defacl_char(other),
    }
}

/// Fetch default privileges for the managed schemas, roles, and declared
/// entry scopes.
///
/// Returns a map of `DefaultPrivKey → DefaultPrivState` ready for insertion
/// into a `RoleGraph`.
///
/// Role-grantee rows in the schema layer keep the historical rule: any owner,
/// as long as the schema is managed and the grantee is managed. PUBLIC rows
/// and everything in the global layer are assertion-scoped instead — they are
/// reported only for the exact `(owner, scope, on_type)` patterns the
/// manifest declares, and PUBLIC rows only for the privileges its rules
/// mention. That keeps pgroles from ever revoking a default it wasn't told
/// about.
pub(crate) async fn fetch_default_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
    scopes: &[DefaultPrivScopePattern],
) -> Result<BTreeMap<DefaultPrivKey, DefaultPrivState>, sqlx::Error> {
    let mut rows = sqlx::query_as::<_, DefaultAclRow>(
        r#"
        SELECT
            owner_role.rolname AS owner_name,
            n.nspname AS schema_name,
            grantee_role.rolname AS grantee,
            (acl.grantee = 0) AS is_public,
            acl.privilege_type,
            da.defaclobjtype::text AS obj_type_char
        FROM pg_default_acl da
        JOIN pg_roles owner_role ON owner_role.oid = da.defaclrole
        JOIN pg_namespace n ON n.oid = da.defaclnamespace
        CROSS JOIN LATERAL aclexplode(da.defaclacl) AS acl
        LEFT JOIN pg_roles grantee_role ON grantee_role.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND da.defaclnamespace <> 0
        ORDER BY owner_role.rolname, n.nspname, da.defaclobjtype
        "#,
    )
    .bind(managed_schemas)
    .fetch_all(pool)
    .await?;

    // Global layer: effective defaults for the declared (owner, type) pairs.
    // The LEFT JOIN plus COALESCE(acldefault) is what synthesizes PostgreSQL's
    // built-ins when no explicit row exists yet; `acl.grantee <> r.oid` drops
    // owner self-entries (module doc explains why that is load-bearing).
    let global_pairs: std::collections::BTreeSet<(String, String, String)> = scopes
        .iter()
        .filter(|pattern| pattern.schema.is_none())
        .filter_map(|pattern| {
            let stored = object_type_to_defacl_char(pattern.on_type)?;
            let builtin = object_type_to_acldefault_char(pattern.on_type)?;
            Some((
                pattern.owner.clone(),
                stored.to_string(),
                builtin.to_string(),
            ))
        })
        .collect();
    if !global_pairs.is_empty() {
        let owners: Vec<String> = global_pairs
            .iter()
            .map(|(owner, _, _)| owner.clone())
            .collect();
        let chars: Vec<String> = global_pairs
            .iter()
            .map(|(_, stored, _)| stored.clone())
            .collect();
        let builtin_chars: Vec<String> = global_pairs
            .iter()
            .map(|(_, _, builtin)| builtin.clone())
            .collect();
        rows.extend(
            sqlx::query_as::<_, DefaultAclRow>(
                r#"
                WITH global_scope(owner_name, obj_char, builtin_char) AS (
                    SELECT * FROM unnest($1::text[], $2::text[], $3::text[])
                )
                SELECT
                    r.rolname::text AS owner_name,
                    NULL::text AS schema_name,
                    grantee_role.rolname::text AS grantee,
                    (acl.grantee = 0) AS is_public,
                    acl.privilege_type,
                    s.obj_char AS obj_type_char
                FROM global_scope s
                JOIN pg_roles r ON r.rolname = s.owner_name
                LEFT JOIN pg_default_acl da
                       ON da.defaclrole = r.oid
                      AND da.defaclnamespace = 0
                      AND da.defaclobjtype = s.obj_char::"char"
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(da.defaclacl, acldefault(s.builtin_char::"char", r.oid))
                ) AS acl
                LEFT JOIN pg_roles grantee_role ON grantee_role.oid = acl.grantee
                WHERE acl.grantee <> r.oid
                ORDER BY r.rolname, s.obj_char
                "#,
            )
            .bind(&owners)
            .bind(&chars)
            .bind(&builtin_chars)
            .fetch_all(pool)
            .await?,
        );
    }

    let mut defaults: BTreeMap<DefaultPrivKey, DefaultPrivState> = BTreeMap::new();

    for row in rows {
        let privilege = match acl_char_to_privilege(&row.privilege_type) {
            Some(privilege) => privilege,
            None => continue,
        };

        let on_type = match defacl_obj_type_to_object_type(&row.obj_type_char) {
            Some(object_type) => object_type,
            None => continue,
        };

        let scope = match &row.schema_name {
            Some(schema) => DefaultPrivilegeScope::Schema {
                schema: schema.clone(),
            },
            None => DefaultPrivilegeScope::Global,
        };

        let grantee = if row.is_public {
            // PUBLIC rows are kept only when the manifest names this exact
            // (owner, scope, type) pattern with this privilege.
            let covered = scopes.iter().any(|pattern| {
                pattern.owner == row.owner_name
                    && pattern.schema.as_deref() == row.schema_name.as_deref()
                    && pattern.on_type == on_type
                    && pattern.public_privileges.contains(&privilege)
            });
            if !covered {
                continue;
            }
            Grantee::Public
        } else {
            // Skip dangling grantee OIDs (NULL name but not PUBLIC). The
            // global-layer query is already scoped to declared (owner, type)
            // pairs, so the managed-role filter is the only check left for
            // both layers.
            let Some(name) = &row.grantee else { continue };
            if !managed_roles.contains(&name.as_str()) {
                continue;
            }
            Grantee::Role(name.clone())
        };

        let key = DefaultPrivKey {
            owner: row.owner_name.clone(),
            scope,
            on_type,
            grantee,
        };

        let entry = defaults.entry(key).or_insert_with(|| DefaultPrivState {
            privileges: std::collections::BTreeSet::new(),
        });
        entry.privileges.insert(privilege);
    }

    Ok(defaults)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defacl_obj_type_mapping() {
        assert_eq!(defacl_obj_type_to_object_type("r"), Some(ObjectType::Table));
        assert_eq!(
            defacl_obj_type_to_object_type("S"),
            Some(ObjectType::Sequence)
        );
        assert_eq!(
            defacl_obj_type_to_object_type("f"),
            Some(ObjectType::Function)
        );
        assert_eq!(defacl_obj_type_to_object_type("T"), Some(ObjectType::Type));
        assert_eq!(
            defacl_obj_type_to_object_type("n"),
            Some(ObjectType::Schema)
        );
        assert_eq!(defacl_obj_type_to_object_type("x"), None);
    }

    #[test]
    fn acl_char_mapping_consistent() {
        // Verify the duplicated mapping matches expectations
        assert_eq!(acl_char_to_privilege("r"), Some(Privilege::Select));
        assert_eq!(acl_char_to_privilege("a"), Some(Privilege::Insert));
        assert_eq!(acl_char_to_privilege("w"), Some(Privilege::Update));
        assert_eq!(acl_char_to_privilege("d"), Some(Privilege::Delete));
        assert_eq!(acl_char_to_privilege("D"), Some(Privilege::Truncate));
        assert_eq!(acl_char_to_privilege("x"), Some(Privilege::References));
        assert_eq!(acl_char_to_privilege("t"), Some(Privilege::Trigger));
        assert_eq!(acl_char_to_privilege("X"), Some(Privilege::Execute));
        assert_eq!(acl_char_to_privilege("U"), Some(Privilege::Usage));
        assert_eq!(acl_char_to_privilege("C"), Some(Privilege::Create));
        assert_eq!(acl_char_to_privilege("c"), Some(Privilege::Connect));
        assert_eq!(acl_char_to_privilege("T"), Some(Privilege::Temporary));
        assert_eq!(acl_char_to_privilege("?"), None);
    }
}
