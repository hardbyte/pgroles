//! Query default privileges from `pg_default_acl`.
//!
//! Default privileges control the ACLs automatically applied to newly created
//! objects. They are set via `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>
//! IN SCHEMA <schema> GRANT ... ON <type> TO <grantee>`.
//!
//! The `pg_default_acl` table stores:
//!   - `defaclrole`: OID of the owner role
//!   - `defaclnamespace`: OID of the schema (0 = global, i.e. all schemas)
//!   - `defaclobjtype`: char indicating the object type
//!     'r' = relation (table), 'S' = sequence, 'f' = function, 'T' = type, 'n' = schema
//!   - `defaclacl`: the ACL array
//!
//! We use `aclexplode(defaclacl)` to decompose the ACL into individual grants.

use std::collections::BTreeMap;

use sqlx::PgPool;

use pgpolicy_core::manifest::{ObjectType, Privilege};
use pgpolicy_core::model::{DefaultPrivKey, DefaultPrivState};

/// A raw row from the `pg_default_acl` + `aclexplode()` query.
#[derive(Debug, sqlx::FromRow)]
struct DefaultAclRow {
    /// The owner role name (whose newly-created objects get these defaults).
    owner_name: String,
    /// The schema name (NULL for global defaults — we filter these out).
    schema_name: Option<String>,
    /// The grantee role name (NULL means PUBLIC — we skip those).
    grantee: Option<String>,
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

/// Fetch all default privileges from `pg_default_acl` for the given schemas and roles.
///
/// Returns a map of `DefaultPrivKey → DefaultPrivState` ready for insertion into a `RoleGraph`.
///
/// Only returns defaults where the schema is in `managed_schemas` and the grantee
/// is in `managed_roles`. Owner filtering is intentionally NOT done here — we want
/// to capture defaults set by any owner (the manifest's `default_owner` or
/// per-schema `owner`) as long as the grantee is managed.
pub async fn fetch_default_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<BTreeMap<DefaultPrivKey, DefaultPrivState>, sqlx::Error> {
    let rows = sqlx::query_as::<_, DefaultAclRow>(
        r#"
        SELECT
            owner_role.rolname AS owner_name,
            n.nspname AS schema_name,
            grantee_role.rolname AS grantee,
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

    let mut defaults: BTreeMap<DefaultPrivKey, DefaultPrivState> = BTreeMap::new();

    for row in rows {
        // Skip PUBLIC grantee (NULL)
        let grantee = match row.grantee {
            Some(ref name) => name,
            None => continue,
        };

        // Skip if grantee isn't in the managed set
        if !managed_roles.contains(&grantee.as_str()) {
            continue;
        }

        let schema_name = match row.schema_name {
            Some(ref name) => name,
            None => continue, // global defaults (namespace=0) — we don't manage these
        };

        let privilege = match acl_char_to_privilege(&row.privilege_type) {
            Some(privilege) => privilege,
            None => continue,
        };

        let on_type = match defacl_obj_type_to_object_type(&row.obj_type_char) {
            Some(object_type) => object_type,
            None => continue,
        };

        let key = DefaultPrivKey {
            owner: row.owner_name.clone(),
            schema: schema_name.clone(),
            on_type,
            grantee: grantee.clone(),
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
