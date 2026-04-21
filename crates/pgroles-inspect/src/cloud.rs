//! Cloud-managed PostgreSQL detection and privilege level assessment.
//!
//! Detects whether the connecting role is a true superuser, a cloud provider's
//! "superuser equivalent" (for example `rds_superuser`, `cloudsqlsuperuser`,
//! `alloydbsuperuser`), or a regular user. This determines which DDL
//! operations are safe to attempt.

use sqlx::PgPool;

/// Cloud provider identity, if detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProvider {
    /// Amazon RDS / Aurora.
    AwsRds,
    /// Google Cloud SQL.
    GcpCloudSql,
    /// Google AlloyDB for PostgreSQL.
    GcpAlloyDb,
    /// Azure Database for PostgreSQL.
    AzureFlexible,
    /// Not a recognized cloud provider (self-hosted or unknown).
    Unknown,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudProvider::AwsRds => write!(f, "AWS RDS/Aurora"),
            CloudProvider::GcpCloudSql => write!(f, "Google Cloud SQL"),
            CloudProvider::GcpAlloyDb => write!(f, "Google AlloyDB"),
            CloudProvider::AzureFlexible => write!(f, "Azure Flexible Server"),
            CloudProvider::Unknown => write!(f, "unknown"),
        }
    }
}

/// The privilege level of the connecting role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// True PostgreSQL superuser (SUPERUSER attribute).
    Superuser,
    /// Cloud provider's superuser equivalent (e.g., rds_superuser, cloudsqlsuperuser).
    /// Has most but not all superuser capabilities.
    CloudSuperuser(CloudProvider),
    /// Regular user — limited privilege operations available.
    Regular,
}

impl PrivilegeLevel {
    /// Whether this privilege level can execute `ALTER ROLE ... SUPERUSER`.
    pub fn can_grant_superuser(&self) -> bool {
        matches!(self, PrivilegeLevel::Superuser)
    }

    /// Whether this privilege level can create and manage roles.
    pub fn can_manage_roles(&self) -> bool {
        !matches!(self, PrivilegeLevel::Regular)
    }

    /// Whether this privilege level can set BYPASSRLS on other roles.
    pub fn can_set_bypassrls(&self) -> bool {
        matches!(self, PrivilegeLevel::Superuser)
    }

    /// Whether this privilege level can set REPLICATION on other roles.
    pub fn can_set_replication(&self) -> bool {
        matches!(self, PrivilegeLevel::Superuser)
    }

    /// Return a list of role attributes that this privilege level cannot set.
    pub fn unsupported_attributes(&self) -> Vec<&'static str> {
        match self {
            PrivilegeLevel::Superuser => vec![],
            PrivilegeLevel::CloudSuperuser(_) => {
                vec!["SUPERUSER", "REPLICATION", "BYPASSRLS"]
            }
            PrivilegeLevel::Regular => {
                vec![
                    "SUPERUSER",
                    "CREATEDB",
                    "CREATEROLE",
                    "REPLICATION",
                    "BYPASSRLS",
                ]
            }
        }
    }
}

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivilegeLevel::Superuser => write!(f, "superuser"),
            PrivilegeLevel::CloudSuperuser(provider) => {
                write!(f, "cloud superuser ({provider})")
            }
            PrivilegeLevel::Regular => write!(f, "regular user"),
        }
    }
}

/// Detect the privilege level and cloud provider of the connecting role.
///
/// Queries the current role's attributes and role memberships to determine:
/// 1. Whether the role has SUPERUSER
/// 2. Whether it's a member of a recognized managed-service admin role
/// 3. Falls back to Regular if neither
pub async fn detect_privilege_level(pool: &PgPool) -> Result<PrivilegeLevel, sqlx::Error> {
    // Check if current user is a true superuser.
    let is_superuser: (bool,) =
        sqlx::query_as("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(pool)
            .await?;

    if is_superuser.0 {
        return Ok(PrivilegeLevel::Superuser);
    }

    // Check for cloud provider superuser role memberships.
    let cloud_roles: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT gr.rolname::text
        FROM pg_auth_members m
        JOIN pg_roles gr ON gr.oid = m.roleid
        JOIN pg_roles mr ON mr.oid = m.member
        WHERE mr.rolname = current_user
          AND gr.rolname IN ('rds_superuser', 'cloudsqlsuperuser', 'alloydbsuperuser', 'azure_pg_admin')
        "#,
    )
    .fetch_all(pool)
    .await?;

    for (role_name,) in &cloud_roles {
        match role_name.as_str() {
            "rds_superuser" => return Ok(PrivilegeLevel::CloudSuperuser(CloudProvider::AwsRds)),
            "cloudsqlsuperuser" => {
                return Ok(PrivilegeLevel::CloudSuperuser(CloudProvider::GcpCloudSql));
            }
            "alloydbsuperuser" => {
                return Ok(PrivilegeLevel::CloudSuperuser(CloudProvider::GcpAlloyDb));
            }
            "azure_pg_admin" => {
                return Ok(PrivilegeLevel::CloudSuperuser(CloudProvider::AzureFlexible));
            }
            _ => {}
        }
    }

    Ok(PrivilegeLevel::Regular)
}

/// Validate that a set of planned changes are compatible with the detected
/// privilege level. Returns warnings for operations that may fail.
pub fn validate_changes_for_privilege_level(
    changes: &[pgroles_core::diff::Change],
    level: &PrivilegeLevel,
) -> Vec<String> {
    use pgroles_core::diff::Change;
    use pgroles_core::model::RoleAttribute;

    if matches!(level, PrivilegeLevel::Superuser) {
        return vec![];
    }

    let mut warnings = Vec::new();
    let unsupported = level.unsupported_attributes();

    for change in changes {
        match change {
            Change::CreateRole { name, state } => {
                if state.superuser && unsupported.contains(&"SUPERUSER") {
                    warnings.push(format!(
                        "Cannot create role \"{name}\" with SUPERUSER — {level} lacks this privilege"
                    ));
                }
                if state.replication && unsupported.contains(&"REPLICATION") {
                    warnings.push(format!(
                        "Cannot create role \"{name}\" with REPLICATION — {level} lacks this privilege"
                    ));
                }
                if state.bypassrls && unsupported.contains(&"BYPASSRLS") {
                    warnings.push(format!(
                        "Cannot create role \"{name}\" with BYPASSRLS — {level} lacks this privilege"
                    ));
                }
            }
            Change::CreateSchema { .. } | Change::AlterSchemaOwner { .. } => {}
            Change::AlterRole { name, attributes } => {
                for attr in attributes {
                    let attr_name = match attr {
                        RoleAttribute::Superuser(true) => Some("SUPERUSER"),
                        RoleAttribute::Replication(true) => Some("REPLICATION"),
                        RoleAttribute::Bypassrls(true) => Some("BYPASSRLS"),
                        _ => None,
                    };
                    if let Some(attr_name) = attr_name
                        && unsupported.contains(&attr_name)
                    {
                        warnings.push(format!(
                            "Cannot alter role \"{name}\" to set {attr_name} — {level} lacks this privilege"
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::diff::Change;
    use pgroles_core::model::{RoleAttribute, RoleState};

    #[test]
    fn superuser_has_no_unsupported_attrs() {
        assert!(
            PrivilegeLevel::Superuser
                .unsupported_attributes()
                .is_empty()
        );
    }

    #[test]
    fn cloud_superuser_cannot_grant_superuser() {
        let level = PrivilegeLevel::CloudSuperuser(CloudProvider::AwsRds);
        assert!(!level.can_grant_superuser());
        assert!(level.can_manage_roles());
        assert!(level.unsupported_attributes().contains(&"SUPERUSER"));
    }

    #[test]
    fn regular_user_limited_capabilities() {
        let level = PrivilegeLevel::Regular;
        assert!(!level.can_grant_superuser());
        assert!(!level.can_manage_roles());
        assert!(level.unsupported_attributes().len() >= 4);
    }

    #[test]
    fn validate_warns_on_superuser_creation_with_cloud_provider() {
        let level = PrivilegeLevel::CloudSuperuser(CloudProvider::GcpCloudSql);
        let changes = vec![Change::CreateRole {
            name: "admin".to_string(),
            state: RoleState {
                superuser: true,
                ..RoleState::default()
            },
        }];

        let warnings = validate_changes_for_privilege_level(&changes, &level);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("SUPERUSER"));
        assert!(warnings[0].contains("cloud superuser"));
    }

    #[test]
    fn validate_warns_on_alter_bypassrls_with_cloud_provider() {
        let level = PrivilegeLevel::CloudSuperuser(CloudProvider::AwsRds);
        let changes = vec![Change::AlterRole {
            name: "service".to_string(),
            attributes: vec![RoleAttribute::Bypassrls(true)],
        }];

        let warnings = validate_changes_for_privilege_level(&changes, &level);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("BYPASSRLS"));
    }

    #[test]
    fn validate_no_warnings_for_superuser() {
        let level = PrivilegeLevel::Superuser;
        let changes = vec![Change::CreateRole {
            name: "admin".to_string(),
            state: RoleState {
                superuser: true,
                bypassrls: true,
                replication: true,
                ..RoleState::default()
            },
        }];

        let warnings = validate_changes_for_privilege_level(&changes, &level);
        assert!(warnings.is_empty());
    }

    #[test]
    fn display_formats() {
        assert_eq!(
            PrivilegeLevel::CloudSuperuser(CloudProvider::AwsRds).to_string(),
            "cloud superuser (AWS RDS/Aurora)"
        );
        assert_eq!(
            PrivilegeLevel::CloudSuperuser(CloudProvider::GcpAlloyDb).to_string(),
            "cloud superuser (Google AlloyDB)"
        );
        assert_eq!(PrivilegeLevel::Superuser.to_string(), "superuser");
        assert_eq!(PrivilegeLevel::Regular.to_string(), "regular user");
    }
}
