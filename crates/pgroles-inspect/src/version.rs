//! PostgreSQL version detection.
//!
//! Queries `server_version_num` to determine the PostgreSQL major version,
//! which controls syntax differences (e.g., `WITH INHERIT` in PG 16+).

use sqlx::PgPool;

/// Parsed PostgreSQL server version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgVersion {
    /// The raw version number from `server_version_num` (e.g., 160004 for 16.4).
    pub version_num: i32,
}

impl PgVersion {
    /// Major version (e.g., 16 for version_num 160004).
    pub fn major(&self) -> i32 {
        self.version_num / 10000
    }

    /// Whether this version supports `GRANT ... WITH INHERIT TRUE/FALSE`
    /// and `WITH SET TRUE/FALSE` (PG 16+).
    pub fn supports_grant_with_options(&self) -> bool {
        self.major() >= 16
    }
}

impl std::fmt::Display for PgVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let major = self.major();
        let minor = self.version_num % 10000;
        write!(f, "{major}.{minor}")
    }
}

/// Detect the PostgreSQL server version.
pub async fn detect_pg_version(pool: &PgPool) -> Result<PgVersion, sqlx::Error> {
    let row: (i32,) = sqlx::query_as("SELECT current_setting('server_version_num')::int")
        .fetch_one(pool)
        .await?;
    Ok(PgVersion { version_num: row.0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_version_parsing() {
        let v = PgVersion {
            version_num: 160004,
        };
        assert_eq!(v.major(), 16);
        assert!(v.supports_grant_with_options());
        assert_eq!(v.to_string(), "16.4");
    }

    #[test]
    fn pg15_does_not_support_grant_options() {
        let v = PgVersion {
            version_num: 150008,
        };
        assert_eq!(v.major(), 15);
        assert!(!v.supports_grant_with_options());
    }

    #[test]
    fn pg14_version() {
        let v = PgVersion {
            version_num: 140012,
        };
        assert_eq!(v.major(), 14);
        assert!(!v.supports_grant_with_options());
    }
}
