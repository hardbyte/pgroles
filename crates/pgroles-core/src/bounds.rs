//! Size bounds for policy content.
//!
//! These are the single source of truth for the limits that appear in three
//! places at once:
//!
//! 1. the OpenAPI schema of every CRD embedding policy content
//!    (`maxLength` / `maxItems` / `maxProperties`, via `#[schemars(length(...))]`),
//! 2. the CLI's manifest validation, so `pgroles validate` rejects exactly what
//!    the API server would reject, and
//! 3. the CEL cost budget for `PostgresPolicyCandidate`'s whole-spec
//!    `self == oldSelf` immutability rule — that rule is only admissible
//!    because every collection and string in the transitive schema is bounded.
//!
//! See `docs/design/adr-001-candidate-api-shakedown.md`, Decision 1.
//!
//! The bounds are derived from PostgreSQL and from observed usage, not from
//! CEL: `MAX_IDENTIFIER` is PostgreSQL's `NAMEDATALEN - 1`, and the collection
//! bounds sit an order of magnitude above any real policy.

/// PostgreSQL identifier limit (`NAMEDATALEN - 1`). Longer names are silently
/// truncated by the server, so accepting them would mean managing a role by a
/// name that does not exist.
pub const MAX_IDENTIFIER: u32 = 63;

/// Qualified object names and free-text comments.
pub const MAX_OBJECT_NAME: u32 = 256;

/// Role-level `config` values (`ALTER ROLE ... SET p = v`).
pub const MAX_CONFIG_VALUE: u32 = 256;

/// Role-level `config` entries per role or profile.
pub const MAX_CONFIG_ENTRIES: u32 = 32;

/// Role naming patterns (`{schema}-{profile}`). Larger than an identifier
/// because a pattern carries placeholders that shrink on substitution; the
/// *expanded* name is separately held to `MAX_IDENTIFIER`.
pub const MAX_ROLE_PATTERN: u32 = 128;

/// ISO 8601 timestamps (`password_valid_until`).
pub const MAX_TIMESTAMP: u32 = 64;

/// Kubernetes object names (RFC 1123 subdomain).
pub const MAX_K8S_NAME: u32 = 253;

/// Kubernetes Secret data keys.
pub const MAX_SECRET_KEY: u32 = 253;

/// Top-level `roles` entries.
pub const MAX_ROLES: u32 = 1024;

/// Top-level `grants` entries.
pub const MAX_GRANTS: u32 = 4096;

/// Privileges within one grant. PostgreSQL defines twelve.
pub const MAX_PRIVILEGES: u32 = 16;

/// Top-level `memberships` entries.
pub const MAX_MEMBERSHIPS: u32 = 512;

/// Members within one membership edge.
pub const MAX_MEMBERS: u32 = 256;

/// Top-level `default_privileges` entries.
pub const MAX_DEFAULT_PRIVILEGES: u32 = 512;

/// Grant entries within one default-privilege block.
pub const MAX_DEFAULT_PRIVILEGE_GRANTS: u32 = 16;

/// `profiles` map entries (`maxProperties`).
pub const MAX_PROFILES: u32 = 64;

/// Grants within one profile.
pub const MAX_PROFILE_GRANTS: u32 = 64;

/// Default-privilege entries within one profile.
pub const MAX_PROFILE_DEFAULT_PRIVILEGES: u32 = 32;

/// Top-level `schemas` bindings.
pub const MAX_SCHEMAS: u32 = 256;

/// Profile names referenced by one schema binding.
pub const MAX_SCHEMA_PROFILES: u32 = 64;

/// Top-level `retirements` entries.
pub const MAX_RETIREMENTS: u32 = 512;
