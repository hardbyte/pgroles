//! pgroles-operator — Kubernetes operator for PostgresPolicy CRDs.
//!
//! Watches `PostgresPolicy` custom resources and reconciles PostgreSQL roles,
//! grants, default privileges, and memberships against live databases.

pub mod advisory;
pub mod context;
pub mod crd;
pub mod observability;
pub mod reconciler;
