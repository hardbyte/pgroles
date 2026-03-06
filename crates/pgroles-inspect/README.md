# pgroles-inspect

Database introspection, version detection, and privilege checks for `pgroles`.

This crate connects to PostgreSQL, inspects roles and privileges from
`pg_catalog`, and builds the current-state graph used by the `pgroles` diff
engine.

## What It Includes

- Scoped inspection of managed roles, grants, memberships, and default privileges
- Unscoped inspection for brownfield manifest generation
- PostgreSQL server version detection (`server_version_num`)
- Managed-service privilege-level detection for supported providers
- Safety checks before dropping roles

## Typical Use

```rust
use sqlx::PgPool;

let pool = PgPool::connect("postgres://postgres:postgres@localhost/postgres").await?;

let version = pgroles_inspect::detect_pg_version(&pool).await?;
let privilege_level = pgroles_inspect::detect_privilege_level(&pool).await?;

println!("PG major: {}", version.major());
println!("Privilege level: {privilege_level}");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Notes

- This crate is intended to be paired with `pgroles-core`.
- Provider-aware privilege detection currently covers AWS RDS/Aurora, Google
  Cloud SQL, AlloyDB, and Azure Database for PostgreSQL. Other
  PostgreSQL-compatible managed services may still work, but warnings may be
  generic.

## Related Crates

- [`pgroles-core`](https://crates.io/crates/pgroles-core): desired-state model and SQL renderer
- [`pgroles-cli`](https://crates.io/crates/pgroles-cli): CLI built on this crate

Full project documentation: <https://github.com/hardbyte/pgroles>
