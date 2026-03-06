# pgroles Architecture Assessment & Implementation Plan

## Executive Summary

pgroles is already a well-structured, production-oriented Rust project with a solid foundation. The codebase (~8k LOC across 4 crates) implements the core plan/apply workflow, profile-based role expansion, convergent diff engine, SQL generation, database introspection, and a Kubernetes operator. This document assesses the current state against the prior art landscape and provides a concrete, prioritized implementation plan for the gaps that remain.

---

## 1. Current State Assessment

### 1.1 What pgroles already solves (vs prior art)

| Capability | pgbedrock | TF cyrilgdn | pgroles (today) |
|---|---|---|---|
| Plan/apply workflow | Partial (check/live) | Yes (via TF) | **Yes** (diff/apply) |
| Fine-grained privileges | No (read/write binary) | Yes | **Yes** (all PG privs) |
| Default privileges | Broken | Broken | **Correct** (per-owner, per-schema) |
| Role inheritance graph | Partial | No graph model | **Yes** (BTreeMap/BTreeSet) |
| Convergent model | Yes | Yes (per resource) | **Yes** (whole-graph) |
| Profile/template system | No | No | **Yes** (profiles × schemas) |
| Role retirement lifecycle | No | No | **Yes** (reassign/drop/terminate) |
| Brownfield `generate` | Yes | N/A | **Partial** (`inspect` exists) |
| PG 16+ syntax | No | Broken | **Yes** (`WITH INHERIT/ADMIN`) |
| K8s operator | No | No | **Yes** (alpha CRD) |
| Transactional apply | No | No | **Yes** |
| Safety preflight checks | No | No | **Yes** (owned objects, sessions) |
| Idempotent diff | Broken (spurious changes) | Broken (dirty state) | **Yes** (BTreeMap determinism) |

### 1.2 What pgroles does NOT yet solve

These are the meaningful gaps relative to the briefing's requirements:

1. **Row-Level Security (RLS) policy management** — No support for `CREATE POLICY`, `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, or policy-to-role binding.

2. **Cloud provider auth abstraction** — No awareness of Cloud SQL IAM users, RDS IAM auth, or Vault dynamic credentials. External role names (e.g., `serviceaccount@project.iam`) can be used in memberships today, but there's no structured provider model.

3. **Full `generate`/`export` command** — `inspect` builds a `RoleGraph` from the DB but doesn't serialize it back to a YAML manifest. Brownfield adoption requires this round-trip.

4. **Managed scope / reconciliation modes** — The current model is fully convergent (authoritative). There's no `additive` mode for teams that only want to manage a subset of roles without revoking unmanaged ones.

5. **PG version detection and syntax adaptation** — SQL generation hardcodes PG 16+ syntax (`WITH INHERIT`). No runtime version detection or fallback for PG 14/15.

6. **Superuser vs managed-PG privilege detection** — No detection of whether the connecting role is a true superuser, `rds_superuser`, or `cloudsqlsuperuser`, and no graceful degradation.

7. **JSON output format** — Only `sql` and `summary` formats; no `--format json` for CI/CD integration.

8. **Drift detection exit code** — `diff` doesn't set a non-zero exit code when drift is detected (needed for CI gates).

9. **Manifest export from RoleGraph** — The `RoleGraph → YAML` path doesn't exist (only `YAML → RoleGraph` exists).

---

## 2. Gap Analysis: Priority Assessment

### Tier 1 — High value, clear path, builds on existing architecture

| Gap | Why now | Effort |
|---|---|---|
| `generate` / `export` command | Biggest adoption blocker for brownfield DBs. `inspect` already builds the `RoleGraph`; needs serialization. | Medium (2-3 days) |
| `--format json` output | Table-stakes for CI/CD pipelines. Changes are already structured data. | Small (0.5 day) |
| Drift exit code | CI gate essential. Trivial: exit 2 when diff is non-empty. | Tiny (< 1 hour) |
| PG version detection | Prevents breakage on PG 14/15. Query `SHOW server_version_num` once, branch in SQL gen. | Small (1 day) |

### Tier 2 — High value, moderate complexity

| Gap | Why now | Effort |
|---|---|---|
| Reconciliation modes (additive) | Critical for incremental adoption. Teams won't trust a tool that revokes unmanaged roles on first run. | Medium (2-3 days) |
| Managed-PG privilege detection | Cloud SQL/RDS are majority of deployments. Failing with `permission denied` is a terrible first experience. | Small (1 day) |
| RLS policy management | Unique differentiator vs all prior art. No other tool manages this. | Large (5-7 days) |

### Tier 3 — Strategic, longer-term

| Gap | Why later | Effort |
|---|---|---|
| Cloud auth provider abstraction | Useful but can be worked around with role naming conventions. | Medium-Large |
| Vault integration | Complementary tool; users can set up Vault creation statements manually. | Medium |
| LDAP/SCIM adapter | Enterprise feature. | Large |

---

## 3. Implementation Plan

### Phase A: Brownfield Adoption & CI/CD Readiness

**Goal:** Make pgroles usable for teams with existing databases, and integrate into CI pipelines.

#### A1. Drift exit code for `diff` command
- **Files:** `crates/pgroles-cli/src/main.rs`
- **Change:** After computing changes in the `diff` subcommand, exit with code 2 if changes are non-empty, 0 if clean. Add `--exit-code` flag (default on) to match `git diff` semantics.
- **Test:** CLI integration test asserting exit code behavior.

#### A2. `--format json` output
- **Files:** `crates/pgroles-cli/src/main.rs`, `crates/pgroles-cli/src/lib.rs`
- **Change:** Add `Json` variant to the output format enum. Serialize `Vec<Change>` via serde. The `Change` enum needs `#[derive(Serialize)]` added in `crates/pgroles-core/src/diff.rs`. Also needs serde derives on `RoleState`, `RoleAttribute`, `GrantKey`, `GrantState`, etc.
- **Dependencies:** Add `serde_json` to `pgroles-cli` deps.
- **Test:** Roundtrip test: parse JSON output, verify it deserializes back to expected `Change` list.

#### A3. `generate` / `export` command
- **Files:** New function in `crates/pgroles-cli/src/lib.rs`, new subcommand in `main.rs`, new module `crates/pgroles-core/src/export.rs`
- **Design:**
  - `RoleGraph → PolicyManifest` conversion function in core crate
  - Heuristic profile detection: group roles with identical grant patterns into profiles
  - For v1, emit a flat manifest (no profiles, just `roles:` + `grants:` + `default_privileges:` + `memberships:`) — simple and correct
  - Profile inference is a stretch goal
  - `serde_yaml::to_string(&manifest)` for output
  - The generated manifest, when applied back to the same DB, must produce zero diff (round-trip invariant)
- **Test:** Integration test: inspect DB → generate manifest → parse → expand → build RoleGraph → diff against inspected RoleGraph → assert empty.

#### A4. PG version detection and syntax adaptation
- **Files:** `crates/pgroles-inspect/src/lib.rs` (add version query), `crates/pgroles-core/src/sql.rs` (conditional syntax)
- **Design:**
  - Add `pg_version: u32` field to a new `SqlContext` struct passed to `render_statements`
  - For PG < 16: omit `WITH INHERIT/ADMIN` from membership grants (use legacy `GRANT ... TO ... WITH ADMIN OPTION` syntax)
  - For PG < 16: membership introspection skips the `inherit_option`/`admin_option` columns from `pg_auth_members` (they were added in PG 16)
  - Version detection: `SELECT current_setting('server_version_num')::int` — returns e.g. `160004` for PG 16.4
- **Breaking concern:** This changes the `render` function signatures. Use a builder pattern or pass context to avoid breaking existing call sites.
- **Test:** Unit tests for PG 14-style and PG 16-style SQL output.

### Phase B: Reconciliation Modes & Cloud Safety

**Goal:** Support incremental adoption and cloud-managed Postgres.

#### B1. Reconciliation modes
- **Files:** `crates/pgroles-core/src/manifest.rs` (add mode field), `crates/pgroles-core/src/diff.rs` (filter changes by mode)
- **Manifest addition:**
  ```yaml
  mode: authoritative  # default: revoke/drop anything not in manifest
  # mode: additive     # only create/grant, never revoke/drop
  # mode: adopt        # like authoritative but skip roles not currently in DB
  ```
- **Design:**
  - `authoritative` (current behavior, default): full convergence
  - `additive`: filter out all `Revoke`, `RevokeDefaultPrivilege`, `RemoveMember`, `DropRole` changes from the diff output
  - `adopt`: like authoritative, but only manage roles that already exist in the DB or are declared in the manifest. Don't drop roles that aren't in the manifest but also weren't created by pgroles.
- **Implementation:** Add a `ReconcileMode` enum and a post-filter on `diff()` output. The diff engine itself stays pure; filtering happens in the CLI/operator layer.
- **Test:** Same manifest, same DB state → different change sets under different modes.

#### B2. Managed-PG privilege detection
- **Files:** `crates/pgroles-inspect/src/lib.rs`
- **Design:**
  - After connecting, query for the connecting role's attributes and memberships
  - Detect `rds_superuser`, `cloudsqlsuperuser`, or true `SUPERUSER` attribute
  - Store as an enum: `PrivilegeLevel { Superuser, CloudSuperuser(Provider), Regular }`
  - Before applying changes that require superuser (e.g., `ALTER ROLE ... SUPERUSER`, `BYPASSRLS`, `REPLICATION`), check privilege level and either:
    - Emit a warning and skip the change
    - Return an error with a helpful message about the cloud provider limitation
  - This is primarily a validation pass on the change list, not a change to the diff engine

#### B3. Schema ownership and `ALTER DEFAULT PRIVILEGES` creator model
- **Context:** The briefing correctly identifies that default privileges require per-creator awareness. pgroles already handles this correctly via the `owner` field in `DefaultPrivKey`. The remaining gap is:
  - The manifest should validate that the declared owner actually has CREATE privileges on the schema
  - If multiple roles can create objects, the user must declare default privilege rules for each creator
- **Files:** `crates/pgroles-core/src/manifest.rs` (validation), documentation
- **This is primarily a validation and documentation improvement**, not an architecture change.

### Phase C: Row-Level Security

**Goal:** Become the only tool that manages RLS policies declaratively.

#### C1. RLS data model
- **Files:** `crates/pgroles-core/src/manifest.rs`, `crates/pgroles-core/src/model.rs`
- **Manifest addition:**
  ```yaml
  rls_policies:
    - table: orders
      schema: inventory
      name: tenant_isolation
      command: ALL           # SELECT, INSERT, UPDATE, DELETE, or ALL
      permissive: true       # PERMISSIVE (default) or RESTRICTIVE
      roles: [inventory-editor]  # TO clause; omit for PUBLIC
      using: "tenant_id = current_setting('app.tenant_id')::int"
      with_check: "tenant_id = current_setting('app.tenant_id')::int"
  ```
- **Model types:**
  ```rust
  struct RlsPolicyKey {
      schema: String,
      table: String,
      policy_name: String,
  }

  struct RlsPolicyState {
      command: RlsCommand,        // All, Select, Insert, Update, Delete
      permissive: bool,
      roles: Vec<String>,         // empty = PUBLIC
      using_expr: Option<String>,
      with_check_expr: Option<String>,
  }
  ```
- **RoleGraph extension:** Add `rls_policies: BTreeMap<RlsPolicyKey, RlsPolicyState>` and `rls_enabled_tables: BTreeSet<(String, String)>` (schema, table pairs where RLS is enabled).

#### C2. RLS diff engine
- **Files:** `crates/pgroles-core/src/diff.rs`
- **New Change variants:**
  ```rust
  EnableRls { schema: String, table: String },
  DisableRls { schema: String, table: String },
  CreatePolicy { key: RlsPolicyKey, state: RlsPolicyState },
  AlterPolicy { key: RlsPolicyKey, state: RlsPolicyState },
  DropPolicy { key: RlsPolicyKey },
  ```
- **Ordering:** `EnableRls` before `CreatePolicy`, `DropPolicy` before `DisableRls`.
- **Diff logic:** Compare policy keys and states exactly like grants.

#### C3. RLS introspection
- **Files:** `crates/pgroles-inspect/src/` — new `rls.rs` module
- **Queries:**
  ```sql
  -- Enabled tables
  SELECT schemaname, tablename FROM pg_tables
  WHERE rowsecurity = true AND schemaname = ANY($1);

  -- Policies
  SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
  FROM pg_policies WHERE schemaname = ANY($1);
  ```
- **Parsing:** `pg_policies.roles` is a text array; map to role names. `cmd` is one of `ALL`, `SELECT`, `INSERT`, `UPDATE`, `DELETE`.

#### C4. RLS SQL generation
- **Files:** `crates/pgroles-core/src/sql.rs`
- **SQL patterns:**
  ```sql
  ALTER TABLE "schema"."table" ENABLE ROW LEVEL SECURITY;
  CREATE POLICY "policy_name" ON "schema"."table"
    AS PERMISSIVE FOR ALL TO "role"
    USING (expr) WITH CHECK (expr);
  ALTER POLICY "policy_name" ON "schema"."table" USING (new_expr);
  DROP POLICY "policy_name" ON "schema"."table";
  ALTER TABLE "schema"."table" DISABLE ROW LEVEL SECURITY;
  ```

### Phase D: Cloud Auth & Extended Integrations (Future)

These are documented for completeness but should not block the initial phases.

#### D1. Cloud auth provider model
- **Design concept:**
  ```yaml
  auth_providers:
    - type: cloud_sql_iam
      project: my-gcp-project
    - type: rds_iam
      region: us-east-1
    - type: vault
      mount: database/postgres-prod
  ```
- **What it would do:** Auto-detect IAM-mapped role names, validate role naming conventions, set `rds_iam` attribute on RDS IAM roles.
- **Not urgent:** Users can work around this by manually specifying the IAM-mapped role names in memberships today.

#### D2. Vault integration
- **Design concept:** Generate a Vault-compatible creation statement template from the pgroles manifest. The tool would output:
  ```sql
  CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
  GRANT "inventory-editor" TO "{{name}}" WITH INHERIT TRUE;
  ```
- **This is an export format**, not a runtime integration.

---

## 4. Architecture Recommendations

### 4.1 Avoid breaking the core abstraction

The current architecture is clean:
```
YAML → PolicyManifest → ExpandedManifest → RoleGraph (desired)
                                                ↓ diff()
DB   → pg_catalog queries → RoleGraph (current) → Vec<Change> → SQL
```

All new features (RLS, reconciliation modes, version detection) should plug into this pipeline without restructuring it. Specifically:

- **RLS** extends `RoleGraph` with new fields, extends `Change` with new variants, extends introspection with new queries, and extends SQL generation with new renderers. The diff engine pattern (compare current vs desired by key) is reused unchanged.
- **Reconciliation modes** are a post-filter on `Vec<Change>`, not a change to the diff algorithm.
- **Version detection** is a context parameter to SQL generation, not a change to the model.
- **Export** is a `RoleGraph → PolicyManifest` function — the reverse of `from_expanded`.

### 4.2 Keep the crate boundaries

The 4-crate split is correct:
- `pgroles-core`: Pure, no IO, testable without a database
- `pgroles-inspect`: Database-dependent, async
- `pgroles-cli`: Binary, thin orchestration layer
- `pgroles-operator`: Kubernetes-specific

New code should go in the right crate:
- RLS model/diff/sql → `pgroles-core`
- RLS introspection → `pgroles-inspect`
- Export command → `pgroles-core` (conversion logic) + `pgroles-cli` (subcommand)
- Version detection → `pgroles-inspect` (query) + `pgroles-core` (SQL context)

### 4.3 Testing strategy

The existing test strategy is sound:
- **Unit tests** (inline `#[cfg(test)]`): model, diff, SQL rendering, manifest parsing
- **Integration tests** (`tests/cli.rs`): CLI binary execution, fixture-based
- **Live DB tests** (`#[ignore]`): require `DATABASE_URL`, run in CI with PG service
- **E2E tests** (kind cluster): operator reconciliation

New features should follow the same pattern. In particular:
- **RLS**: unit tests for diff and SQL, live DB tests for introspection + round-trip
- **Export**: unit test for `RoleGraph → manifest → RoleGraph` round-trip
- **Version detection**: unit tests with mocked version numbers

### 4.4 What NOT to build

Based on the prior art analysis, these are explicit non-goals to avoid scope creep:

- **GUI / web dashboard** — That's Bytebase territory. pgroles is a CLI/operator tool.
- **Schema DDL management** — That's SchemaHero / migration tool territory. pgroles manages authorization, not schema.
- **Multi-database orchestration in a single manifest** — The ROADMAP correctly identifies this as a future concern. One manifest = one database connection.
- **Password management** — Vault handles this better. pgroles should not store or template passwords.
- **LDAP/SCIM sync** — Enterprise feature, out of scope for v0.x.

---

## 5. Sequencing & Dependencies

```
Phase A (Brownfield + CI/CD)
├── A1: Drift exit code (no deps)
├── A2: JSON output (no deps)
├── A3: Generate/export (depends on A1/A2 for testing convenience)
└── A4: PG version detection (no deps, but inform C3)

Phase B (Adoption Safety)
├── B1: Reconciliation modes (no deps)
├── B2: Cloud-PG detection (no deps)
└── B3: Default priv validation (no deps)

Phase C (RLS) — can start after A is stable
├── C1: RLS model (no deps)
├── C2: RLS diff (depends on C1)
├── C3: RLS introspection (depends on C1, A4)
└── C4: RLS SQL gen (depends on C1, C2)

Phase D (Future)
└── After C is stable
```

Phases A and B can be worked in parallel. Phase C should start after Phase A stabilizes. Phase D is intentionally deferred.

---

## 6. Summary

pgroles has already solved the hardest problems in this space: correct `ALTER DEFAULT PRIVILEGES` semantics, a convergent diff engine with deterministic output, PG 16 grant syntax, and a clean Rust architecture. The remaining gaps are:

1. **Brownfield adoption** (`generate` command) — biggest adoption blocker
2. **CI/CD integration** (JSON output, drift exit codes) — table stakes
3. **Incremental adoption** (additive reconciliation mode) — trust builder
4. **RLS policy management** — unique competitive differentiator
5. **Cloud-managed PG safety** — better error experience

None of these require architectural changes. They all plug cleanly into the existing pipeline.
