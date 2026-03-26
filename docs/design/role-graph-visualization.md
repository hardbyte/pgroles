# Design: Role Graph Visualization for `pgroles`

Status: accepted
Date: 2026-03-26

## Summary

Add a new CLI-first graph surface to `pgroles` that can visualize:

- the actual roles in scope
- membership hierarchy and inheritance/admin links
- privileges granted to those roles
- default privileges that will apply to future objects
- optionally, drift between desired and current state

The recommended delivery path is:

1. add a pure visualization data model in `pgroles-core`
2. add `pgroles graph` to the CLI
3. ship `json`, `dot`, `mermaid`, and `tree` output first
4. add an interactive browser viewer later, driven by the same JSON export

This keeps the first version aligned with the existing CLI/operator product shape, avoids adding a credentialed web service, and reuses the existing `RoleGraph` model rather than inventing a second representation.

## Problem

`pgroles` already models roles, memberships, grants, and default privileges as a normalized `RoleGraph`, but the current user-facing inspection surface is minimal. `pgroles inspect` prints only counts, which is useful as a health check but not as a debugging or review tool.

That leaves several common questions harder to answer than they should be:

- Which login roles inherit which group roles?
- Which principals are external versus managed by `pgroles`?
- Which schemas and object types does a given role actually reach?
- Where do default privileges come from, and who receives them?
- What exactly will change when a diff is applied?

This is already called out implicitly in the roadmap: make `inspect` and generated exports easier to use as normalized graph/debugging surfaces.

## Goals

- Visualize role membership and privilege structure from the existing `RoleGraph`.
- Support both desired state and live current state.
- Support a diff-oriented view later without changing the underlying data model.
- Keep output deterministic and scriptable.
- Make the first implementation usable from the CLI and CI, not only from a browser.
- Keep the architecture pure in `pgroles-core` and thin in `pgroles-cli`.

## Non-goals

- A write-capable admin UI.
- Direct browser connections to PostgreSQL.
- A long-running server process inside `pgroles`.
- Replacing `diff` SQL output or plan summaries.
- Visualizing every database object individually by default on large schemas.

## Current State

`pgroles` already has the right model boundary for this feature:

- `pgroles-core` owns `RoleGraph`, with roles, grants, default privileges, and membership edges.
- `pgroles-inspect` already builds `RoleGraph` from a live database, both scoped and unscoped.
- `pgroles-cli` already has the manifest/database loading paths needed for `desired`, `current`, and later `diff` graph modes.

The gap is presentation, not data acquisition.

## User Stories

### 1. Brownfield review

An engineer runs:

```bash
pgroles graph current --database-url postgres://... --scope all --format dot > roles.dot
```

They can see group roles, login roles, external IAM-style principals, and the access bundles attached to each.

### 2. Manifest authoring review

An engineer runs:

```bash
pgroles graph desired -f pgroles.yaml --format mermaid
```

They paste the output into a PR comment or internal docs to review intended role structure before applying.

### 3. Drift review

An engineer runs:

```bash
pgroles graph diff -f pgroles.yaml --database-url postgres://... --format html -o plan.html
```

They inspect which edges and nodes are planned additions, removals, or flag changes.

### 4. Terminal-only quick review

An engineer runs:

```bash
pgroles graph desired -f pgroles.yaml
```

Without specifying a format, they get an indented text tree on stdout showing role hierarchy, grants, and default privileges — useful for a quick sanity check without leaving the terminal.

### 5. Operator troubleshooting

A future operator-oriented surface can reuse the same JSON graph artifact and render it in docs or another static frontend without re-querying PostgreSQL from the browser.

## Options Considered

### Option A: Extend `inspect` with better text-only output

Pros:

- smallest implementation
- no new rendering formats
- easy to test

Cons:

- not actually graphical
- weak for dense grants and membership structure
- limited reuse in docs or PR review

Verdict:

Useful as a companion, but insufficient as the primary solution.

### Option B: CLI-first graph export

Pros:

- matches the current product shape
- works in local dev, CI, and automation
- no server, auth, or credential storage concerns
- reuses existing manifest/inspect paths
- easy to version and diff in generated artifacts

Cons:

- interactive UX is deferred unless an HTML viewer is added
- users may need external tooling for some formats

Verdict:

Recommended as the first implementation.

### Option C: Embedded docs-site viewer first

Pros:

- richer UX
- visually aligned with the existing docs site
- easier to make interactive

Cons:

- the docs app should not become the only runtime for a core inspection feature
- introduces frontend dependency and build decisions before the graph model is stable
- harder to use in CI and local automation

Verdict:

Good phase 2, not the first delivery vehicle.

### Option D: Live web UI backed by PostgreSQL

Pros:

- strongest interactive UX
- could support multi-database browsing later

Cons:

- adds auth, secret handling, deployment, and runtime maintenance
- significantly outside the current CLI/operator scope
- easy to overbuild before the graph model stabilizes

Verdict:

Not recommended for v1.

## Research Snapshot

All version checks below were verified on 2026-03-26.

### Existing repo constraints

- The docs app currently pins `next` `16.1.6`, `react` `18.2.0`, `react-dom` `18.2.0`, and `tailwindcss` `^3.2.1`.
- `npm view` on 2026-03-26 showed newer versions available: `next` `16.2.1`, `react` `19.2.4`, `react-dom` `19.2.4`, and `tailwindcss` `4.2.2`.

Implication:

The docs site is a valid future host for a viewer, but it is not the best place to anchor the first implementation of a core graph feature.

### Mermaid

- Verified version: `11.13.0`
- Strengths: easy text output, markdown-friendly, familiar to many users
- Weaknesses: limited interaction, less suitable for dense graphs, weaker control over large graph layout

Use in `pgroles`:

Keep as an export target for PRs and lightweight docs embeds, not as the primary interactive renderer.

### Cytoscape.js

- Verified version: `3.33.1`
- Strengths: graph-native library, JSON-friendly, layout support, filtering/selectors, browser interactivity without requiring React
- Weaknesses: interactive viewer work is still non-trivial, especially around layout tuning and collapsed nodes

Use in `pgroles`:

Best candidate for a future HTML viewer.

### ELKJS

- Verified version: `0.11.1`
- Strengths: good layered layout support for DAG-like structures, suitable for role-to-role and role-to-access graphs
- Weaknesses: adds layout complexity and browser payload

Use in `pgroles`:

Use with Cytoscape.js for the interactive viewer when we add one.

### React Flow

- Verified version: `12.10.1`
- Strengths: polished React-based node UI toolkit
- Weaknesses: better fit for editors and canvas-style apps than for a CLI-driven graph export surface

Use in `pgroles`:

Not the recommended first choice. It would couple the feature more tightly to the docs frontend without a strong product reason.

### Graphviz

- Local experiment confirmed `dot` is available in the current environment as Graphviz `12.2.1`.
- A trivial role/member/access graph rendered successfully to SVG.

Use in `pgroles`:

Excellent export target, but not a primary runtime dependency. `pgroles` should emit DOT text directly and let users render it with Graphviz if they want SVG or PNG.

## Experiment Notes

### Manifest expansion size

Running:

```bash
SQLX_OFFLINE=true cargo run -p pgroles-cli -- validate -f examples/multi-schema.yaml
```

produced:

- 8 roles
- 27 grants
- 6 default privileges
- 7 memberships

Conclusion:

Even a moderate example already creates enough edges that an object-per-node view will get noisy quickly. The default renderer should collapse grant targets by schema and object type, with optional expansion.

### Static rendering viability

Running:

```bash
printf 'digraph roles { rankdir=LR; "orders-editor" -> "orders-team@example.com" [label="member"]; "orders-editor" -> "orders.tables[*]" [label="SELECT,INSERT,UPDATE,DELETE"]; }' | dot -Tsvg
```

produced valid SVG immediately.

Conclusion:

DOT export is a low-risk, high-value first graphical output.

## Recommendation

Implement a new CLI-first `graph` surface with a stable intermediate JSON model.

### v1 recommendation

Ship:

- `pgroles graph desired`
- `pgroles graph current`
- output formats: `json`, `dot`, `mermaid`, `tree`
- default format: `tree` (immediate terminal value without requiring external tooling)

Defer:

- interactive HTML viewer
- direct docs-site integration
- operator-surfaced graph artifacts

### v2 recommendation

Add:

- `pgroles graph diff`
- `--format html`
- a client-side interactive viewer using Cytoscape.js + ELKJS

## Proposed CLI

```bash
pgroles graph desired -f pgroles.yaml                               # defaults to tree
pgroles graph desired -f pgroles.yaml --format json
pgroles graph desired -f pgroles.yaml --format dot > roles.dot
pgroles graph current --database-url postgres://... --scope all --format mermaid
pgroles graph current -f pgroles.yaml --database-url postgres://... --scope managed --format json
pgroles graph diff -f pgroles.yaml --database-url postgres://... --format html -o plan.html
```

### Subcommands

- `desired`: build from manifest expansion only. Requires `-f`.
- `current`: build from live database inspection. Requires `--database-url`. Also requires `-f` when `--scope managed` (to determine which roles are managed). When `--scope all`, no manifest is needed (uses `inspect_all()`).
- `diff`: compare desired and current and render drift visually. Requires both `-f` and `--database-url`.

### Flags by subcommand

| Flag | `desired` | `current` | `diff` |
|------|-----------|-----------|--------|
| `-f`, `--file` | required | required if `--scope managed` | required |
| `--database-url` | — | required | required |
| `--format` | optional (default: `tree`) | optional (default: `tree`) | optional (default: `tree`) |
| `-o`, `--output` | optional | optional | optional |
| `--scope` | — | optional (default: `managed`) | — |
| `--collapse` | optional | optional | optional |
| `--max-nodes` | optional | optional | optional |
| `--include-default-privileges` | optional | optional | optional |
| `--include-external-principals` | optional | optional | optional |

## Visualization Model

Add a new pure module in `pgroles-core`, for example `visual.rs`, that converts `RoleGraph` into a graph-oriented DTO.

### Top-level DTO

```rust
pub struct VisualGraph {
    pub meta: VisualMeta,
    pub nodes: Vec<VisualNode>,
    pub edges: Vec<VisualEdge>,
}
```

All DTO types derive both `Serialize` and `Deserialize` so that the JSON format is a stable interchange boundary consumable by external tooling and the future HTML viewer.

### Metadata

```rust
pub struct VisualMeta {
    pub source: VisualSource,
    pub role_count: usize,
    pub grant_count: usize,
    pub default_privilege_count: usize,
    pub membership_count: usize,
    pub collapsed: bool,
}
```

### Node kinds

- `Role`
- `ExternalPrincipal`
- `GrantTarget`
- `DefaultPrivilegeTarget`
- `Database`
- future: `RlsPolicy`

### Edge kinds

- `Membership`
- `Grant`
- `DefaultPrivilege`
- future: `DriftAdd`
- future: `DriftRemove`
- future: `DriftModify`

### Stable IDs

Use deterministic IDs so tests and exported artifacts stay stable:

- `role:<name>`
- `external:<name>`
- `grant:<object_type>:<schema_or_db>:<name_or_star>` — for database-level grants where there is no schema, use the database name in the `schema_or_db` position (e.g. `grant:database:mydb:mydb`)
- `default:<owner>:<schema>:<object_type>:<grantee>` — one node per default privilege *rule* (owner + schema + object type + grantee combination). The individual privilege verbs (SELECT, INSERT, etc.) are attributes on the node, not separate nodes.

### Labels and attributes

Each node and edge should carry enough structured data for both text renderers and future HTML rendering:

- node label
- kind
- whether the node is managed
- whether a role is `LOGIN`
- membership flags: `inherit`, `admin`
- privilege lists
- schema/object type context
- optional comment snippet

## Default Graph Semantics

### Roles

- Managed roles are primary nodes.
- External principals referenced only by memberships are rendered as `ExternalPrincipal` nodes.
- Login roles should be visually distinguishable from group roles.

### Memberships

- Render `role -> member` edges, matching the existing `MembershipEdge` semantics.
- Show `inherit=false` and `admin=true` explicitly in edge labels or badges.

### Grants

Default behavior should collapse grants by schema and object type.

Examples:

- `orders.schema`
- `orders.tables[*]`
- `orders.sequences[*]`
- `orders.functions[*]`
- `mydb.database`

This keeps the graph legible even when a role has many wildcard grants.

### Default privileges

Default privileges need distinct treatment because they are future-facing and owner-scoped.

Recommended rendering:

- create a node like `defaults: migration_runner -> orders.tables`
- connect that node to the grantee role with a `DefaultPrivilege` edge

This makes owner context explicit and avoids confusing default privileges with current object grants.

## Diff View Semantics

The visual diff should not reuse raw `Change` operations directly as the render model. Instead, it should compare normalized visual nodes and edges and annotate them with state:

- `unchanged`
- `added`
- `removed`
- `modified`

Recommended visual treatment (following the palette defined in `docs/BRAND.md`):

- **stone**: unchanged — neutral background
- **teal**: additions — control-plane / informational accent
- **amber**: removals and flag changes — plan/change emphasis accent

Do not rely on color alone. Add textual badges such as `+`, `-`, or `changed`.

## Rendering Targets

### JSON

Purpose:

- stable machine-readable interchange format
- foundation for all other renderers
- future docs viewer input

Must be:

- deterministic
- versioned
- documented

### DOT

Purpose:

- immediate graphical value
- easy SVG/PNG generation with Graphviz
- useful in CI and docs pipelines

Notes:

- generate DOT directly from Rust
- do not make Graphviz a build-time or runtime dependency of `pgroles`

### Mermaid

Purpose:

- PR comments
- markdown embeds
- lightweight docs integration

Notes:

- best-effort layout only
- suitable for smaller graphs or collapsed views

### Tree

Purpose:

- immediate terminal-only value
- quick sanity check without requiring external tooling
- default output format when `--format` is omitted

Notes:

- indented text tree showing role hierarchy, grants, and default privileges
- use Unicode box-drawing characters for structure
- trivial to implement, fills the gap between "counts only" (`inspect`) and "needs external tooling" (DOT/Mermaid)

### HTML

Purpose:

- future interactive inspection

Notes:

- client-side only
- consumes `VisualGraph` JSON
- preferred stack: Cytoscape.js + ELKJS
- if embedded in `docs/` later, follow the existing docs diagram palette and interaction style rather than introducing a separate visual system

## Crate Placement

### `pgroles-core`

Add:

- `visual.rs`
- DTO types
- `RoleGraph -> VisualGraph` transformation
- DOT, Mermaid, and tree renderers

Why:

- all of this is pure and deterministic
- easy to unit test
- reusable by CLI, operator, and future viewers

### `pgroles-cli`

Add:

- `graph` subcommand
- loader/orchestration for desired/current/diff modes
- output writing

Why:

- matches existing command architecture
- keeps database connection logic in CLI, not in the viewer

### `docs/`

Later:

- optional example viewer page
- optional upload/paste JSON demo

Why later:

- the graph model and export format should stabilize first

## Testing Strategy

### Unit tests in `pgroles-core`

- stable node and edge ordering
- expected collapsed nodes for wildcard grants
- correct treatment of external principals
- correct default privilege node synthesis
- DOT and Mermaid snapshot tests on small fixtures
- tree output snapshot tests

### CLI tests

- command wiring
- output format selection
- `desired` mode against example manifests
- `current` mode can be covered where existing integration tests already use PostgreSQL

### Manual verification

- generate DOT from `examples/multi-schema.yaml`
- render with Graphviz to confirm readability
- verify Mermaid output remains readable for small examples
- verify tree output is readable in a standard terminal

## Implementation Plan

### Phase 1: Pure graph export

- add `VisualGraph` DTOs in `pgroles-core`
- implement `RoleGraph -> VisualGraph`
- add JSON output
- add tree output

Exit criteria:

- stable JSON for `desired` graphs
- unit tests cover collapsing and external principals
- tree output works as default format

### Phase 2: Static graph outputs

- add DOT renderer
- add Mermaid renderer
- add `pgroles graph desired`
- add `pgroles graph current`

Exit criteria:

- sample manifests render correctly
- docs can show examples using generated Mermaid or rendered SVG

### Phase 3: Diff overlay

- add visual diff model
- add `pgroles graph diff`

Exit criteria:

- additions, removals, and membership flag changes are visually distinguishable

### Phase 4: Interactive viewer

- add HTML renderer or a small static viewer app
- use Cytoscape.js + ELKJS
- add filtering and collapse/expand controls

Exit criteria:

- users can inspect medium-sized graphs interactively without scrolling through raw SQL

## Risks and Mitigations

### Risk: graph explosion on real databases

Mitigation:

- default collapsed grant targets
- optional `--max-nodes`
- optional filtering by role or schema in the HTML viewer later

### Risk: confusing current grants and default privileges

Mitigation:

- separate node/edge kinds
- distinct labels and visual treatment

### Risk: over-coupling to the docs frontend

Mitigation:

- make JSON the system boundary
- keep v1 CLI-first

### Risk: turning this into a second planning engine

Mitigation:

- derive visualization strictly from `RoleGraph` and, for diff mode, from normalized node/edge comparisons
- do not create graph-only business rules that diverge from diff/apply behavior

## Open Questions

- Should `current --scope all` become a first-class top-level inspect/export mode outside `generate`, or stay graph-specific?
- Should `graph diff` visualize only structure, or also planned SQL operations such as retirements?
- Should HTML be self-contained, or should it load a local JSON file into a static viewer page?

## Decision

Proceed with a CLI-first graph export feature centered on a new pure `VisualGraph` model in `pgroles-core`.

Implement `json`, `dot`, `mermaid`, and `tree` first, with `tree` as the default format.

Plan for an interactive browser viewer later, backed by the same JSON format and implemented with Cytoscape.js + ELKJS.

## References

- `RoleGraph` and membership/default privilege structures in the existing codebase
- `docs/BRAND.md` for the stone/amber/teal color palette
- roadmap item to make `inspect` and exports better graph/debugging surfaces
- local experiments on 2026-03-26:
  - `cargo run -p pgroles-cli -- validate -f examples/multi-schema.yaml`
  - `dot -V`
  - trivial DOT-to-SVG render
- official docs and project sites:
  - Graphviz: <https://graphviz.org/>
  - Mermaid configuration and security docs: <https://mermaid.js.org/config/configuration>, <https://mermaid.js.org/community/security.html>
  - Cytoscape.js: <https://js.cytoscape.org/>
  - React Flow: <https://reactflow.dev/>
  - Next.js support policy: <https://nextjs.org/support-policy>
