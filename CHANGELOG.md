# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Promotion: a reviewed candidate's approval now gates the merge that makes its content the desired state.** When a `PostgresPolicy` reconciles, the operator computes the canonical digest of the policy's own content — the same encoding, over the same canonical form, as a candidate's `status.contentDigest`, so promoting a candidate's content verbatim yields an identical digest — and publishes it as `status.content_digest`. If it matches a non-terminal candidate whose plan is **approved**, that plan becomes the policy's plan for this transition: the operator adopts the reviewed artifact rather than minting an approval of its own, and runs it through the existing approved-plan path, which under the database lock re-inspects, recomputes the canonical effects and executes only if the recomputed change digest equals the approved one. The property is unchanged from ordinary approval — *the statements executed are exactly the approved canonical effects, recomputed under the lock* — and promotion adds no new trusted step. On success the candidate becomes `Promoted=True` (terminal), its plan reaches `Applied`, and any other candidate sitting on an approved plan has that plan retired with `SupersededByPromotion`, leaving its write-once decision record untouched. Every other case is reported rather than silently ignored: content matching a candidate whose plan is not approved falls back to the ordinary manual-plan flow with `Promoted=False, reason=PromotedWithoutApproval` (and promotes once that fresh plan is approved and applied); content edited or rebased after approval falls back with `Promoted=False, reason=PromotionDigestMismatch`, whose message names the enforcement gap plainly — nothing executed, but the merged spec is the desired state and is not being converged until a fresh plan is approved; content matching no candidate is simply the ordinary policy flow. Under `approval: auto` the gate is trivially satisfied and promotion executes immediately, with the candidate still reaching `Promoted`; under `mode: observe` nothing ever executes, so a promoted candidate reports `Promoted=False, reason=PromotionNotExecuted` and stays open until the policy is switched to `mode: apply`. Recognition is by digest rather than by a one-shot transition, so an interrupted reconcile records the promotion on the next pass. There are still no `pgroles candidate` subcommands: a faithful digest must be computed over the operator's typed content model, and a second implementation would be a second definition of the thing the digest exists to make unambiguous — [the docs](https://hardbyte.github.io/pgroles/docs/operator-candidates/) give the `kubectl` and CI recipes instead. (#182, #173)

- **The operator now plans candidates.** A `PostgresPolicyCandidate` enqueues its parent `PostgresPolicy`, and is planned inside that policy's reconcile — same credentials, same advisory and in-process locks, after the policy's own enforcement or planning has completed, so the proposal is compared against post-enforcement reality rather than against drift the policy was about to remove. The result is a `PostgresPolicyPlan` owned by the **candidate** (so deleting the proposal prunes the plan and its SQL artifact), reviewed and decided exactly like any other plan, and bound to the candidate's name and UID, its content digest and encoding, the parent policy's UID, the target identity, the reconciliation mode and the approval-effect change digest. Candidate planning **writes nothing**: no SQL in any state, and no generated-password Secret — `password.generate` resolves through the same read-only path a policy uses (#181), so an unmaterialised credential contributes its `:missing` sentinel to the digest and the Secret is still created only when a policy executes. Revalidation reuses the policy's own semantics: an identical change digest retains the plan and any decision on it, a changed digest supersedes with a cause, and effects that vanished clear the plan. While the parent is failing or holds changes of its own awaiting a decision, the candidate reports `Ready=False, reason=BlockedByActivePolicy` and is replanned when the parent recovers. `spec.replaces` marks the named predecessor `Superseded` once the successor is planned, and an ephemeral overlay whose `(role, object)` effect pairs intersect the candidate's supersedes the plan with `OverlayOverlap` for fresh review — non-overlapping ephemeral traffic leaves the digest identical and the plan standing, so candidates stay usable on policies with continuous ephemeral activity. Terminal candidates enter a bounded retention loop; `pgroles.io/keep=true` exempts an object (candidates and plans alike). (#182, #173)

- **`PostgresPolicyCandidate`, a spec-immutable proposal of policy content.** `spec.content` carries the exact policy-content schema — everything a `PostgresPolicy` declares about PostgreSQL, and nothing about how or when it is executed. Interval, mode and approval always come from the parent policy; the connection does too, unless `spec.target.connectionRef` overrides it to preview a migration destination. The whole spec is immutable, enforced by the API server itself (`self == oldSelf`), so a reviewer never has to adjudicate which version was approved. `spec.content` deliberately emits **no OpenAPI defaults**: a schema default is materialised into the stored object at write time, so a later change to a default value would leave a stored candidate meaning something different from the identical source YAML — and its content digest would stop matching the digest computed from that YAML. Serde-level defaults are unchanged, so omitted fields still resolve exactly as they do for a policy. This release adds the API, the canonical content digest (`pgroles.io/candidate-content/v1`) and the RBAC; the reconciler lifecycle follows. (#182, #173)

- **Plans are now bound to the database they were computed against, not just to the Kubernetes reference that reached it.** `DatabaseIdentity` is a Secret name and key; repointing that Secret at a different server left plan, conflict and lock identity unchanged, so an approval made against one server could execute against another. Every plan now records and binds *two* complementary identities: the **physical** one, `pg_control_system().system_identifier`, which answers "same storage lineage?" — it survives failover to a replica and catches a restore taken from elsewhere — and the **logical** one, a fingerprint of the resolved host, port and database, which answers "same endpoint?" and catches the clone, branch and replica confusion the physical identifier cannot see (replicas, PITR restores, Aurora clones and Neon branches all inherit their parent's `system_identifier`). A change in either fails closed, and so does a *downgrade*: an identifier that was readable at approval and is not at execution supersedes rather than quietly falling back, so revoking `EXECUTE` cannot buy a weaker binding. Consistent unavailability is the ordinary path for engines that only speak the PostgreSQL protocol (CockroachDB, Spanner's PostgreSQL interface, Redshift, Aurora DSQL); no mainstream managed PostgreSQL restricts `pg_control_system()`, which has been `PUBLIC`-executable since 9.6. Set `spec.connection.requirePhysicalIdentity: true` where a real PostgreSQL is expected and the loss of the physical half should stop reconciliation (`TargetIdentityBlocked` condition) rather than weaken it silently. The identities appear on plan status as `targetPhysicalIdentity`, `targetLogicalFingerprint` and `physicalIdentityAvailable`. (#180, #173)

### Changed

- **BREAKING: `spec.mode: plan` is renamed to `spec.mode: observe`.** The CRD enum simply changes — `plan` is no longer accepted, with no alias or shim (pre-1.0). After the rename, "plan" names exactly one artifact: the `PostgresPolicyPlan` resource. The `ApprovalIgnored` condition reason `PlanModeNeverExecutes` is renamed to `ObserveModeNeverExecutes`, and status/event messages now say `observe` where they named the mode. **Upgrade note:** update policies that set `mode: plan` to `mode: observe` before installing the new CRDs; the API server will reject the old value. Stored objects written before the rename still *deserialize*: the operator accepts the legacy `plan` value on read only, so existing objects keep reconciling and their status is rewritten to say `observe`. Apply the new CRDs before or together with the operator upgrade; a stored `spec.mode: plan` object must be updated to `observe` before its next spec write, which the API server will otherwise reject.

- **Every collection and string in policy content now carries an explicit size limit. This is a breaking change.** The bounds are on the shared content type, so they apply to `PostgresPolicy` as well as to candidates, and to the CLI as well as to the CRD: identifiers (role, schema, owner and member names) `63` characters — PostgreSQL's `NAMEDATALEN - 1`, beyond which the server silently truncates — object names and comments `256`, config values `256`; `roles` `1024`, `grants` `4096` (`privileges` `16` each), `memberships` `512` (`members` `256` each), `default_privileges` `512` (`grant` `16` each), `schemas` `256`, `retirements` `512`, `profiles` `64` entries (`grants` `64`, `default_privileges` `32`), and `config` `32` entries per role or profile. **Upgrade note:** a policy exceeding any of these is rejected on its next apply, by the API server and by `pgroles validate` alike. The limits sit an order of magnitude above any policy we have seen. Every object was already bounded by the ~1.5MiB etcd cap; that limit simply produced an opaque `etcdserver: request is too large` instead of a field-level error. Making the bounds explicit is also what makes whole-spec CEL immutability admissible on candidates, and unblocks CEL validation on `PostgresPolicy` itself, which was impossible while the schema was unbounded. (#182, #173)

- **The approval-effect encoding is now `pgroles.io/approval-effect/v2`.** It binds the resolved target identity described above, which the v1 encoding did not. **Upgrade note: every change digest changes once.** Digests from different encodings are never comparable, so on first reconcile after the upgrade each open plan is superseded and replaced by an equivalent plan under v2, and any decision already recorded on it does not carry over — those plans need one fresh approval. Nothing executes in the meantime, and nothing else about a policy changes. This also affects live systems in one further, deliberate way: a **major version upgrade** (`pg_upgrade` runs a fresh `initdb`, minting a new `system_identifier`) and a **blue-green cutover** both move the target identity, and will correctly invalidate any approval open across them. Re-approve the fresh plan afterwards. (#180)
- **URL-mode connections now bind the endpoint they resolve to, not only the Secret they read.** Previously the digest bound `{secret.name}/{key}` for a `secretRef` connection, so editing the URL inside that Secret was invisible to the approval identity. The resolved host, port and database are now bound for both connection modes. Credentials and connection options remain excluded, so password and token rotation still do not invalidate an open approval. (#180, #185)

- **Generated password Secrets are no longer created before a plan is approved.** For a `password.generate` role under `apply` + `approval: manual`, resolving the password used to create the Kubernetes Secret during reconciliation — while the plan was still awaiting a decision — so a plan that was rejected, or simply never approved, still left a live credential in the cluster. Password resolution is now non-mutating in every mode: an existing Secret is read, a missing one resolves to in-memory material, and the Secret is created only as the approved plan executes, immediately before the SQL transaction. If a Secret already exists at that point (another replica, or an earlier interrupted attempt), the database is set from *its* password rather than the freshly generated one. **Upgrade note:** nothing to migrate — existing generated Secrets are read and reused, and `approval: auto` is unchanged in observable behaviour, since planning and execution happen in the same reconcile. Under `approval: manual` the Secret now appears when the plan applies rather than when it is proposed. (#181, #174)
- **A generated Secret that disappears now says so before the password rotates.** Deleting the Secret has always made the next plan regenerate and rotate the password, which is the intended recovery — it just happened silently. The policy now emits a `GeneratedSecretMissing` Warning Event naming the Secret and the role. (#181)

- **`PostgresPolicy` now tells Kubernetes which field identifies an entry in `spec.schemas`, `spec.roles`, and `spec.retirements`.** They are lists of named objects, but the CRD emitted them as plain arrays, so the API server treated each list as an opaque unit: server-side apply replaced the whole list rather than merging per entry, and duplicate names were accepted. They are now map-lists keyed by `name`, `name`, and `role` respectively. **Upgrade note:** a manifest containing two entries with the same key in one of those three lists is now rejected by the API server at `kubectl apply` time. Such a manifest was never applied silently — the API server accepted the write, and the policy then failed to reconcile, because `expand_manifest` rejects duplicate schemas, roles, and retirements. The rejection simply moves from reconcile time, where it surfaced as a policy that would not converge, to admission time, where it surfaces as a failed write. `memberships`, `grants`, and `default_privileges` are deliberately left as plain arrays: the same role legitimately appears across several `memberships` entries, and the natural keys for the other two are composite. (#126)

### Fixed

- **The plan approval documentation now describes the mechanism that exists.** The page three other docs route users to as *the* approval reference told them to run `pgroles plan approve`, set `mode: observe`, and treat the shipped semantic change digest, pending-plan revalidation and deferred generated Secrets as unbuilt — none of which was true in either direction. It now documents the only decision mechanism there is (a write to the plan's status subresource recording a terminal `Approved` or `Denied` condition together with `decidedBy`), with copy-pasteable `kubectl` commands for both approval **and** rejection, the two admission layers that make `decidedBy` mean anything, and a reference table for every plan status field. Its forward-looking callout now lists exactly the things that genuinely remain unbuilt: the `pgroles plan` / `pgroles candidate` subcommands, an `approvedChangeDigest` token, and candidate content by reference. (#184, #173)
- **A superseded plan now says why it was superseded.** Every supersede wrote the same `Approved=False` message — "Database state changed since plan was approved" — which named the least common cause and misdescribed the rest: an effect-neutral policy edit, effects that vanished before a decision, replacement by a newer plan, or a moved target all read as a database change the reviewer then went looking for. Each call site now names its own cause, carried on a `Superseded=True` condition, and a moved target reports the target-identity reason (`TargetChanged`, `TargetIdentityUnavailable`, `TargetIdentityAppeared`) rather than the generic `Superseded`. (#184)
- **`kubectl get pgplan -o wide` now surfaces the change digest.** The wide output showed `Hash` — `status.sqlHash`, a diagnostic for the preview text — while the value a decision actually binds had no column at all. A `Digest` column reading `.status.changeDigest` joins it. (#184)

- **Retiring a plan no longer tries to rewrite the decision recorded on it.** Every supersede path wrote `Approved=False`, which the plan CRD rejects on any plan a human actually decided: a recorded decision is terminal, and clearing it would leave a `decidedBy` with no decision beside it. Against a real API server the patch failed, so a plan whose effects changed after approval stayed actionable instead of being retired. A plan is now voided by its **phase** alone — `Superseded`, with the cause on a `Superseded=True` condition — and the decision record is left exactly as the reviewer left it. Execution gates on phase plus a fresh digest match, so a superseded plan is never selected however its conditions read. A plan nobody decided still carries the cause on its `Approved=False` condition. (#185, #182)
- **The operator's RBAC now covers the candidate writes it actually performs.** The chart's ClusterRole and `k8s/deploy/rbac.yaml` granted only `get`/`list`/`watch` on `postgrespolicycandidates`, while the reconciler patches a candidate's `ownerReferences` to adopt it and deletes terminal candidates beyond the retention bound. Both verbs are now granted. (#182)
- **A crash mid-replacement no longer leaves a policy with no plan to act on.** Plan creation documents the rule that the plan it replaces is retired only once the replacement is visible, and both replace paths in the reconciler inverted it — superseding first, so a failure before the new plan materialised left the policy pointing at a plan nobody could approve. Retirement now happens in one place, after creation, and covers approved plans as well as pending ones: an approval whose effects have moved is voided along with its plan, while one that still describes the current effects is never discarded. (#185)
- **`status.current_plan_ref` no longer strands a reference on a plan that is gone.** Every path that concludes a policy has no outstanding work now clears the reference and then retires the plan it pointed at, in that order, so an interrupted reconcile leaves a pending plan the next pass finds rather than a reference to nothing. (#185)
- **A `spec.mode: observe` policy now revalidates when drift disappears out of band.** Observe mode only ever opens plans; when the database converged by other means the pending plan stayed Pending and `current_plan_ref` kept pointing at it while the policy reported `InSync`. It now supersedes that plan and clears the reference. (#185)
- **A change set held in its failure-retry window is no longer reported as awaiting approval.** When an identical change set has failed recently, the operator holds off on opening a new plan; the policy nonetheless claimed a plan was "created" and "awaiting approval" while pointing at a Failed plan with no decision to make. It now reports `PlanFailedRetryBackoff` and says so. (#185)

## [0.9.0] - 2026-08-14

### Added

- **Bounded, request-driven PostgreSQL memberships in Kubernetes.** `EphemeralAccessPolicy` defines a requestable bundle; immutable `EphemeralAccessRequest` resources resolve, activate, expire, and revoke one grant without touching the durable `PostgresPolicy`. **`approval.mode: Required` is only a real approval boundary under admission enforcement** — approving and otherwise managing a request are the same write to `ephemeralaccessrequests/status`, so RBAC alone cannot separate them. Deploy the CI-tested Kyverno profile in `k8s/security/`, or front the API with a trusted broker, before relying on it: [securing ephemeral access](https://hardbyte.github.io/pgroles/docs/ephemeral-access-security/) sets out the three trust postures. Requires PostgreSQL 16 or later. (#158)
- **A generated [Helm chart reference](charts/pgroles-operator/README.md) documenting every value.** Previously 14 of the 21 chart values were undocumented, including `serviceAccount.annotations` (required for GKE Workload Identity) and the `EPHEMERAL_ACCESS_MAXIMUM_DURATION` / `EPHEMERAL_ACCESS_MAX_PENDING_TTL` ceilings. Generated by helm-docs from `values.yaml`; CI fails if it drifts.
- **Approving a plan that can never execute is now reported.** A policy in `spec.mode: plan` never consults `spec.approval`, so annotating its plan is accepted and then does nothing — indistinguishable from a stalled operator. The policy now reports an `ApprovalIgnored` condition and a warning Event, pointing at `mode: apply` with `approval: manual`, which is the combination that gates an apply.
- **Namespace-scoped operator deployments.** The chart value `operator.watchNamespace` sets `WATCH_NAMESPACE`, which scopes every operator watch and conflict-detection list to one namespace, and switches the chart from `ClusterRole`/`ClusterRoleBinding` to a namespaced `Role`/`RoleBinding`. Unset, the operator remains cluster-scoped as before. (#162)

### Changed

- **Ephemeral-access reconciliation is now proportional to the requests relevant to one policy**, instead of listing and filtering every retained `EphemeralAccessRequest` in the namespace on each pass. The request controller's existing watch feeds a shared index keyed by access-policy name and by resolved access-policy and target-policy UID; effective-graph composition, access-policy triggers, and scoped cleanup read that index and the namespace-wide LIST calls are gone. Indexes and the controller-owned UID labels added alongside them are routing optimizations only — every authorization and ownership decision still verifies the immutable UIDs in `status.resolvedAccess`. New OTLP metrics report cache size, indexed lookup sizes, and ephemeral reconcile duration and concurrency by resource kind. (#162)

### Deprecated

- **Omitting `spec.approval` on a `PostgresPolicy`.** Behaviour is unchanged — the value is still inferred from `spec.mode` (`apply` → `auto`, `plan` → `manual`) — but the inference hides whether a human gates SQL execution behind an unrelated field, and `spec.mode` itself defaults to `apply`. Policies relying on it report an `ApprovalUnset` condition and increment `pgroles.deprecated.approval_unset`. **Migration:** write down the value you already get. A future release will reject the omission. (#73)

### Removed

- **`PostgresPolicy` status fields `planned_sql`, `planned_sql_truncated`, and `last_reconcile_time`.** Superseded by `PostgresPolicyPlan` in 0.5.0, but still written on every reconcile with pending changes. **Migration:** read plan SQL from the plan the policy points at — `kubectl get pgplan $(kubectl get pgr <policy> -o jsonpath='{.status.current_plan_ref.name}') -o jsonpath='{.status.sqlInline}'` — falling back to the gzipped ConfigMap in `status.sqlRef`, or a truncated `status.sqlInline` for plans too large for either. Replace `last_reconcile_time` with `status.last_successful_reconcile_time`. (#73)
- **`OperatorContext::new`**, in the `pgroles-operator` crate. It could not supply the shared request index the reconcilers now read, so a context built through it produced lookups that no watch ever fed. **Migration:** use `OperatorContext::new_with_runtime_config`, passing the `RequestIndex` fed by the request controller's watch and the optional watch namespace. (#162)

### Fixed

- **The operator no longer holds PostgreSQL connections open against every database it manages.** Connection pools are cached for the operator's lifetime and inherited sqlx's 10-minute idle timeout, which never elapsed against the 5-minute default requeue interval — each reconcile re-touched the pool first, and sqlx's FIFO idle queue spread those touches across every pooled connection. A pool that once peaked at N concurrent connections therefore occupied N backends indefinitely, per database, whether or not anything was reconciling. Pools now drain to zero between reconciles.

## [0.8.0] - 2026-08-02

### Fixed

- **Policy names longer than 63 characters no longer break plan creation, plan lookup, and cleanup.** Kubernetes caps label values at 63 bytes but allows resource names up to 253, and the operator conflated the two rules. Three defects followed. A sanitized label value truncated at the cap could land on a separator and be rejected outright, so the plan ConfigMap failed to write and the policy stopped reconciling (thanks @aarons-afk for the report and original fix, #146). `generate_plan_name` cut the policy-name prefix without trimming an exposed `.` or `-`, so the appended `-plan-…` began a new DNS label with a separator and the API server refused the plan. And `is_valid_secret_name` rejected `generatePassword.secretName` values beginning with a digit, which Kubernetes permits. All three rules now come from one module (`k8s_names`) that restates them once, with property tests over a hostile alphabet — including multi-byte UTF-8, which an earlier fix attempt silently truncated mid-character.
- **Plans and plan-SQL ConfigMaps are now matched to their policy by controller-owner UID rather than by a truncated label.** The `pgroles.io/policy` label carries at most 63 bytes of a name that may be 253, so two policies sharing a 63-byte prefix selected each other's plans and SQL ConfigMaps — cross-approving and cross-deleting them — and the plan→policy watch never matched for any longer name, so approvals and status transitions silently stopped waking the reconciler. The label remains as a server-side prefilter; identity is now the UID at every lookup, approval, and cleanup site, including the create-conflict path, which deletes a colliding non-owned ConfigMap instead of adopting it. **Upgrade note:** deleting a policy with `--cascade=orphan` strips the owner references this depends on, so orphaned plans are no longer re-adopted by a recreated policy of the same name and must be deleted by hand. See [limitations](https://hardbyte.github.io/pgroles/docs/limitations/).
- **Schema owner transfers no longer strip the incoming owner's privileges when a stale explicit grant exists.** `ALTER SCHEMA ... OWNER TO z` merges z's pre-existing explicit ACL entry into the new owner entry, so a same-plan `REVOKE` against that stale grant removed the *new owner's* USAGE — leaving the owner unable to resolve its own schema until the next reconcile. The diff engine now suppresses schema revokes whose grantee is that schema's incoming owner in the same plan; the state converges in a single pass. Proven by the live property suite, which previously had to exclude this shape. (#140)

### Added

- **Profiles can now declare `config` defaults for the roles they generate, with `{schema}`/`{profile}` placeholder substitution in values.** The same role-level `ALTER ROLE ... SET` config introduced below is now available on `profiles[].config`, so a per-schema `search_path` default (`config: { search_path: "{schema}" }`) can be declared once and expanded across every `schema x profile` binding instead of repeated per generated role. Placeholders substitute only in values — keys stay literal PostgreSQL parameter names, and the `config.role` membership cross-check applies to generated roles the same as hand-written ones. `pgroles generate --suggest-profiles` never clusters a `config`-carrying role into a profile, keeping it flat instead, since collapsing config maps modulo placeholder substitution risks silently changing what gets applied.
- **Roles can now declare configuration parameter defaults via `config`, managed with `ALTER ROLE ... SET`.** Keys are PostgreSQL setting names (including dot-qualified custom settings like `app.tenant`); values are always strings — quote numbers and booleans (`statement_timeout: "30000"`, `jit: "off"`) — and the same rule is enforced by both the CLI parser and the CRD schema, so a manifest means the same thing in both paths. Settings are diffed against the cluster-wide entries in `pg_roles.rolconfig`: authoritative and adopt modes `RESET` settings present on a managed role but absent from the manifest, while additive mode leaves config on pre-existing roles unchanged (config on newly created roles is still applied). Declaring `config: { role: <group> }` on blue/green login roles makes PostgreSQL `SET ROLE` at connect time, so objects created under either credential are owned by the shared group role and survive password rotation; when the target role is declared in the same manifest, pgroles validates that a matching membership is declared too. `pgroles generate` exports existing role config defaults for brownfield adoption. Per-database settings (`ALTER ROLE ... IN DATABASE`) are not managed. See [examples/zero-downtime-password-rotation.yaml](examples/zero-downtime-password-rotation.yaml). (#132)
- **New [executor privileges](https://hardbyte.github.io/pgroles/docs/executor-privileges/) and [limitations](https://hardbyte.github.io/pgroles/docs/limitations/) docs pages.** The former documents the minimal `CREATEROLE`-based grant set pgroles needs (verified against a live PostgreSQL 16 server), including the greenfield-vs-brownfield `ADMIN OPTION` distinction and a copy-pasteable bootstrap SQL block. The latter is a single-page, matter-of-fact list of what pgroles does not manage — column-level grants, per-database role settings, server configuration, extensions, row-level security, unmodeled grant object types (domains, FDWs, languages, tablespaces, large objects, publications/subscriptions), password drift, and database creation/ownership.
- **`diff` and `apply` now detect and warn about column-level grants in schemas whose privileges pgroles manages.** pgroles has never managed `GRANT SELECT (col) ON table ...` (it only reads `pg_class`-level ACLs, not `pg_attribute.attacl`), so column-level grants were a silent audit hole in authoritative mode — the manifest looked like the whole truth even when it wasn't. Inspection now aggregates column-level ACL entries per `(schema, relation, grantee)`, including grants to `PUBLIC`, and prints a warning listing the affected columns and privileges via `InspectionDiagnostics`. This is detection only: the grants are still not diffed, revoked, or exported by `generate`, and — unlike an `UnsatisfiableWildcardGrant`, which blocks reconciliation because desired state can't be computed — the warning never blocks `diff`/`apply` or operator reconciliation.

### Changed

- **Documented PostgreSQL version support as 16, 17, and 18 — the versions CI actually tests.** PG 14–15 code paths (the legacy `WITH ADMIN OPTION` grant syntax fallback) remain in the codebase but are now described as best-effort and untested rather than "supported," across the installation, quick start, memberships, architecture docs, and `ROADMAP.md`.
- **Documented a transaction-mode pooler caveat for role configuration defaults.** `config` (including `config.role`) is applied by PostgreSQL at connection start, so behind a pooler like PgBouncer it attaches to pooled server connections rather than individual clients; pooler reset queries do not remove it since PostgreSQL reapplies `ALTER ROLE ... SET` config on every (re)connect. See [role configuration defaults](https://hardbyte.github.io/pgroles/docs/manifest-reference/#role-configuration-defaults).

## [0.7.8] - 2026-06-04

### Added

- **Externally managed roles can now be marked `external: true`.** External roles may still be referenced in grants, schema ownership, default privileges, and as members of managed roles, but pgroles will not create, alter, drop, password-manage, or manage memberships granted from those roles. This avoids breaking Cloud SQL IAM users and groups whose `LOGIN` attribute and provider memberships are owned outside pgroles. (#123)
- **Operator reconciles can now be requested immediately with `pgroles reconcile` or the `reconcile.pgroles.io/requestedAt` annotation.** The CLI annotates a `PostgresPolicy` and can optionally wait until `status.lastHandledReconcileAt` records that the operator successfully handled the request. The operator also includes the annotation value in its watch predicate, so changing only the request timestamp triggers a reconcile without mutating the policy spec. (#118)
- **`pgroles render-bundle` composes a policy bundle into a single flat manifest.** Validates and composes the bundle (rejecting scope/ownership conflicts up front), then emits the resulting `PolicyManifest` as YAML with a provenance header recording the source bundle basename, the manifest schema version (`pgroles.manifest.v1`), and the fragments it composed. The output round-trips through `pgroles validate -f` / `diff -f` / `apply -f`, so a bundle can be composed in CI and the rendered manifest wrapped into a `PostgresPolicy` resource in a GitOps repo. Pre-rendering keeps cross-team and cross-environment fragment composition available to operator users without adding operator-side CRDs. The renderer is byte-deterministic across machines: the header records only the bundle file's basename (never an absolute or `pwd`-relative path), and the YAML body is post-processed to strip serde-emitted optional defaults (empty optional sequences, `null` scalars, and the default `role_pattern`) so the file doesn't churn under unrelated upgrades. Required fields like `Membership.members`, `Grant.privileges`, and `DefaultPrivilege.grant`, plus named empty profiles, are preserved even when empty so the rendered manifest always re-parses. `--check <path>` compares against an existing rendered file and exits with code 2 on drift, suitable as a CI gate that catches stale checked-in renders. The new [bundle composition guide](https://hardbyte.github.io/pgroles/docs/bundle-composition/) documents when to use each of the three workflows (single manifest, CLI bundle for direct apply, rendered bundle for the operator). Use `--no-header` to omit the header and `--output <path>` to write to a file. (#92)

## [0.7.7] - 2026-05-18

### Added

- **The operator can now `SET ROLE` to a privileged parent role on every pooled connection.** Set `connection.params.setRole: <role>` on a `PostgresPolicy` and the operator's sqlx pool runs `SET ROLE "<role>"` once via `after_connect`, so the session's `current_user` becomes that role and its attributes (`CREATEROLE`, `CREATEDB`, …) apply to every subsequent statement. This unblocks the "operator authenticates as a low-privilege identity (e.g. Cloud SQL IAM user via Workload Identity) that has been granted membership in `cloudsqlsuperuser`" pattern, where PostgreSQL's role membership semantics otherwise refuse role-attribute inheritance. The role identifier is validated at admission time against `^[A-Za-z_][A-Za-z0-9_$-]*$` via the CRD's OpenAPI `pattern`, and `SET ROLE` failures surface as a distinct `SetRoleFailed` status reason instead of being conflated with database connection failures. (#119, #120)

## [0.7.6] - 2026-05-14

### Fixed

- **Wildcard `GRANT EXECUTE` no longer flaps on schemas that contain procedures.** PostgreSQL's `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ...` does not cover procedures, but the inspector includes procedures in routine inventory. Function wildcard grants now render as `ALL ROUTINES`, and specific function/procedure grant and revoke targets render as `ROUTINE`, so manifests using `object.type: function` remain backward-compatible while converging on schemas with extension-installed procedures. (#113, #114)

## [0.7.5] - 2026-05-14

### Added

- **The operator can now authenticate to Cloud SQL with native GKE Workload Identity.** Structured connection params accept `auth.type: gcp_workload_identity`, fetch short-lived Cloud SQL IAM login tokens from the GKE metadata server, optionally impersonate a target Google service account through IAMCredentials, and refresh cached pools before token expiry. Static `password` / `passwordSecret` fields are mutually exclusive with provider-backed auth, and `sslMode` defaults to `require` for this mode. (#114, #115)

### Changed

- **Operator and manifest documentation are easier to validate and navigate.** The docs now include a dedicated manifest reference, a tooling guide with schema-validation examples, and Cloud SQL examples that cover native Workload Identity auth as well as proxy-based connectivity. (#111, #115)

## [0.7.4] - 2026-05-12

### Fixed

- **Wildcard `GRANT EXECUTE` on schemas with long function signatures no longer flaps.** The inventory queries (`fetch_object_inventory` and `fetch_object_inventory_for_wildcards`) `UNION ALL` their per-type rows. All branches except the function one project `object_name` as a PostgreSQL `name`-typed column (`c.relname`, `t.typname`, `n.nspname`, `db.datname`, 63-byte cap), while the function branch projects the text-typed `proname || '(' || identity_args || ')'`. PostgreSQL resolves the UNION result column to the common type — `name` — and silently truncates the text function signatures to 63 bytes. The wildcard satisfaction check in `normalize_wildcard_grants` then iterates the truncated inventory keys against the full-signature grant keys, treats every wildcard on a schema containing a long-signatured function as unsatisfied, and re-emits `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA … TO …` on every reconcile. Cast each `name`-typed `object_name` column to `text` so the UNION result is uniformly text. This closes the residual flap referenced in #105 for non-trivial function inventories (overloaded helpers, custom-typed arguments, extension defaults). (#109)

## [0.7.3] - 2026-05-12

### Fixed

- **Privilege inspection no longer returns PUBLIC / NULL grantee ACL entries.** Extension-installed functions (e.g. `partman`, `pg_stat_statements`) typically carry a `GRANT EXECUTE … TO PUBLIC` entry; previous inspection runs surfaced those PUBLIC rows alongside managed grantees, causing wildcard `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA … TO {role}` to be re-emitted every reconcile because the inspector couldn't reconcile a PUBLIC row against the managed grantee set. Privilege queries now restrict results to the managed-grantee set in SQL, so the wildcard converges. (#108)

### Changed

- **Inspection catalog queries are constrained to the wildcard scope.** `n.nspname = ANY(...)` predicates are added to each leg of inventory and grantability catalog queries so PostgreSQL can apply namespace filtering before joining the unnest scope rows. ACL filtering moves from Rust to SQL via `unnest(aclexplode(...))` with a managed-grantee predicate, reducing inspector wall time on large databases without changing observable behaviour. (#108)

## [0.7.2] - 2026-05-08

### Added

- **Operator OTLP metrics now expose database inspection cost.** The operator records inspection phase durations, inspected object counts, wildcard inventory size, unsatisfied wildcard scope counts, and grantability query/object counts so large-schema deployments can spot catalog-query regressions.

### Changed

- Wildcard diagnostics now avoid grantability catalog scans when current ACLs already satisfy the wildcard, and scope grantability checks to the unsatisfied wildcard schema/object-type pairs.

### Fixed

- **Unsatisfiable wildcard grants now fail with a clear diagnostic instead of re-planning forever.** A wildcard such as `function name: "*"` remains strict desired state: every matching object must either already have the requested privilege or be grantable by the executor. When a matching object is missing the privilege and the executor lacks the corresponding `WITH GRANT OPTION`, CLI `diff`/`plan`/`apply` now stop with `UnsatisfiableWildcardGrant` instead of printing or applying repeated wildcard SQL. The operator reports `Ready=False` and `Degraded=True` with the same reason, leaves no new `PostgresPolicyPlan` or SQL ConfigMap for that reconcile, and retries at the normal policy interval. (#105, #106)

## [0.7.1] - 2026-05-08

### Fixed

- **Wildcard grants no longer flap when an inventory object loses its ACL between reconciles.** When a desired manifest had a wildcard grant (e.g. `function name: "*"`) and an object in scope was `DROP`ped+`CREATE`d externally — for example by a service running its own migrations — the inspector's wildcard-collapse failed and `diff` emitted both a wildcard `GRANT ... ON ALL ... IN SCHEMA` and a per-name `REVOKE` for every previously-granted object. Apply order re-granted everywhere then stripped the previously-known set, the next reconcile observed the inversion, and the controller flapped indefinitely. `diff` now treats a desired wildcard as shadowing per-name revocations of the same privileges within the same `(role, schema, type)` scope; covers both wildcard-only and wildcard-plus-specific-extras manifest shapes. (#104)
- **Status starvation removed for cache-invalidating connection failures.** `reconcile_apply` previously held the in-process per-database lock across the connection probe, so `PostgresPolicy` resources sharing one credentials Secret could serialize on the lock during a Secret rotation to a bad URL — each lock-holder paying the full `POOL_ACQUIRE_TIMEOUT_SECS`. Lock contention requeues silently without updating the policy status, so an unlucky sibling could spend tens of seconds bouncing on the lock before publishing its `Ready=False/DatabaseConnectionFailed` condition. The connection probe now runs *before* lock acquisition, so failures surfaced at pool creation time (first reconcile, or after a Secret-resourceVersion / params-fingerprint cache invalidation) update status independently of concurrent reconciles for the same database target. Connection failures encountered inside the locked DDL phase against an already-cached pool are unaffected. (#104)
- **TLA+ model for wildcard-grant convergence** (`correctness/races/Convergence.tla`). Verifies eventually-permanent convergence under fairness and a finite number of external `DROP+CREATE`s, and produces the partly-dev15-shaped lasso counterexample under v0.7.0 semantics. (#104)

## [0.7.0] - 2026-05-06

### Added

- **`pgroles generate --suggest-profiles`** — deterministically refactor flat brownfield manifests into reusable profiles, with live database inventory checks before wildcard collapse so generated profiles do not broaden privileges. (#96)
- **`pgroles_core::suggest` public API** and `pgroles_inspect::fetch_object_inventory` for callers building their own brownfield profile-suggestion pipelines. (#96)

### Fixed

- **Large operator plan SQL previews no longer exceed Kubernetes ConfigMap limits.** Small redacted SQL previews remain inline, large previews are stored as gzip-compressed ConfigMap `binaryData`, and exceptionally large incompressible previews fall back to a truncated inline preview while apply continues to render executable SQL from the in-memory change set. (#98)
- **Status-less `PostgresPolicyPlan` resources and orphaned plan SQL ConfigMaps are cleaned up defensively.** The operator persists SQL artifacts before making plans visible, cleans stale status-less plans and orphaned SQL ConfigMaps before and after reconcile, and also collects stale policy-labeled SQL ConfigMaps left behind by older versions. (#99)
- **Plan storage correctness is modeled in TLA+.** The model covers persistence failure, the invariant that plans are not visible before their SQL artifact is ready, at-most-one actionable plan safety, and eventual cleanup of stale status-less plans and orphan SQL artifacts. (#98, #99)

### Changed

- **BREAKING: `PolicyManifest.profiles` is now `BTreeMap<String, Profile>`** (was `HashMap<String, Profile>`). YAML serialization is now deterministic — two `pgroles generate` runs against the same database produce byte-identical output. Library consumers that construct `PolicyManifest` directly will need to update their map type. The CLI and operator are unaffected. (#96)

## [0.7.0-beta.2] - 2026-05-06

### Fixed

- **Large operator plan SQL previews no longer exceed Kubernetes ConfigMap limits.** Small redacted SQL previews remain inline, large previews are stored as gzip-compressed ConfigMap `binaryData`, and exceptionally large incompressible previews fall back to a truncated inline preview while apply continues to render executable SQL from the in-memory change set. (#98)
- **Status-less `PostgresPolicyPlan` resources and orphaned plan SQL ConfigMaps are cleaned up defensively.** The operator persists SQL artifacts before making plans visible, cleans stale status-less plans and orphaned SQL ConfigMaps before and after reconcile, and also collects stale policy-labeled SQL ConfigMaps left behind by older versions. (#99)
- **Plan storage correctness is modeled in TLA+.** The new model covers persistence failure, the invariant that plans are not visible before their SQL artifact is ready, at-most-one actionable plan safety, and eventual cleanup of stale status-less plans and orphan SQL artifacts. (#98, #99)

## [0.7.0-beta.1] - 2026-05-05

### Added

- **`pgroles generate --suggest-profiles`** — deterministically refactor a flat brownfield manifest into reusable profiles. The suggester clusters roles whose grants share an identical *schema-relative signature* across multiple schemas, picks a uniform role-name pattern (`{schema}-{profile}` / `{schema}_{profile}` / `{profile}-{schema}` / `{profile}_{schema}`) so role names are preserved verbatim, and verifies round-trip equivalence against the flat manifest before committing. Re-runs on databases where a suggested manifest has already been applied are idempotent (auto-generated profile-role comments are recognised and ignored). (#96)
- **Live-DB inventory required for safe wildcard collapse** — the suggester only collapses per-name grants into wildcards (`name: "*"`) when given a complete object inventory from `pgroles_inspect::fetch_object_inventory`. The CLI fetches this automatically. A grant-only view would treat ungranted objects as nonexistent and could broaden privileges; the suggester now refuses to collapse if the provided inventory is missing any object that already appears in input grants. (#96)
- **`pgroles_core::suggest` module** — new public API: `suggest_profiles`, `SuggestOptions`, `SuggestReport`, `SuggestedProfile`, `SkipReason` (with variants `MultiSchema`, `SchemaNotDeclared`, `OwnerMismatch`, `UniqueAttributes`, `UnrepresentableGrant`, `SoleSchema`, `NoUniformPattern`, `SchemaPatternConflict`, `RoundTripFailure`, `IncompleteFullInventory`), `Inventory`, `inventory_from_manifest_grants`, `expand_wildcard_grants`. (#96)
- **`pgroles_inspect::fetch_object_inventory`** re-exported at the crate root for callers building their own suggester pipelines. (#96)

### Changed

- **BREAKING: `PolicyManifest.profiles` is now `BTreeMap<String, Profile>`** (was `HashMap<String, Profile>`). YAML serialization is now deterministic — two `pgroles generate` runs against the same database produce byte-identical output. Library consumers that construct `PolicyManifest` directly will need to update their map type. The CLI and operator are unaffected. (#96)

## [0.6.0] - 2026-04-30

### Added

- **Schema management** — declared schemas (`schemas[].owner`) are now first-class state. pgroles creates missing schemas, converges `OWNER TO`, and filters implicit owner ACLs from inspection/export so plan and apply round-trip cleanly. Plan/apply summaries report schema creations and owner alterations. Generated SQL includes `CREATE SCHEMA` and `ALTER SCHEMA … OWNER TO`. (#90)
- **Profile-level `inherit`** — profiles can set `inherit` on generated roles (already existed for `login`); threaded through to the operator CRD as well. (#95)

### Fixed

- **Additive mode no longer rewrites brownfield role attributes or comments.** Previously a pre-existing role like `accounts_editor LOGIN NOINHERIT` could trigger `ALTER ROLE … NOLOGIN INHERIT` under additive mode, which contradicts incremental adoption semantics. Additive mode now leaves attributes and comments unchanged on pre-existing roles. (#95)
- **CLI execution sticks to a single backend.** When a hostname resolves to multiple PostgreSQL servers, one-shot commands could inspect one backend and execute mutations against another. Connection identity is now pinned for the lifetime of a CLI invocation, and SQL execution failures include the backend identity. (#95)

### Changed

- **Documentation** — README and docs updated with schema-management semantics, examples, operator guidance, additive-brownfield behavior, and generated-role attributes. (#90, #95)
- **Dependency bumps** — `next` 16.2.0 → 16.2.3 in `/docs` (#75); `rand` 0.9.2 → 0.9.3 (#82).

## [0.5.0] - 2026-04-15

### Added

- **PostgresPolicyPlan CRD** — reconciliation plans are now separate Kubernetes resources with their own lifecycle. Plans can be reviewed, approved, rejected, or auto-approved before execution. Includes manual approval via annotations, plan superseding on policy changes, and operator-restart safety. (#74)
- **Operator password management** — the operator can generate random passwords and store them in Kubernetes Secrets with ownerReferences, or sync passwords from existing Secrets. Passwords are sent to PostgreSQL as SCRAM-SHA-256 verifiers (cleartext never crosses the wire). Includes secret rotation detection via resourceVersion tracking. (#65)
- **Structured connection parameters** — `connection.params` supports individual fields for host, port, dbname, username, password, and sslMode. Each field accepts a literal value or a `*Secret` SecretKeySelector reference. Integrates natively with Zalando postgres-operator, CloudNativePG, and CrunchyData PGO without requiring an ExternalSecret intermediary. (#87)
- **Pre-flight schema validation** — the operator validates that every schema referenced by the policy exists in the target database before issuing DDL, surfacing a clear `MissingDatabaseObject` status condition instead of failing mid-transaction. (#80)
- **Plan visibility improvements** — plans include SQL preview annotations, change summary annotations, SQL statement count (post-wildcard expansion), and printer columns for the SQL ConfigMap name and hash (`kubectl get pgplan -o wide`).
- **Printer columns for PostgresPolicy** — `kubectl get pgr` now shows Ready, Mode, Drift, Changes, and Last Reconcile columns.
- **CLI accepts Kubernetes CR manifests** — `pgroles diff/apply/validate` can read `PostgresPolicy` YAML directly (extracts the `spec` from the CR wrapper). (#71)
- **Manifest optional for inspect** — `pgroles inspect` can connect to a database without a manifest file to show the current role state. (#69)
- **Staged adoption guide** — new documentation page covering brownfield adoption patterns and PUBLIC privilege caveats. (#70)

### Fixed

- **Wildcard grant convergence on empty schemas** — wildcard grants on sequences, functions, and other types now converge correctly when no objects of that type exist. Previously re-issued on every reconcile, causing unbounded plan creation. (#84)
- **Missing-object SQL errors classified as non-transient** — SQLSTATE codes 3F000, 42P01, 42883, 42704 are now classified as `Slow` retry with `MissingDatabaseObject` reason instead of exponential transient backoff. (#79)
- **Plan resource deduplication** — recently-failed plans with the same SQL hash are deduplicated within a 120-second window, preventing accumulation during fast retries. (#81)
- **MemberSpec defaults removed from CRD** — `inherit` and `admin` fields are now `Option<bool>` with defaults applied at resolution time, avoiding perpetual ArgoCD diffs when using ServerSideApply. (#83)
- **TLS support for PostgreSQL connections** — the operator and CLI now support TLS connections to PostgreSQL, required for Cloud SQL and other managed services. (#67)

### Changed

- **E2E tests split into 3 parallel suites** — operator scenarios, load tests, and plan lifecycle run concurrently in separate kind clusters, reducing CI wall clock from ~20 min to ~10 min. Shared setup extracted into a composite action. (#85)
- **SCRAM-SHA-256 verifiers** — passwords are always hashed client-side before being sent to PostgreSQL. The verifier is stored alongside the cleartext in generated Secrets. Verified against RFC 7677 known vectors.
- **GitHub Actions updated to Node 24 runtimes.** (#66)

## [0.4.1] - 2026-04-08

### Fixed

- Enable TLS for PostgreSQL connections. (#67)

## [0.4.0] - 2026-04-08

### Added

- Printer columns for `PostgresPolicy` CRD (Ready, Mode, Drift, Changes, Last Reconcile, Age). (#68)

## [0.3.0] - 2026-03-26

### Added

- `pgroles graph` command for role visualization in tree, JSON, dot, and mermaid formats. (#60)

## [0.2.0] - 2026-03-12

### Added

- **Reconciliation modes** (`--mode` flag for CLI, `reconciliation_mode` field for Kubernetes operator):
  - `authoritative` (default): full convergence — anything not in the manifest is revoked or dropped. This is the existing behavior, now explicitly named.
  - `additive`: only grant, never revoke — safe for incremental adoption on existing databases.
  - `adopt`: manage declared roles fully (including revoking excess grants), but never drop undeclared roles.
- `ReconciliationMode` enum and `filter_changes()` post-filter in `pgroles-core` for library consumers.
- **Operator plan mode** via `spec.mode: plan`, including planned SQL in status without mutating PostgreSQL.
- **Password-backed roles** with `password` sources and optional `password_valid_until` support for CLI and operator workflows.
- `pgroles generate --output` for direct brownfield manifest export to a file.
- Live-database integration tests covering all three reconciliation modes.
- Documentation for reconciliation modes in CLI reference, operator guide, and CI/CD guide.

### Changed

- Wildcard relation grants and revokes are now scoped by object subtype, so table wildcards do not accidentally touch views or materialized views.
- The docs site, README, and operator guidance now reflect the current production-focused controller model more accurately.

## [0.1.5] - 2026-03-06

Initial public release.
