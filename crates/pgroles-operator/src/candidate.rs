//! `PostgresPolicyCandidate` lifecycle: planning, revalidation, retention.
//!
//! A candidate is a one-shot, immutable proposal of policy content. The
//! operator plans it **inside the parent policy's reconcile**, under the same
//! locks and with the same credentials, after the policy's own enforcement or
//! planning has completed — so the candidate is compared against
//! post-enforcement reality rather than against drift the policy was about to
//! remove anyway.
//!
//! Two properties shape everything here.
//!
//! **Planning writes nothing.** A candidate never issues SQL and never
//! materialises a generated-password Secret: `password.generate` resolves
//! through the same read-only path the policy uses (#181), so an unmaterialised
//! generated password contributes the `:missing` sentinel to the plan's digest
//! and the Secret itself is created only when a *policy* executes. The only
//! writes candidate planning performs are to the candidate's own status and to
//! the plan it owns. [`candidate_password_changes`] is the seam that holds this
//! line, and `candidate_planning_never_materialises_secrets` tests it.
//!
//! **Candidates never open their own connections.** They plan on the pool the
//! parent's reconcile already holds. The single exception is an explicit
//! `spec.target` override, which is a *preview* of a migration destination:
//! credentials, locking and the plan's bound target identity all follow the
//! override, which is exactly why such a plan can never be promoted onto the
//! current target.
//!
//! See `docs/src/pages/docs/operator-candidates.md` for the behaviour and
//! `docs/design/adr-001-candidate-api.md` (Decisions 3 and 6) for the
//! ownership and overlay-overlap rules.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use kube::{Resource, ResourceExt};
use tracing::info;

use pgroles_core::model::MembershipEdge;
use pgroles_core::overlap::{
    EffectPair, describe_pair, effect_pairs, intersecting_pairs, membership_overlay_pairs,
};

use crate::context::OperatorContext;
use crate::crd::{
    CandidatePhase, CandidateTarget, ConnectionSpec, DatabaseIdentity, PlanPhase, PlanReference,
    PolicyCondition, PostgresPolicy, PostgresPolicyCandidate, PostgresPolicyCandidateStatus,
    PostgresPolicyPlan, SecretReference, candidate_reason, is_retention_exempt, ready_condition,
    set_condition_in, superseded_condition,
};
use crate::plan::{CandidatePlanBinding, SupersedeCause};
use crate::reconciler::{ReconcileError, ResolvedPassword};

/// Maximum terminal candidates retained per policy before the oldest are
/// pruned. Deleting a candidate cascades to the plan it owns and to that
/// plan's SQL ConfigMap.
const DEFAULT_MAX_TERMINAL_CANDIDATES: usize = 10;

// ---------------------------------------------------------------------------
// The parent gate
// ---------------------------------------------------------------------------

/// Why the parent policy is not in a state a candidate can be planned against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCause {
    /// The policy has changes of its own that have not executed — it is
    /// awaiting a decision, or in `mode: observe` where it never executes.
    AwaitingDecision,
    /// The policy's reconcile did not converge: failing, suspended, in
    /// conflict, or blocked on target identity.
    Unstable,
}

impl BlockCause {
    fn message(self) -> &'static str {
        match self {
            BlockCause::AwaitingDecision => {
                "the active policy has changes of its own awaiting a decision, so this candidate \
                 would be planned against a state the database is not in yet"
            }
            BlockCause::Unstable => {
                "the active policy is not converging, so there is no post-enforcement state to \
                 plan this candidate against"
            }
        }
    }
}

/// Whether the parent's just-finished reconcile permits candidate planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentGate {
    Stable,
    Blocked(BlockCause),
}

/// Decide the gate from the two facts the parent's reconcile leaves behind.
///
/// The spec says a candidate is blocked when the parent "is failing or awaiting
/// its own approval". That maps onto two observable facts and nothing else:
/// the reconcile reached a converged outcome, and no plan of the policy's own
/// is still actionable. `mode: observe` therefore blocks candidates exactly
/// while it holds pending changes, and lets them through when it is in sync —
/// which is the honest reading, since an observe-mode policy never executes
/// and its "post-enforcement state" is simply the database as it stands.
pub fn parent_gate(converged: bool, has_actionable_plan: bool) -> ParentGate {
    if !converged {
        ParentGate::Blocked(BlockCause::Unstable)
    } else if has_actionable_plan {
        ParentGate::Blocked(BlockCause::AwaitingDecision)
    } else {
        ParentGate::Stable
    }
}

// ---------------------------------------------------------------------------
// Planning inputs
// ---------------------------------------------------------------------------

/// Everything candidate planning borrows from the parent's reconcile.
pub struct CandidatePlanning<'a> {
    /// The pool the parent's reconcile holds, under both of its locks.
    pub pool: &'a sqlx::PgPool,
    pub identity: &'a DatabaseIdentity,
    pub target_identity: &'a pgroles_core::approval::TargetIdentity,
    /// Membership edges contributed by active ephemeral overlays — the
    /// difference between the policy's effective and declared desired graphs.
    pub overlay_edges: &'a [MembershipEdge],
    pub gate: ParentGate,
}

/// What planning one candidate produced.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CandidateOutcome {
    /// A plan exists (fresh or deduplicated) holding these effects.
    Planned { plan_name: String, changes: i32 },
    /// The content produces no changes at all — nothing to review.
    NoEffects,
    /// A plan exists, but an ephemeral overlay touches the same
    /// `(role, object)` pairs, so it must be reviewed afresh.
    OverlayOverlap {
        plan_name: String,
        changes: i32,
        overlapping: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Plan every non-terminal candidate of `policy`, then run candidate retention.
///
/// Called from the parent's reconcile while its locks are still held. Failures
/// planning one candidate are recorded on that candidate and never abort the
/// parent's reconcile: a proposal is not allowed to break enforcement.
pub async fn reconcile_candidates(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    planning: &CandidatePlanning<'_>,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();
    let candidates_api: Api<PostgresPolicyCandidate> =
        Api::namespaced(ctx.kube_client.clone(), &namespace);

    let mut candidates: Vec<PostgresPolicyCandidate> = candidates_api
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|candidate| candidate_belongs_to(candidate, policy))
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    // Oldest first, so `spec.replaces` chains settle in the order they were
    // filed rather than in whatever order the API server returned.
    candidates.sort_by(|a, b| {
        a.metadata
            .creation_timestamp
            .cmp(&b.metadata.creation_timestamp)
            .then_with(|| a.name_any().cmp(&b.name_any()))
    });

    let overlay_pairs = membership_overlay_pairs(planning.overlay_edges);

    for candidate in &mut candidates {
        // First touch: adopt the candidate and stamp the identity everything
        // downstream is compared against, before any planning can fail.
        if let Err(err) = adopt_candidate(ctx, policy, candidate).await {
            tracing::warn!(
                candidate = %candidate.name_any(),
                %err,
                "failed to adopt candidate; skipping this cycle"
            );
            continue;
        }

        if candidate_phase(candidate).is_terminal() {
            continue;
        }

        // A denied plan is terminal for the candidate too: it has no other
        // plan coming, and the revision is a successor object. A failure to
        // *read* the plans is handled like a failed adoption — logged, this
        // candidate skipped — because a proposal must never abort the parent's
        // pass over its siblings.
        let denied = match plan_was_denied(ctx, candidate, &namespace).await {
            Ok(denied) => denied,
            Err(err) => {
                tracing::warn!(
                    candidate = %candidate.name_any(),
                    %err,
                    "failed to read this candidate's plans; skipping this cycle"
                );
                continue;
            }
        };
        if denied {
            mark_superseded(
                ctx,
                candidate,
                candidate_reason::PLAN_DENIED,
                "the plan for this candidate was denied; file a successor to propose a revision",
            )
            .await?;
            continue;
        }

        if let ParentGate::Blocked(cause) = planning.gate {
            block_candidate(ctx, candidate, cause).await?;
            continue;
        }

        match plan_candidate(ctx, policy, candidate, planning, &overlay_pairs).await {
            Ok(outcome) => {
                record_outcome(ctx, candidate, outcome).await?;
            }
            Err(err) => {
                let message = err.to_string();
                tracing::warn!(
                    candidate = %candidate.name_any(),
                    policy = %policy_name,
                    %message,
                    "failed to plan candidate"
                );
                write_status(ctx, candidate, |status| {
                    set_condition_in(
                        &mut status.conditions,
                        ready_condition(false, candidate_reason::PLANNING_FAILED, &message),
                    );
                })
                .await?;
                crate::events::publish_candidate_event(
                    &ctx.event_recorder,
                    candidate,
                    true,
                    candidate_reason::PLANNING_FAILED,
                    message,
                )
                .await
                .ok();
            }
        }
    }

    // Supersession is explicit and only takes effect once the successor has a
    // plan of its own: marking the predecessor earlier would leave a reviewer
    // with neither a live proposal nor a reviewable replacement.
    apply_replacements(ctx, &candidates).await?;

    cleanup_terminal_candidates(ctx, &namespace, &candidates).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Planning one candidate
// ---------------------------------------------------------------------------

async fn plan_candidate(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &PostgresPolicyCandidate,
    planning: &CandidatePlanning<'_>,
    overlay_pairs: &BTreeSet<EffectPair>,
) -> Result<CandidateOutcome, ReconcileError> {
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let content = &candidate.spec.content;

    let manifest = content.to_policy_manifest();
    let expanded = pgroles_core::manifest::expand_manifest(&manifest)?;
    let mut desired = pgroles_core::model::RoleGraph::from_expanded(
        &expanded,
        manifest.default_owner.as_deref(),
    )?;

    // Compose the same ephemeral overlay the policy composed. Without it an
    // authoritative candidate would propose revoking every live ephemeral
    // membership — noise that is not the candidate's content. Edges whose
    // roles the candidate does not declare are left out: the candidate is
    // removing that role, which the pair intersection below reports as an
    // overlap rather than silently planning around.
    let mut overlay_roles: BTreeSet<String> = BTreeSet::new();
    for edge in planning.overlay_edges {
        if !desired.roles.contains_key(&edge.role) || !desired.roles.contains_key(&edge.member) {
            continue;
        }
        if desired
            .memberships
            .iter()
            .any(|existing| existing.role == edge.role && existing.member == edge.member)
        {
            continue;
        }
        overlay_roles.insert(edge.role.clone());
        overlay_roles.insert(edge.member.clone());
        desired.memberships.insert(edge.clone());
    }

    // Resolve the execution context. Everything after this point runs against
    // `target`, which is the parent's connection unless `spec.target` overrides
    // it — in which case the plan binds that database's identity and can never
    // be promoted onto the current one.
    let target = resolve_target(ctx, policy, candidate, planning, &namespace).await?;
    let result = plan_against_target(
        ctx,
        policy,
        candidate,
        overlay_pairs,
        &target,
        &manifest,
        &expanded,
        &desired,
        &overlay_roles,
        &namespace,
    )
    .await;
    // An override holds its own advisory lock; release it on every path.
    target.release().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn plan_against_target(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &PostgresPolicyCandidate,
    overlay_pairs: &BTreeSet<EffectPair>,
    target: &CandidateTargetContext<'_>,
    manifest: &pgroles_core::manifest::PolicyManifest,
    expanded: &pgroles_core::manifest::ExpandedManifest,
    desired: &pgroles_core::model::RoleGraph,
    overlay_roles: &BTreeSet<String>,
    namespace: &str,
) -> Result<CandidateOutcome, ReconcileError> {
    let content = &candidate.spec.content;
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|g| g.object.object_type == pgroles_core::manifest::ObjectType::Database);
    let inspect_config =
        pgroles_inspect::InspectConfig::from_expanded(expanded, has_database_grants)
            .with_additional_roles(
                manifest
                    .retirements
                    .iter()
                    .map(|retirement| retirement.role.clone()),
            )
            .with_additional_roles(overlay_roles.iter().cloned());
    let inspection =
        pgroles_inspect::inspect_with_diagnostics(target.pool(), &inspect_config).await?;
    if let Some(message) = inspection.diagnostics.blocking_message() {
        return Err(ReconcileError::UnsatisfiableWildcardGrant(message));
    }
    let current = inspection.graph;

    crate::reconciler::validate_referenced_schemas_exist(target.pool(), expanded).await?;

    let reconciliation_mode: pgroles_core::diff::ReconciliationMode =
        content.reconciliation_mode.into();
    let mut changes = pgroles_core::diff::filter_changes(
        pgroles_core::diff::apply_role_retirements(
            pgroles_core::diff::diff(&current, desired),
            &manifest.retirements,
        ),
        reconciliation_mode,
    );
    changes = pgroles_core::diff::filter_external_role_changes(changes, &expanded.roles);

    // Read-only password resolution. Generated Secrets are named for the
    // parent policy because that is what promotion would create; nothing is
    // written here in any state.
    let resolved_passwords = crate::reconciler::resolve_passwords_for_roles(
        ctx,
        policy,
        namespace,
        &content.roles,
        false,
    )
    .await?;
    let (password_changes, password_source_versions) =
        candidate_password_changes(&changes, &resolved_passwords, policy);
    if !password_changes.is_empty() {
        changes = pgroles_core::diff::inject_password_changes(changes, &password_changes);
    }

    let summary = crate::reconciler::summarize_changes(&changes);

    if changes.is_empty() {
        // The effects vanished (or never existed): the content is already the
        // database's state. Retire any plan rather than leave a reviewable
        // artifact describing nothing.
        supersede_candidate_plan(ctx, candidate, namespace, SupersedeCause::EffectsCleared).await?;
        return Ok(CandidateOutcome::NoEffects);
    }

    let candidate_pairs = effect_pairs(&changes);
    let overlapping = intersecting_pairs(&candidate_pairs, overlay_pairs);

    let sql_ctx = crate::reconciler::detect_sql_context(target.pool(), &inspect_config).await?;
    let content_digest = content_digest(candidate);

    // `create_or_update_plan` is the whole revalidation rule: an identical
    // change digest deduplicates onto the existing plan, keeping it and any
    // decision recorded on it; a changed digest creates a replacement and
    // supersedes the old one with a cause. Candidates get exactly the policy's
    // Phase 0 semantics because they go through exactly the same function.
    let creation = crate::plan::create_or_update_plan(
        &ctx.kube_client,
        policy,
        &changes,
        &sql_ctx,
        &inspect_config,
        content.reconciliation_mode,
        target.identity(),
        target.target_identity(),
        &summary,
        &password_source_versions,
        Some(CandidatePlanBinding {
            candidate,
            content_digest: &content_digest,
            content_digest_encoding: pgroles_core::candidate::CANDIDATE_CONTENT_ENCODING_V1,
        }),
    )
    .await?;
    let plan_name = creation.plan_name().to_string();

    if creation.is_created() {
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            false,
            candidate_reason::PLANNED,
            format!("Plan {plan_name} created with {} change(s)", summary.total),
        )
        .await
        .ok();
    }

    if !overlapping.is_empty() {
        return Ok(CandidateOutcome::OverlayOverlap {
            plan_name,
            changes: summary.total,
            overlapping: overlapping.iter().map(describe_pair).collect(),
        });
    }

    Ok(CandidateOutcome::Planned {
        plan_name,
        changes: summary.total,
    })
}

/// The execution context a candidate is planned in.
enum CandidateTargetContext<'a> {
    /// The parent's pool, identity and target identity, unchanged.
    Parent(&'a CandidatePlanning<'a>),
    /// An explicit `spec.target` override, with its own locks held for the
    /// duration of the plan.
    Override {
        pool: sqlx::PgPool,
        identity: DatabaseIdentity,
        target_identity: pgroles_core::approval::TargetIdentity,
        _db_lock: crate::context::DatabaseLockGuard,
        advisory_lock: Option<crate::advisory::AdvisoryLock>,
    },
}

impl CandidateTargetContext<'_> {
    fn pool(&self) -> &sqlx::PgPool {
        match self {
            CandidateTargetContext::Parent(planning) => planning.pool,
            CandidateTargetContext::Override { pool, .. } => pool,
        }
    }

    fn identity(&self) -> &str {
        match self {
            CandidateTargetContext::Parent(planning) => planning.identity.as_str(),
            CandidateTargetContext::Override { identity, .. } => identity.as_str(),
        }
    }

    fn target_identity(&self) -> &pgroles_core::approval::TargetIdentity {
        match self {
            CandidateTargetContext::Parent(planning) => planning.target_identity,
            CandidateTargetContext::Override {
                target_identity, ..
            } => target_identity,
        }
    }

    async fn release(self) {
        if let CandidateTargetContext::Override {
            advisory_lock: Some(lock),
            ..
        } = self
        {
            lock.release().await;
        }
    }
}

/// Build the `ConnectionSpec` an override target resolves through.
///
/// The override is URL mode only, so it maps onto the same `ConnectionSpec`
/// the policy uses and therefore resolves, fingerprints and locks by exactly
/// the same code — including the #180 dual target identity.
pub(crate) fn override_connection_spec(target: &CandidateTarget) -> ConnectionSpec {
    ConnectionSpec {
        secret_ref: Some(SecretReference {
            name: target.connection_ref.secret_name.clone(),
        }),
        secret_key: Some(target.connection_ref.key.clone()),
        params: None,
        require_physical_identity: None,
    }
}

async fn resolve_target<'a>(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &PostgresPolicyCandidate,
    planning: &'a CandidatePlanning<'a>,
    namespace: &str,
) -> Result<CandidateTargetContext<'a>, ReconcileError> {
    let Some(target) = candidate.spec.target.as_ref() else {
        return Ok(CandidateTargetContext::Parent(planning));
    };

    let connection = override_connection_spec(target);
    let identity = DatabaseIdentity::from_connection(namespace, &connection);
    if identity.as_str() == planning.identity.as_str() {
        // The override resolves to the parent's own target. Reusing the
        // parent's context is not an optimisation — taking the same lock twice
        // in one reconcile would deadlock against ourselves.
        return Ok(CandidateTargetContext::Parent(planning));
    }

    let pool = ctx
        .get_or_create_pool(namespace, &connection)
        .await
        .map_err(Box::new)?;

    // Locking follows the target: the override is a different database, so it
    // has its own advisory and in-process locks and cannot share the parent's.
    let db_lock = ctx
        .try_lock_database(identity.as_str())
        .await
        .ok_or_else(|| {
            ReconcileError::LockContention(
                identity.as_str().to_string(),
                "candidate target override lock held by another reconcile".to_string(),
            )
        })?;
    let advisory_lock = match crate::advisory::try_acquire(&pool, identity.as_str()).await {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            return Err(ReconcileError::LockContention(
                identity.as_str().to_string(),
                "candidate target override advisory lock held by another session".to_string(),
            ));
        }
        Err(err) => return Err(ReconcileError::SqlExec(err)),
    };

    // Everything below can fail, and `AdvisoryLock` has no `Drop` release —
    // dropping it would return a connection to the pool with the session-level
    // lock still held, blocking every later reconcile of this database. Any
    // error past this point must release the lock before propagating.
    let identity_lookup: Result<_, ReconcileError> = async {
        let physical = pgroles_inspect::detect_system_identifier(&pool).await?;
        let logical = ctx
            .resolve_database_target_fingerprint(namespace, &connection)
            .await
            .map_err(Box::new)?;
        Ok((physical, logical))
    }
    .await;
    let (physical, logical) = match identity_lookup {
        Ok(identities) => identities,
        Err(err) => {
            if let Some(lock) = advisory_lock {
                lock.release().await;
            }
            return Err(err);
        }
    };
    tracing::info!(
        candidate = %candidate.name_any(),
        policy = %policy.name_any(),
        target = %identity.as_str(),
        "planning candidate against an explicit target override"
    );

    Ok(CandidateTargetContext::Override {
        pool,
        identity,
        target_identity: pgroles_core::approval::TargetIdentity {
            physical,
            logical: Some(logical),
        },
        _db_lock: db_lock,
        advisory_lock,
    })
}

// ---------------------------------------------------------------------------
// The no-write seam
// ---------------------------------------------------------------------------

/// Select the password changes a candidate plan describes.
///
/// The policy's [`crate::reconciler::select_password_changes`] compares against
/// the parent's `status.appliedPasswordSourceVersions`, which is the right
/// baseline for a candidate too: the candidate is asking what would happen if
/// its content became the policy's.
///
/// What this function structurally cannot do is materialise anything. It takes
/// resolved passwords by reference and returns only strings, so the
/// `pending_materialization` marker — the sole route to
/// `password::ensure_generated_secret` — is dropped here and can never reach a
/// writer. An unmaterialised generated password still contributes its
/// `:missing` sentinel to the digest, so the plan's identity says plainly that
/// the credential does not exist yet.
pub(crate) fn candidate_password_changes(
    changes: &[pgroles_core::diff::Change],
    resolved: &BTreeMap<String, ResolvedPassword>,
    policy: &PostgresPolicy,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    crate::reconciler::select_password_changes(changes, resolved, policy.status.as_ref())
}

// ---------------------------------------------------------------------------
// Status transitions
// ---------------------------------------------------------------------------

fn candidate_phase(candidate: &PostgresPolicyCandidate) -> CandidatePhase {
    candidate
        .status
        .as_ref()
        .map(|status| status.phase)
        .unwrap_or_default()
}

fn content_digest(candidate: &PostgresPolicyCandidate) -> String {
    pgroles_core::candidate::compute_content_digest(&candidate.spec.content)
}

/// The controller ownerReference from a candidate to its parent policy.
///
/// ADR-001 Decision 3: a controller reference, so deleting the policy
/// garbage-collects its candidates — a candidate has no meaning without its
/// base. Cross-namespace refs are impossible, which is why `spec.policyRef`
/// resolves in the candidate's own namespace.
pub(crate) fn policy_owner_reference(policy: &PostgresPolicy) -> OwnerReference {
    OwnerReference {
        api_version: PostgresPolicy::api_version(&()).to_string(),
        kind: PostgresPolicy::kind(&()).to_string(),
        name: policy.name_any(),
        uid: policy.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Does this candidate already carry the controller reference to `policy`?
pub(crate) fn has_policy_owner_reference(
    candidate: &PostgresPolicyCandidate,
    policy_uid: &str,
) -> bool {
    crate::plan::is_owned_by_uid(candidate, policy_uid)
}

/// Does this candidate belong to `policy`?
///
/// The name in `spec.policyRef` is the author's declaration; the controller
/// ownerReference is the discipline. A candidate that has already been adopted
/// belongs only to the policy with that UID, so a same-named policy that was
/// deleted and recreated never inherits the old policy's candidates while they
/// await garbage collection — matching them by name alone would let planning
/// and, worse, promotion recognition read proposals reviewed against an object
/// that no longer exists. An unadopted candidate (no controller reference yet)
/// matches by name and is bound to a UID on first touch by [`adopt_candidate`].
pub(crate) fn candidate_belongs_to(
    candidate: &PostgresPolicyCandidate,
    policy: &PostgresPolicy,
) -> bool {
    if candidate.spec.policy_ref.name != policy.name_any() {
        return false;
    }
    let controller_uid = candidate
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|owner| owner.controller.unwrap_or(false))
        .map(|owner| owner.uid.as_str());
    match (controller_uid, policy.metadata.uid.as_deref()) {
        // Adopted: only the recorded controller may claim it. A policy with no
        // UID (only constructible in tests) can prove ownership of nothing.
        (Some(owned_by), live_uid) => live_uid == Some(owned_by),
        // Not yet adopted: the name is all there is, and first touch binds it.
        (None, _) => true,
    }
}

/// First-touch bookkeeping: ownerReference, content digest, observedGeneration.
///
/// All three are stamped before anything can fail, so a candidate that never
/// plans successfully still shows what it is and what it is bound to.
async fn adopt_candidate(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &mut PostgresPolicyCandidate,
) -> Result<(), ReconcileError> {
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let name = candidate.name_any();

    let policy_uid = policy.metadata.uid.as_deref().unwrap_or_default();
    if !policy_uid.is_empty() && !has_policy_owner_reference(candidate, policy_uid) {
        let mut owner_references = candidate
            .metadata
            .owner_references
            .clone()
            .unwrap_or_default();
        owner_references.retain(|owner| !owner.controller.unwrap_or(false));
        owner_references.push(policy_owner_reference(policy));
        let patch = serde_json::json!({ "metadata": { "ownerReferences": owner_references } });
        // A merge patch, so no `.force()`: kube validates that `force` is only
        // legal on `Patch::Apply` and would reject this call client-side.
        *candidate = api
            .patch(
                &name,
                &PatchParams::apply("pgroles-operator"),
                &Patch::Merge(&patch),
            )
            .await?;
        info!(candidate = %name, policy = %policy.name_any(), "adopted candidate");
    }

    let digest = content_digest(candidate);
    let generation = candidate.metadata.generation;
    let status = candidate.status.clone().unwrap_or_default();
    if status.content_digest.as_deref() != Some(digest.as_str())
        || status.observed_generation != generation
    {
        write_status(ctx, candidate, |status| {
            status.content_digest = Some(digest.clone());
            status.observed_generation = generation;
        })
        .await?;
    }
    Ok(())
}

/// Apply a status mutation to a candidate and write it back.
async fn write_status<F>(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    mutate: F,
) -> Result<(), ReconcileError>
where
    F: FnOnce(&mut PostgresPolicyCandidateStatus),
{
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let mut status = candidate.status.clone().unwrap_or_default();
    mutate(&mut status);
    let patch = serde_json::json!({ "status": status });
    let updated = api
        .patch_status(
            &candidate.name_any(),
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    *candidate = updated;
    Ok(())
}

async fn record_outcome(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    outcome: CandidateOutcome,
) -> Result<(), ReconcileError> {
    match outcome {
        CandidateOutcome::Planned { plan_name, changes } => {
            let message = format!("Plan {plan_name} holds {changes} change(s) for review");
            write_status(ctx, candidate, |status| {
                status.phase = CandidatePhase::Planned;
                status.plan_ref = Some(PlanReference {
                    name: plan_name.clone(),
                });
                set_condition_in(
                    &mut status.conditions,
                    ready_condition(true, candidate_reason::PLANNED, &message),
                );
            })
            .await
        }
        CandidateOutcome::NoEffects => {
            let message =
                "this candidate's content is already the database's state; nothing to review"
                    .to_string();
            write_status(ctx, candidate, |status| {
                status.phase = CandidatePhase::Planned;
                status.plan_ref = None;
                set_condition_in(
                    &mut status.conditions,
                    ready_condition(true, candidate_reason::NO_EFFECTS, &message),
                );
            })
            .await
        }
        CandidateOutcome::OverlayOverlap {
            plan_name,
            changes,
            overlapping,
        } => {
            let message = format!(
                "an active ephemeral grant touches {} of this candidate's effects ({}); plan \
                 {plan_name} holds {changes} change(s) and requires fresh review",
                overlapping.len(),
                overlapping.join(", "),
            );
            write_status(ctx, candidate, |status| {
                status.phase = CandidatePhase::Planned;
                status.plan_ref = Some(PlanReference {
                    name: plan_name.clone(),
                });
                set_condition_in(
                    &mut status.conditions,
                    ready_condition(false, candidate_reason::OVERLAY_OVERLAP, &message),
                );
            })
            .await?;
            crate::events::publish_candidate_event(
                &ctx.event_recorder,
                candidate,
                true,
                candidate_reason::OVERLAY_OVERLAP,
                message,
            )
            .await
            .ok();
            Ok(())
        }
    }
}

async fn block_candidate(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    cause: BlockCause,
) -> Result<(), ReconcileError> {
    let already_blocked = candidate.status.as_ref().is_some_and(|status| {
        status.conditions.iter().any(|c| {
            c.condition_type == "Ready"
                && c.status == "False"
                && c.reason.as_deref() == Some(candidate_reason::BLOCKED_BY_ACTIVE_POLICY)
        })
    });
    write_status(ctx, candidate, |status| {
        set_condition_in(
            &mut status.conditions,
            ready_condition(
                false,
                candidate_reason::BLOCKED_BY_ACTIVE_POLICY,
                cause.message(),
            ),
        );
    })
    .await?;
    // The parent can stay blocked for many cycles; one Event per transition is
    // the point of Events, a stream of identical ones is noise.
    if !already_blocked {
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            true,
            candidate_reason::BLOCKED_BY_ACTIVE_POLICY,
            cause.message().to_string(),
        )
        .await
        .ok();
    }
    Ok(())
}

async fn mark_superseded(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    reason: &str,
    message: &str,
) -> Result<(), ReconcileError> {
    if candidate_phase(candidate) == CandidatePhase::Superseded {
        return Ok(());
    }
    write_status(ctx, candidate, |status| {
        status.phase = CandidatePhase::Superseded;
        set_condition_in(
            &mut status.conditions,
            superseded_condition(reason, message),
        );
        set_condition_in(
            &mut status.conditions,
            ready_condition(false, reason, message),
        );
    })
    .await?;
    crate::events::publish_candidate_event(
        &ctx.event_recorder,
        candidate,
        true,
        reason,
        message.to_string(),
    )
    .await
    .ok();
    Ok(())
}

/// Mark predecessors named in `spec.replaces` as superseded.
///
/// Only once the successor actually has a plan: an unplanned successor has
/// proved nothing, and retiring the predecessor first would leave a reviewer
/// with nothing at all.
async fn apply_replacements(
    ctx: &OperatorContext,
    candidates: &[PostgresPolicyCandidate],
) -> Result<(), ReconcileError> {
    let planned: BTreeMap<String, String> = candidates
        .iter()
        .filter(|candidate| {
            candidate
                .status
                .as_ref()
                .is_some_and(|status| status.plan_ref.is_some())
        })
        .filter_map(|candidate| {
            candidate
                .spec
                .replaces
                .clone()
                .map(|replaced| (replaced, candidate.name_any()))
        })
        .collect();
    if planned.is_empty() {
        return Ok(());
    }

    for candidate in candidates {
        let Some(successor) = planned.get(&candidate.name_any()) else {
            continue;
        };
        if candidate_phase(candidate).is_terminal() {
            continue;
        }
        let mut candidate = candidate.clone();
        mark_superseded(
            ctx,
            &mut candidate,
            candidate_reason::REPLACED,
            &format!("replaced by candidate {successor}"),
        )
        .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan lookups and retention
// ---------------------------------------------------------------------------

/// The plans owned by one candidate.
async fn candidate_plans(
    ctx: &OperatorContext,
    candidate: &PostgresPolicyCandidate,
    namespace: &str,
) -> Result<Vec<PostgresPolicyPlan>, ReconcileError> {
    let Some(uid) = candidate.metadata.uid.as_deref() else {
        return Ok(Vec::new());
    };
    let plans: Api<PostgresPolicyPlan> = Api::namespaced(ctx.kube_client.clone(), namespace);
    Ok(plans
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|plan| crate::plan::is_owned_by_uid(plan, uid))
        .collect())
}

async fn plan_was_denied(
    ctx: &OperatorContext,
    candidate: &PostgresPolicyCandidate,
    namespace: &str,
) -> Result<bool, ReconcileError> {
    Ok(candidate_plans(ctx, candidate, namespace)
        .await?
        .iter()
        .any(|plan| {
            matches!(
                crate::plan::check_plan_approval(plan),
                crate::plan::PlanApprovalState::Rejected
            ) || plan
                .status
                .as_ref()
                .is_some_and(|status| status.phase == PlanPhase::Rejected)
        }))
}

/// Retire a candidate's live plan when its effects are gone.
async fn supersede_candidate_plan(
    ctx: &OperatorContext,
    candidate: &PostgresPolicyCandidate,
    namespace: &str,
    cause: SupersedeCause,
) -> Result<(), ReconcileError> {
    for plan in candidate_plans(ctx, candidate, namespace).await? {
        let is_live = plan
            .status
            .as_ref()
            .is_some_and(|status| matches!(status.phase, PlanPhase::Pending | PlanPhase::Approved));
        if !is_live {
            continue;
        }
        crate::plan::mark_plan_superseded(&ctx.kube_client, &plan, cause).await?;
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            false,
            "PlanSuperseded",
            format!("Plan {} superseded: {}", plan.name_any(), cause.message()),
        )
        .await
        .ok();
    }
    Ok(())
}

/// Prune terminal candidates beyond the retention bound.
///
/// Plans cascade: each is owned by its candidate, so deleting the candidate
/// takes the plan and its SQL ConfigMap with it. `pgroles.io/keep=true` exempts
/// a candidate, and this is best-effort — retention must never block planning.
async fn cleanup_terminal_candidates(
    ctx: &OperatorContext,
    namespace: &str,
    candidates: &[PostgresPolicyCandidate],
) {
    let mut terminal: Vec<&PostgresPolicyCandidate> = candidates
        .iter()
        .filter(|candidate| candidate_phase(candidate).is_terminal())
        .filter(|candidate| !is_retention_exempt(*candidate))
        .collect();
    if terminal.len() <= DEFAULT_MAX_TERMINAL_CANDIDATES {
        return;
    }
    terminal.sort_by(|a, b| {
        a.metadata
            .creation_timestamp
            .cmp(&b.metadata.creation_timestamp)
    });

    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), namespace);
    let excess = terminal.len() - DEFAULT_MAX_TERMINAL_CANDIDATES;
    for candidate in terminal.into_iter().take(excess) {
        let name = candidate.name_any();
        info!(candidate = %name, "pruning terminal candidate");
        if let Err(err) = api.delete(&name, &DeleteParams::default()).await {
            tracing::warn!(candidate = %name, %err, "failed to prune terminal candidate");
        }
    }
}

/// Read the `Ready` condition reason from a candidate status, for tests and
/// status consumers that only care about the current verdict.
pub fn ready_reason(status: &PostgresPolicyCandidateStatus) -> Option<&str> {
    status
        .conditions
        .iter()
        .find(|c: &&PolicyCondition| c.condition_type == "Ready")
        .and_then(|c| c.reason.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        GeneratePasswordSpec, LocalObjectReference, PolicyContent, PostgresPolicyCandidateSpec,
        PostgresPolicySpec, RoleSpec,
    };

    fn policy(name: &str) -> PostgresPolicy {
        let spec: PostgresPolicySpec = serde_json::from_value(serde_json::json!({
            "connection": { "secretRef": { "name": "db" } },
        }))
        .expect("minimal policy spec");
        let mut policy = PostgresPolicy::new(name, spec);
        policy.metadata.uid = Some(format!("{name}-uid"));
        policy.metadata.namespace = Some("default".to_string());
        policy
    }

    fn role(name: &str) -> RoleSpec {
        serde_json::from_value(serde_json::json!({ "name": name, "login": true }))
            .expect("minimal role spec")
    }

    fn candidate(name: &str, content: PolicyContent) -> PostgresPolicyCandidate {
        PostgresPolicyCandidate::new(
            name,
            PostgresPolicyCandidateSpec {
                policy_ref: LocalObjectReference {
                    name: "orders".to_string(),
                },
                replaces: None,
                target: None,
                content,
            },
        )
    }

    #[test]
    fn the_gate_blocks_only_a_parent_that_has_not_finished_its_own_work() {
        assert_eq!(parent_gate(true, false), ParentGate::Stable);
        assert_eq!(
            parent_gate(true, true),
            ParentGate::Blocked(BlockCause::AwaitingDecision)
        );
        assert_eq!(
            parent_gate(false, false),
            ParentGate::Blocked(BlockCause::Unstable)
        );
        // A failing parent is blocked whether or not a plan of its own is open;
        // "unstable" is the cause a reviewer needs to see first.
        assert_eq!(
            parent_gate(false, true),
            ParentGate::Blocked(BlockCause::Unstable)
        );
    }

    #[test]
    fn candidate_planning_never_materialises_secrets() {
        // A generated password with no Secret yet: the sole route to
        // `ensure_generated_secret` is the `pending_materialization` marker,
        // and the candidate seam returns strings only, so it cannot survive.
        let resolved = BTreeMap::from([(
            "reporting_reader".to_string(),
            ResolvedPassword {
                cleartext: "in-memory".to_string(),
                source_version: "orders-reporting-reader:password:missing".to_string(),
                pending_materialization: Some(crate::reconciler::PendingGeneratedSecret {
                    role: "reporting_reader".to_string(),
                    spec: GeneratePasswordSpec {
                        length: None,
                        secret_name: None,
                        secret_key: None,
                    },
                }),
            },
        )]);
        let changes = vec![pgroles_core::diff::Change::CreateRole {
            name: "reporting_reader".to_string(),
            state: Default::default(),
        }];

        let (passwords, versions) =
            candidate_password_changes(&changes, &resolved, &policy("orders"));

        assert_eq!(
            passwords.get("reporting_reader").map(String::as_str),
            Some("in-memory")
        );
        // The sentinel is what reaches the digest, so the plan's identity says
        // out loud that the credential does not exist yet.
        assert_eq!(
            versions.get("reporting_reader").map(String::as_str),
            Some("orders-reporting-reader:password:missing")
        );
    }

    /// The safety property in structural form: nothing on the candidate
    /// planning path may call a writer. A unit test cannot observe the absence
    /// of an API call without a fake API server, but it *can* observe that the
    /// module never names the two functions that perform the writes — Secret
    /// materialisation and SQL execution — which is the property this phase
    /// promises, and it fails the moment someone reaches for one.
    #[test]
    fn the_candidate_module_calls_no_writer() {
        let source = include_str!("candidate.rs");
        // This test's own body names them, and so does the prose explaining
        // why they are absent; neither is a call.
        let body: String = source
            .split_once("mod tests {")
            .map(|(before, _)| before)
            .expect("this module has a test module")
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n");
        for writer in [
            "ensure_generated_secret",
            "materialize_pending_generated_secrets",
            "execute_changes_in_transaction",
            "execute_plan",
        ] {
            assert!(
                !body.contains(&format!("{writer}(")),
                "candidate planning must not call {writer}: planning adds no writes beyond the \
                 active policy's own reconcile"
            );
        }
    }

    #[test]
    fn an_override_target_resolves_through_the_ordinary_connection_spec() {
        let spec = override_connection_spec(&CandidateTarget {
            connection_ref: crate::crd::CandidateConnectionRef {
                secret_name: "orders-new-postgres".to_string(),
                key: "url".to_string(),
            },
        });
        assert_eq!(
            spec.secret_ref.as_ref().map(|r| r.name.as_str()),
            Some("orders-new-postgres")
        );
        assert_eq!(spec.effective_secret_key(), "url");
        assert!(spec.params.is_none());
        // Identity, fingerprint and locking all derive from this spec, which is
        // what makes the override bind the destination's identity rather than
        // the parent's.
        assert!(!spec.requires_physical_identity());
    }

    #[test]
    fn the_owner_reference_is_a_controller_reference_to_the_policy() {
        let policy = policy("orders");
        let owner = policy_owner_reference(&policy);
        assert_eq!(owner.kind, "PostgresPolicy");
        assert_eq!(owner.uid, "orders-uid");
        assert_eq!(owner.controller, Some(true));

        let mut candidate = candidate("orders-change-x7k2p", PolicyContent::default());
        assert!(!has_policy_owner_reference(&candidate, "orders-uid"));
        candidate.metadata.owner_references = Some(vec![owner]);
        assert!(has_policy_owner_reference(&candidate, "orders-uid"));
        // A same-named policy that was deleted and recreated must not inherit
        // the old one's candidates.
        assert!(!has_policy_owner_reference(&candidate, "orders-uid-2"));
    }

    /// Ownership by UID, declaration by name. A recreated same-name policy
    /// must not inherit — and above all must not promote through — candidates
    /// adopted by its deleted predecessor.
    #[test]
    fn a_candidate_belongs_only_to_the_policy_that_adopted_it() {
        let orders = policy("orders");
        let mut unadopted = candidate("orders-change-x7k2p", PolicyContent::default());

        // Wrong name never matches, adopted or not.
        assert!(!candidate_belongs_to(&unadopted, &policy("billing")));

        // Right name, no controller reference yet: belongs, pending adoption.
        assert!(candidate_belongs_to(&unadopted, &orders));

        // Adopted by this policy: still belongs.
        unadopted.metadata.owner_references = Some(vec![policy_owner_reference(&orders)]);
        let adopted = unadopted;
        assert!(candidate_belongs_to(&adopted, &orders));

        // Same name, different UID — the deleted-and-recreated policy. The
        // candidate is the predecessor's, awaiting garbage collection.
        let mut recreated = policy("orders");
        recreated.metadata.uid = Some("orders-uid-2".to_string());
        assert!(!candidate_belongs_to(&adopted, &recreated));

        // A policy that cannot prove its identity claims nothing it has not
        // merely been named by.
        let mut anonymous = policy("orders");
        anonymous.metadata.uid = None;
        assert!(!candidate_belongs_to(&adopted, &anonymous));
        // ...though an unadopted candidate still matches by name alone.
        let fresh = candidate("orders-change-a1b2c", PolicyContent::default());
        assert!(candidate_belongs_to(&fresh, &anonymous));
    }

    #[test]
    fn phases_are_terminal_exactly_where_the_docs_say() {
        assert!(CandidatePhase::Promoted.is_terminal());
        assert!(CandidatePhase::Superseded.is_terminal());
        assert!(!CandidatePhase::Pending.is_terminal());
        assert!(!CandidatePhase::Planned.is_terminal());
        assert!(!CandidatePhase::Stale.is_terminal());
    }

    #[test]
    fn a_blocked_cause_says_which_half_of_the_rule_fired() {
        assert!(
            BlockCause::AwaitingDecision
                .message()
                .contains("awaiting a decision")
        );
        assert!(BlockCause::Unstable.message().contains("not converging"));
    }

    #[test]
    fn the_content_digest_is_the_phase_1a_digest() {
        let candidate = candidate(
            "orders-change-x7k2p",
            PolicyContent {
                roles: vec![role("reporting_reader")],
                ..Default::default()
            },
        );
        assert_eq!(
            content_digest(&candidate),
            pgroles_core::candidate::compute_content_digest(&candidate.spec.content)
        );
        assert!(content_digest(&candidate).starts_with("sha256:"));
    }
}
