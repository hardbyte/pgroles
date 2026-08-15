//! Promotion: recognising that a policy's new content *is* a reviewed
//! candidate, and gating execution on the approval that candidate carries.
//!
//! Approval never changes a `PostgresPolicy`. Promotion is the ordinary GitOps
//! write — the pull request carrying the same content merges, the GitOps
//! controller updates `PostgresPolicy.spec`, and this module is what recognises
//! the update as the approved candidate.
//!
//! # The safety property
//!
//! > The effects executed are exactly the approved canonical effects,
//! > recomputed under the lock.
//!
//! Nothing here executes anything, and nothing here re-implements execution.
//! When a promotion is recognised and its candidate's plan is `Approved`, this
//! module hands the reconciler *that plan* in place of the policy's own
//! `current_plan_ref`, and the existing approved-plan path takes over
//! unchanged: it recomputes the canonical change digest from the effects the
//! policy would produce right now, against the state it just inspected under
//! both locks, and executes only if that digest equals the one the plan was
//! approved with — with the target identity bound into the digest either way.
//!
//! Adopting the candidate's plan rather than transferring its approval into a
//! freshly-created policy plan is deliberate. Copying an `Approved` condition
//! onto a new object would mean writing an approval no human decided, with a
//! `decidedBy` the operator invented, and would give the operator a code path
//! that manufactures approvals — precisely the authority the plan-decision
//! model exists to deny it. The candidate's plan is already the reviewed
//! artifact: it carries the decision, the `decidedBy`, the approved change
//! digest and the bound target identity. Reusing it means promotion adds no
//! new trusted step at all.
//!
//! # What is *not* a promotion
//!
//! Everything else, and each case is reported rather than silently ignored:
//!
//! - content matching no candidate — the ordinary policy flow, nothing new;
//! - content matching a candidate whose plan is not approved — the ordinary
//!   manual-plan flow, with `PromotedWithoutApproval` on the candidate;
//! - content that changed into something no candidate holds while an approved
//!   candidate is open — the edited-after-approval case, with
//!   `PromotionDigestMismatch` on that candidate and the enforcement gap named
//!   in plain words.
//!
//! See `docs/src/pages/docs/operator-candidates.md` for the behaviour these
//! rules implement.

use kube::ResourceExt;
use kube::api::{Api, ListParams, Patch, PatchParams};

use crate::context::OperatorContext;
use crate::crd::{
    ApprovalMode, CandidatePhase, PlanPhase, PolicyMode, PostgresPolicy, PostgresPolicyCandidate,
    PostgresPolicyPlan, candidate_reason, promoted_condition, ready_condition, set_condition_in,
};
use crate::plan::{PlanApprovalState, SupersedeCause, check_plan_approval};
use crate::reconciler::ReconcileError;

// ---------------------------------------------------------------------------
// The pure decision seam
// ---------------------------------------------------------------------------

/// Everything the promotion decision needs to know about one candidate.
///
/// Deliberately not the Kubernetes object: the decision is a function of four
/// facts, and keeping it that way is what makes every row of the edge-case
/// table in the docs a unit test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFacts {
    pub name: String,
    /// `status.contentDigest` — absent until the candidate's first reconcile.
    pub content_digest: Option<String>,
    /// Promoted or superseded: never planned again, never promoted again.
    pub terminal: bool,
    /// The candidate's live plan, if it has one.
    pub plan: Option<PlanFacts>,
}

/// The live plan of a candidate, and whether it carries an approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanFacts {
    pub name: String,
    /// A terminal `Approved=True` decision, on a plan that has not already
    /// executed, failed or been retired.
    pub approved: bool,
}

impl CandidateFacts {
    fn approved_plan(&self) -> Option<&PlanFacts> {
        self.plan.as_ref().filter(|plan| plan.approved)
    }
}

/// What the policy's current content is, relative to the open candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Promotion {
    /// Not a promotion: no candidate holds this content, and nothing about the
    /// change makes an open approval suspect.
    None,
    /// This content is a candidate whose plan is approved.
    Approved {
        candidate: String,
        plan: String,
        /// Other candidates holding an approved plan. Their approvals were
        /// made against a base this promotion replaces.
        superseded: Vec<String>,
    },
    /// This content is a candidate, but nobody approved its plan.
    WithoutApproval { candidate: String },
    /// The content changed into something no candidate holds, while these
    /// candidates were sitting on an approved plan.
    Mismatch { candidates: Vec<String> },
}

/// Decide what the policy's content means, given the open candidates.
///
/// `previous_digest` is the content digest this policy carried on its last
/// reconcile. It matters for exactly one thing: distinguishing *the content
/// just changed and does not match the approved candidate* (the
/// edited-after-approval case) from *the content has not changed and a
/// candidate is under review* (the entire normal life of a candidate). Without
/// it, every policy with an open approved candidate would permanently report a
/// mismatch.
pub fn decide_promotion(
    policy_digest: &str,
    previous_digest: Option<&str>,
    candidates: &[CandidateFacts],
) -> Promotion {
    let open = || candidates.iter().filter(|candidate| !candidate.terminal);

    // Matching is not conditioned on the digest having changed. A promotion
    // whose bookkeeping was interrupted — the SQL executed, the operator
    // restarted before writing `Promoted=True` — must still be recognised on
    // the next reconcile, and re-recognising an already-executed promotion is
    // harmless: its effects are gone, so the plan clears rather than replays.
    if let Some(matched) = open().find(|candidate| {
        candidate
            .content_digest
            .as_deref()
            .is_some_and(|digest| digest == policy_digest)
    }) {
        return match matched.approved_plan() {
            Some(plan) => Promotion::Approved {
                candidate: matched.name.clone(),
                plan: plan.name.clone(),
                superseded: open()
                    .filter(|other| other.name != matched.name)
                    .filter(|other| other.approved_plan().is_some())
                    .map(|other| other.name.clone())
                    .collect(),
            },
            None => Promotion::WithoutApproval {
                candidate: matched.name.clone(),
            },
        };
    }

    let content_changed = previous_digest.is_some_and(|previous| previous != policy_digest);
    if content_changed {
        let stranded: Vec<String> = open()
            .filter(|candidate| candidate.approved_plan().is_some())
            .map(|candidate| candidate.name.clone())
            .collect();
        if !stranded.is_empty() {
            return Promotion::Mismatch {
                candidates: stranded,
            };
        }
    }

    Promotion::None
}

/// What the reconciler should do about a [`Promotion`] in this execution mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionAction {
    /// Reconcile exactly as if candidates did not exist.
    Ignore,
    /// Execute the candidate's approved plan in place of the policy's own —
    /// still subject to the fresh digest comparison under the lock.
    ExecuteApprovedPlan { candidate: String, plan: String },
    /// Ordinary manual-plan flow; record `PromotedWithoutApproval`.
    WithoutApproval { candidate: String },
    /// Ordinary manual-plan flow; record `PromotionDigestMismatch`.
    Mismatch {
        candidates: Vec<String>,
        /// Whether the merged spec is now unenforced pending a fresh approval.
        /// True under `apply` + `manual`, which is the enforcement gap the
        /// design names; false where the policy converges (or never executes)
        /// regardless.
        enforcement_suspended: bool,
    },
    /// The content was promoted but this policy never executes, so the
    /// candidate cannot reach `Promoted`.
    NotExecuted { candidate: String },
}

/// Map a promotion onto an action, given how the policy executes.
///
/// Two modes make the gate moot rather than absent:
///
/// - **`approval: auto`** — the policy approves and executes its own plan on
///   every reconcile, so there is no approval to gate on and the candidate's
///   plan is not needed. The gate is trivially satisfied; the candidate still
///   reaches `Promoted` through the ordinary post-execution bookkeeping.
/// - **`mode: plan`** — the policy never executes anything, ever. A candidate
///   promoted into a plan-mode policy therefore cannot reach `Promoted`: it
///   reports `PromotionNotExecuted` and stays non-terminal, and becomes
///   `Promoted` if and when the policy is switched to `mode: apply` and the
///   content executes.
pub fn promotion_action(
    promotion: Promotion,
    mode: PolicyMode,
    approval: ApprovalMode,
) -> PromotionAction {
    let never_executes = mode == PolicyMode::Plan;
    let enforcement_suspended = !never_executes && approval == ApprovalMode::Manual;

    match promotion {
        Promotion::None => PromotionAction::Ignore,
        Promotion::Approved {
            candidate, plan, ..
        } => {
            if never_executes {
                PromotionAction::NotExecuted { candidate }
            } else if approval == ApprovalMode::Auto {
                PromotionAction::Ignore
            } else {
                PromotionAction::ExecuteApprovedPlan { candidate, plan }
            }
        }
        Promotion::WithoutApproval { candidate } => {
            if never_executes {
                PromotionAction::NotExecuted { candidate }
            } else if approval == ApprovalMode::Auto {
                PromotionAction::Ignore
            } else {
                PromotionAction::WithoutApproval { candidate }
            }
        }
        Promotion::Mismatch { candidates } => PromotionAction::Mismatch {
            candidates,
            enforcement_suspended,
        },
    }
}

/// The candidates whose approved plans a successful promotion strands.
///
/// Only candidates that hold an *approved* plan: an approval made against a
/// base this promotion replaced can never be used again, so leaving it live
/// would leave an executable authorisation lying around. Candidates whose
/// plans are merely pending are left alone — they are replanned against the
/// new base by the ordinary revalidation rule, which keeps their plan when the
/// effects are unchanged.
pub fn stranded_by_promotion(promoted: &str, candidates: &[CandidateFacts]) -> Vec<String> {
    candidates
        .iter()
        .filter(|candidate| !candidate.terminal)
        .filter(|candidate| candidate.name != promoted)
        .filter(|candidate| candidate.approved_plan().is_some())
        .map(|candidate| candidate.name.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Reading the facts out of the cluster
// ---------------------------------------------------------------------------

/// A candidate object paired with the facts the decision is made from.
pub struct PromotionContext {
    pub candidates: Vec<PostgresPolicyCandidate>,
    pub facts: Vec<CandidateFacts>,
    /// Live plans, indexed by owning candidate name.
    plans: Vec<(String, PostgresPolicyPlan)>,
}

impl PromotionContext {
    pub fn candidate(&self, name: &str) -> Option<&PostgresPolicyCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.name_any() == name)
    }

    pub fn plan_of(&self, candidate: &str) -> Option<&PostgresPolicyPlan> {
        self.plans
            .iter()
            .find(|(owner, _)| owner == candidate)
            .map(|(_, plan)| plan)
    }
}

/// A plan is live when it can still authorise something: not applied, failed,
/// rejected or already retired.
fn plan_is_live(plan: &PostgresPolicyPlan) -> bool {
    plan.status
        .as_ref()
        .is_some_and(|status| matches!(status.phase, PlanPhase::Pending | PlanPhase::Approved))
}

/// Load every candidate of `policy` and its live plan.
pub async fn load_context(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
) -> Result<PromotionContext, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();

    let candidates: Vec<PostgresPolicyCandidate> =
        Api::<PostgresPolicyCandidate>::namespaced(ctx.kube_client.clone(), &namespace)
            .list(&ListParams::default())
            .await?
            .into_iter()
            .filter(|candidate| candidate.spec.policy_ref.name == policy_name)
            .collect();
    if candidates.is_empty() {
        return Ok(PromotionContext {
            candidates,
            facts: Vec::new(),
            plans: Vec::new(),
        });
    }

    let all_plans: Vec<PostgresPolicyPlan> =
        Api::<PostgresPolicyPlan>::namespaced(ctx.kube_client.clone(), &namespace)
            .list(&ListParams::default())
            .await?
            .into_iter()
            .filter(plan_is_live)
            .collect();

    let mut plans: Vec<(String, PostgresPolicyPlan)> = Vec::new();
    let mut facts: Vec<CandidateFacts> = Vec::new();
    for candidate in &candidates {
        let uid = candidate.metadata.uid.clone().unwrap_or_default();
        let owned = all_plans
            .iter()
            .find(|plan| !uid.is_empty() && crate::plan::is_owned_by_uid(*plan, &uid));
        let plan_facts = owned.map(|plan| PlanFacts {
            name: plan.name_any(),
            approved: check_plan_approval(plan) == PlanApprovalState::Approved,
        });
        if let Some(plan) = owned {
            plans.push((candidate.name_any(), plan.clone()));
        }
        facts.push(CandidateFacts {
            name: candidate.name_any(),
            content_digest: candidate
                .status
                .as_ref()
                .and_then(|status| status.content_digest.clone()),
            terminal: candidate
                .status
                .as_ref()
                .map(|status| status.phase)
                .unwrap_or_default()
                .is_terminal(),
            plan: plan_facts,
        });
    }

    Ok(PromotionContext {
        candidates,
        facts,
        plans,
    })
}

// ---------------------------------------------------------------------------
// Recognition and bookkeeping
// ---------------------------------------------------------------------------

/// Recognise what this reconcile's content means, and record it.
///
/// Returns the plan the reconciler must treat as the policy's current plan, if
/// this is a promotion carrying an approval. Everything else is reported on
/// the candidate and leaves the ordinary flow untouched.
pub async fn recognize(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    content_digest: &str,
) -> Result<Option<PostgresPolicyPlan>, ReconcileError> {
    let context = load_context(ctx, policy).await?;
    let previous = policy
        .status
        .as_ref()
        .and_then(|status| status.content_digest.clone());

    let promotion = decide_promotion(content_digest, previous.as_deref(), &context.facts);
    let action = promotion_action(
        promotion,
        policy.spec.mode,
        policy.spec.effective_approval(),
    );

    // Remember the content before acting on it. The mismatch case fires on the
    // transition, so recording the digest is what keeps it a single reported
    // event rather than a warning re-emitted on every reconcile — and the
    // condition it wrote stays on the candidate meanwhile.
    if previous.as_deref() != Some(content_digest) {
        stamp_content_digest(ctx, policy, content_digest).await?;
    }

    let plan = match &action {
        PromotionAction::Ignore => None,
        PromotionAction::ExecuteApprovedPlan { candidate, plan } => {
            tracing::info!(
                policy = %policy.name_any(),
                %candidate,
                %plan,
                "recognised promotion of an approved candidate; its plan is this reconcile's plan"
            );
            context.plan_of(candidate).cloned().filter(|found| {
                // Guard against the facts and the object disagreeing.
                found.name_any() == *plan
            })
        }
        PromotionAction::WithoutApproval { candidate } => {
            let message = format!(
                "this candidate's content was promoted into policy {} while its plan held no \
                 approval, so nothing executed on it; the policy falls back to its ordinary \
                 manual-plan flow, and this candidate becomes Promoted once that fresh plan is \
                 approved and applied",
                policy.name_any()
            );
            report(
                ctx,
                &context,
                candidate,
                candidate_reason::PROMOTED_WITHOUT_APPROVAL,
                &message,
            )
            .await?;
            None
        }
        PromotionAction::NotExecuted { candidate } => {
            let message = format!(
                "this candidate's content was promoted into policy {}, but that policy is in \
                 mode: plan and never executes; the candidate can only become Promoted once the \
                 policy is in mode: apply and the content is applied",
                policy.name_any()
            );
            report(
                ctx,
                &context,
                candidate,
                candidate_reason::PROMOTION_NOT_EXECUTED,
                &message,
            )
            .await?;
            None
        }
        PromotionAction::Mismatch {
            candidates,
            enforcement_suspended,
        } => {
            for candidate in candidates {
                let mut message = format!(
                    "policy {} now carries content that is not this approved candidate — it was \
                     edited or rebased after approval — so the approval does not authorise it and \
                     nothing has executed.",
                    policy.name_any()
                );
                if *enforcement_suspended {
                    message.push_str(
                        " The merged spec is now the desired state and is NOT being enforced: \
                         drift against either state goes unreconciled until a fresh plan is \
                         approved. Approve the policy's new plan, or file a successor candidate \
                         for the content that was actually merged.",
                    );
                }
                report(
                    ctx,
                    &context,
                    candidate,
                    candidate_reason::PROMOTION_DIGEST_MISMATCH,
                    &message,
                )
                .await?;
            }
            None
        }
    };

    Ok(plan)
}

/// Bookkeeping after the policy successfully executed its content.
///
/// This is the single place `Promoted=True` is written, and it is reached from
/// every executing path — the promotion gate, `approval: auto`, and the
/// ordinary manual approval of a fresh plan after a `PromotedWithoutApproval`
/// fallback. A candidate is promoted when its content is the content that
/// executed; how the execution was authorised is a separate question, answered
/// before the SQL ran.
pub async fn record_promotion(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    content_digest: &str,
) -> Result<(), ReconcileError> {
    let context = load_context(ctx, policy).await?;
    let Some(promoted) = context.facts.iter().find(|candidate| {
        !candidate.terminal
            && candidate
                .content_digest
                .as_deref()
                .is_some_and(|digest| digest == content_digest)
    }) else {
        return Ok(());
    };
    let promoted_name = promoted.name.clone();

    // Retire the approvals this promotion stranded first: if the operator dies
    // between the two writes, an unusable approval left live is the worse of
    // the two states to be caught in.
    for stranded in stranded_by_promotion(&promoted_name, &context.facts) {
        let Some(plan) = context.plan_of(&stranded) else {
            continue;
        };
        crate::plan::mark_plan_superseded(
            &ctx.kube_client,
            plan,
            SupersedeCause::SupersededByPromotion,
        )
        .await?;
        if let Some(candidate) = context.candidate(&stranded) {
            let message = format!(
                "candidate {promoted_name} was promoted and applied, so plan {} — approved \
                 against the previous base — can never execute; file a successor candidate to \
                 propose this change against the new base",
                plan.name_any()
            );
            set_candidate_condition(
                ctx,
                candidate,
                promoted_condition(false, candidate_reason::SUPERSEDED_BY_PROMOTION, &message),
                candidate_reason::SUPERSEDED_BY_PROMOTION,
                &message,
                true,
            )
            .await?;
        }
    }

    let Some(candidate) = context.candidate(&promoted_name) else {
        return Ok(());
    };
    let plan_note = context
        .plan_of(&promoted_name)
        .map(|plan| format!(" (plan {})", plan.name_any()))
        .unwrap_or_default();
    let message = format!(
        "content promoted into policy {} and applied{plan_note}",
        policy.name_any()
    );
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let mut status = candidate.status.clone().unwrap_or_default();
    status.phase = CandidatePhase::Promoted;
    set_condition_in(
        &mut status.conditions,
        promoted_condition(true, candidate_reason::PROMOTED, &message),
    );
    set_condition_in(
        &mut status.conditions,
        ready_condition(true, candidate_reason::PROMOTED, &message),
    );
    api.patch_status(
        &promoted_name,
        &PatchParams::apply("pgroles-operator"),
        &Patch::Merge(&serde_json::json!({ "status": status })),
    )
    .await?;
    crate::events::publish_candidate_event(
        &ctx.event_recorder,
        candidate,
        false,
        candidate_reason::PROMOTED,
        message,
    )
    .await
    .ok();
    tracing::info!(
        policy = %policy.name_any(),
        candidate = %promoted_name,
        "candidate promoted"
    );
    Ok(())
}

async fn report(
    ctx: &OperatorContext,
    context: &PromotionContext,
    candidate: &str,
    reason: &str,
    message: &str,
) -> Result<(), ReconcileError> {
    let Some(object) = context.candidate(candidate) else {
        return Ok(());
    };
    set_candidate_condition(
        ctx,
        object,
        // Deliberately not `Ready`: the planning lifecycle owns that condition
        // and rewrites it every cycle — including with
        // `BlockedByActivePolicy` the moment the promoted policy opens a plan
        // of its own, which is exactly when a reviewer needs to read why the
        // promotion did not execute.
        promoted_condition(false, reason, message),
        reason,
        message,
        true,
    )
    .await
}

/// Write one condition onto a candidate, emitting an Event only on transition.
async fn set_candidate_condition(
    ctx: &OperatorContext,
    candidate: &PostgresPolicyCandidate,
    condition: crate::crd::PolicyCondition,
    reason: &str,
    message: &str,
    warning: bool,
) -> Result<(), ReconcileError> {
    let already = candidate.status.as_ref().is_some_and(|status| {
        status.conditions.iter().any(|c| {
            c.condition_type == condition.condition_type && c.reason.as_deref() == Some(reason)
        })
    });
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let mut status = candidate.status.clone().unwrap_or_default();
    set_condition_in(&mut status.conditions, condition);
    api.patch_status(
        &candidate.name_any(),
        &PatchParams::apply("pgroles-operator"),
        &Patch::Merge(&serde_json::json!({ "status": status })),
    )
    .await?;
    if !already {
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            warning,
            reason,
            message.to_string(),
        )
        .await
        .ok();
    }
    Ok(())
}

async fn stamp_content_digest(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    content_digest: &str,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let api: Api<PostgresPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    api.patch_status(
        &policy.name_any(),
        &PatchParams::apply("pgroles-operator"),
        &Patch::Merge(&serde_json::json!({
            "status": { "content_digest": content_digest }
        })),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — one per row of the edge-case table in operator-candidates.md
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(name: &str, digest: &str) -> CandidateFacts {
        CandidateFacts {
            name: name.to_string(),
            content_digest: Some(digest.to_string()),
            terminal: false,
            plan: None,
        }
    }

    fn with_plan(mut facts: CandidateFacts, plan: &str, approved: bool) -> CandidateFacts {
        facts.plan = Some(PlanFacts {
            name: plan.to_string(),
            approved,
        });
        facts
    }

    /// Row 1: promoted content matches the approved candidate.
    #[test]
    fn approved_content_promotes_through_the_candidates_own_plan() {
        let facts = vec![with_plan(candidate("c1", "sha256:aa"), "c1-plan", true)];
        assert_eq!(
            decide_promotion("sha256:aa", Some("sha256:old"), &facts),
            Promotion::Approved {
                candidate: "c1".to_string(),
                plan: "c1-plan".to_string(),
                superseded: Vec::new(),
            }
        );
    }

    /// Row 3: promotion with no approved plan at all — ordinary flow, reported.
    #[test]
    fn content_matching_an_unapproved_candidate_falls_back_and_says_so() {
        let facts = vec![with_plan(candidate("c1", "sha256:aa"), "c1-plan", false)];
        assert_eq!(
            decide_promotion("sha256:aa", Some("sha256:old"), &facts),
            Promotion::WithoutApproval {
                candidate: "c1".to_string()
            }
        );
        assert_eq!(
            promotion_action(
                decide_promotion("sha256:aa", Some("sha256:old"), &facts),
                PolicyMode::Apply,
                ApprovalMode::Manual
            ),
            PromotionAction::WithoutApproval {
                candidate: "c1".to_string()
            }
        );
    }

    /// Row 3, other half: content matching no candidate is not a promotion.
    #[test]
    fn content_matching_no_candidate_is_the_ordinary_policy_flow() {
        let facts = vec![candidate("c1", "sha256:aa")];
        assert_eq!(
            decide_promotion("sha256:zz", Some("sha256:zz"), &facts),
            Promotion::None
        );
        // With no candidates at all, likewise — including on a first-ever
        // reconcile where there is no previous digest to compare against.
        assert_eq!(decide_promotion("sha256:zz", None, &[]), Promotion::None);
    }

    /// Row 2: content edited after approval — digest mismatch.
    #[test]
    fn content_edited_after_approval_strands_the_candidate_with_an_explicit_reason() {
        let facts = vec![with_plan(candidate("c1", "sha256:aa"), "c1-plan", true)];
        assert_eq!(
            decide_promotion("sha256:edited", Some("sha256:old"), &facts),
            Promotion::Mismatch {
                candidates: vec!["c1".to_string()]
            }
        );
        // And the fallback names the enforcement gap under apply + manual.
        assert_eq!(
            promotion_action(
                decide_promotion("sha256:edited", Some("sha256:old"), &facts),
                PolicyMode::Apply,
                ApprovalMode::Manual
            ),
            PromotionAction::Mismatch {
                candidates: vec!["c1".to_string()],
                enforcement_suspended: true,
            }
        );
    }

    /// The mismatch rule must not fire on a policy that simply has not changed
    /// while a candidate is under review — which is a candidate's whole life.
    #[test]
    fn an_unchanged_policy_with_an_open_approved_candidate_reports_nothing() {
        let facts = vec![with_plan(candidate("c1", "sha256:aa"), "c1-plan", true)];
        assert_eq!(
            decide_promotion("sha256:base", Some("sha256:base"), &facts),
            Promotion::None
        );
        // Nor on the very first observation, where there is no previous digest
        // and therefore no evidence the content changed at all.
        assert_eq!(
            decide_promotion("sha256:base", None, &facts),
            Promotion::None
        );
    }

    /// Row 4: plan X approved, candidate Y merged — Y promotes, X goes stale.
    #[test]
    fn approving_one_candidate_and_merging_another_promotes_the_merged_one() {
        let facts = vec![
            with_plan(candidate("x", "sha256:xx"), "x-plan", true),
            with_plan(candidate("y", "sha256:yy"), "y-plan", true),
        ];
        assert_eq!(
            decide_promotion("sha256:yy", Some("sha256:old"), &facts),
            Promotion::Approved {
                candidate: "y".to_string(),
                plan: "y-plan".to_string(),
                superseded: vec!["x".to_string()],
            }
        );
        assert_eq!(stranded_by_promotion("y", &facts), vec!["x".to_string()]);
        // A merely-pending plan is left to ordinary revalidation, which keeps
        // it when the effects are unchanged.
        let pending = vec![
            with_plan(candidate("x", "sha256:xx"), "x-plan", false),
            with_plan(candidate("y", "sha256:yy"), "y-plan", true),
        ];
        assert!(stranded_by_promotion("y", &pending).is_empty());
    }

    #[test]
    fn a_terminal_candidate_is_never_promoted_again() {
        let mut facts = with_plan(candidate("c1", "sha256:aa"), "c1-plan", true);
        facts.terminal = true;
        assert_eq!(
            decide_promotion("sha256:aa", Some("sha256:old"), &[facts]),
            Promotion::None
        );
    }

    #[test]
    fn a_candidate_without_a_stamped_digest_cannot_match() {
        let facts = vec![CandidateFacts {
            name: "c1".to_string(),
            content_digest: None,
            terminal: false,
            plan: None,
        }];
        assert_eq!(
            decide_promotion("sha256:aa", Some("sha256:old"), &facts),
            Promotion::None
        );
    }

    /// Under `approval: auto` the gate is trivially satisfied: the policy
    /// approves and executes its own plan, so the candidate's plan is not
    /// adopted — but the candidate is still promoted afterwards.
    #[test]
    fn auto_approval_executes_immediately_and_needs_no_candidate_plan() {
        for approved in [true, false] {
            let facts = vec![with_plan(candidate("c1", "sha256:aa"), "c1-plan", approved)];
            assert_eq!(
                promotion_action(
                    decide_promotion("sha256:aa", Some("sha256:old"), &facts),
                    PolicyMode::Apply,
                    ApprovalMode::Auto
                ),
                PromotionAction::Ignore
            );
        }
    }

    /// Under `mode: plan` nothing ever executes, so a promoted candidate stays
    /// non-terminal and says why.
    #[test]
    fn plan_mode_promotion_never_executes_and_the_candidate_stays_open() {
        for approved in [true, false] {
            let facts = vec![with_plan(candidate("c1", "sha256:aa"), "c1-plan", approved)];
            assert_eq!(
                promotion_action(
                    decide_promotion("sha256:aa", Some("sha256:old"), &facts),
                    PolicyMode::Plan,
                    ApprovalMode::Manual
                ),
                PromotionAction::NotExecuted {
                    candidate: "c1".to_string()
                }
            );
        }
    }

    /// A mismatch under a mode that keeps converging is still worth reporting,
    /// but it is not the enforcement gap — so the message must not claim it is.
    #[test]
    fn the_enforcement_gap_is_claimed_only_where_it_exists() {
        let facts = vec![with_plan(candidate("c1", "sha256:aa"), "c1-plan", true)];
        let mismatch = || decide_promotion("sha256:edited", Some("sha256:old"), &facts);
        for (mode, approval) in [
            (PolicyMode::Apply, ApprovalMode::Auto),
            (PolicyMode::Plan, ApprovalMode::Manual),
        ] {
            assert_eq!(
                promotion_action(mismatch(), mode, approval),
                PromotionAction::Mismatch {
                    candidates: vec!["c1".to_string()],
                    enforcement_suspended: false,
                }
            );
        }
    }
}
