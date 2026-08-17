//! Canonical approval-effect digest.
//!
//! An approval must name the *semantic effects* a plan will have, not the SQL
//! text those effects happen to render to. Rendered SQL is unstable in ways
//! that have nothing to do with what a reviewer approved: a `SetPassword`
//! change embeds a SCRAM-SHA-256 verifier built with a fresh random salt on
//! every computation, so hashing the SQL makes a password-bearing plan
//! impossible to approve — it is superseded the moment the diff is recomputed.
//!
//! This module defines a versioned canonical encoding of the typed effects,
//! following the same discipline as the ephemeral bundle hash: a named
//! encoding constant, deterministic serialization, and a self-verifying
//! SHA-256 digest.
//!
//! What the encoding binds:
//!
//! - every typed [`Change`], normalized and ordered independently of the diff
//!   engine's dependency ordering
//! - the reconciliation mode, since the same desired state converges
//!   differently under `additive` or `adopt`
//! - the target database identity, in both of its complementary forms: the
//!   *physical* identity (`pg_control_system().system_identifier`, the storage
//!   lineage) and the *logical* identity (the resolved connection fingerprint
//!   — host, port, database), so an approval cannot be reused against a
//!   different server, a clone, a branch or a replica
//! - the Kubernetes reference the connection was resolved from
//!
//! What it deliberately excludes:
//!
//! - cleartext passwords, generated password material, SCRAM salts and
//!   verifiers — a password change is bound as `(role, password source
//!   identity and version)` instead
//! - rendered SQL text, statement ordering, and renderer-specific formatting
//!
//! The rendered-SQL hash remains useful as a diagnostic for the preview
//! artifact; it is simply not the approval identity.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::diff::{Change, ReconciliationMode};

/// Version tag for the canonical effect encoding.
///
/// Any change to how effects are normalized, ordered, or bound must introduce
/// a new constant. Digests computed under different encodings are never
/// comparable, so a pending approval computed under an older encoding is
/// superseded rather than silently accepted.
pub const APPROVAL_EFFECT_ENCODING_V1: &str = "pgroles.io/approval-effect/v1";

/// Current canonical effect encoding.
///
/// v2 adds the resolved target identity — physical (`system_identifier`) and
/// logical (host/port/database fingerprint) — to the bound inputs. Every
/// digest changes once when an operator upgrades to this encoding, so every
/// open plan supersedes exactly once and is re-reviewed.
pub const APPROVAL_EFFECT_ENCODING_V2: &str = "pgroles.io/approval-effect/v2";

/// Refusal to produce a digest that would not bind what it claims to bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalDigestError {
    /// A `SetPassword` change was present without a corresponding password
    /// source version.
    ///
    /// Binding the role alone would let an approval for one password source
    /// carry over to a different one, so this fails closed instead.
    #[error(
        "no password source version recorded for role `{role}`: \
         refusing to compute an approval digest that cannot bind the password source"
    )]
    MissingPasswordSource { role: String },
}

/// Context bound into the digest alongside the effects themselves.
#[derive(Debug, Clone, Copy)]
pub struct EffectDigestInputs<'a> {
    /// How the desired state converges. The same effects under a different
    /// mode are a different approval.
    pub reconciliation_mode: ReconciliationMode,
    /// Kubernetes-level identity of the connection the effects were computed
    /// through (namespace-scoped Secret reference or canonical params).
    pub target: &'a str,
    /// Identity of the database server itself, as observed at planning time.
    ///
    /// Bound in addition to `target` because the Kubernetes reference can be
    /// repointed at a different server without changing.
    pub target_identity: &'a TargetIdentity,
    /// Stable password source identity per role, keyed by role name — for the
    /// operator this is `secret:key:resourceVersion`. Every role named by a
    /// `SetPassword` change must have an entry.
    pub password_source_versions: &'a BTreeMap<String, String>,
    /// The roles this plan's owner claims management of. Bound because scope
    /// is a material control-plane effect the SQL cannot show: dropping a
    /// role from management produces no SQL at all, yet stops enforcing it.
    pub owned_roles: &'a [String],
    /// The schemas this plan's owner claims management of — bound for the
    /// same reason as `owned_roles`.
    pub owned_schemas: &'a [String],
}

#[derive(Serialize)]
struct CanonicalChangeSet<'a> {
    effect_encoding: &'a str,
    reconciliation_mode: ReconciliationMode,
    target: &'a str,
    target_physical_identity: Option<&'a str>,
    target_logical_fingerprint: Option<&'a str>,
    owned_roles: BTreeSet<&'a str>,
    owned_schemas: BTreeSet<&'a str>,
    effects: Vec<Value>,
}

/// The two complementary answers to "is this the same database?".
///
/// Neither identity is sufficient alone:
///
/// - **Physical** — `pg_control_system().system_identifier`. It answers *same
///   storage lineage?*: it survives failover to a streaming replica, and it
///   catches a restore taken from somewhere else. It is a *lineage*
///   identifier, not an instance one: replicas, PITR and snapshot restores,
///   Aurora clones and Neon branches all inherit the parent's value, and it
///   legitimately changes on a major upgrade (`pg_upgrade` runs a fresh
///   `initdb`) or a blue-green cutover.
/// - **Logical** — the resolved connection fingerprint (host, port, database).
///   It answers *same endpoint?*: it catches exactly the clone/branch/replica
///   confusion the physical identity cannot see, and is in turn fooled by
///   connection poolers and DNS changes.
///
/// Both are therefore bound, and a change in either one fails closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetIdentity {
    /// `system_identifier`, when the server exposes `pg_control_system()`.
    /// `None` on engines that do not implement it (CockroachDB, Spanner's
    /// PostgreSQL interface, Redshift, Aurora DSQL) or where `EXECUTE` has
    /// been revoked from `PUBLIC`.
    pub physical: Option<String>,
    /// Fingerprint of the resolved host, port and database name. `None` only
    /// when the connection could not be resolved to a target.
    pub logical: Option<String>,
}

impl TargetIdentity {
    /// A target identity with only the logical half — the ordinary shape on
    /// engines that do not expose `pg_control_system()`.
    pub fn logical_only(logical: impl Into<String>) -> Self {
        Self {
            physical: None,
            logical: Some(logical.into()),
        }
    }

    /// Whether the physical identity was readable.
    pub fn has_physical(&self) -> bool {
        self.physical.is_some()
    }
}

/// Why a recorded approval can no longer authorise execution against the
/// database in front of the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetIdentityReason {
    /// An identity that was bound at approval reads differently now: the plan
    /// would execute against a different database than the one reviewed.
    TargetChanged,
    /// An identity readable at approval is unreadable now. Treated as a
    /// mismatch rather than "unknown", so revoking `EXECUTE` on
    /// `pg_control_system()` cannot silently demote an approval's guarantees.
    TargetIdentityUnavailable,
    /// An identity that was unavailable at approval is readable now. A
    /// one-time event (an upgrade, or a permission grant); the approval was
    /// never bound to it, so it is re-reviewed once.
    TargetIdentityAppeared,
    /// `requirePhysicalIdentity` is set and the physical identity is not
    /// available. No plan may progress.
    PhysicalIdentityRequired,
}

impl TargetIdentityReason {
    /// Condition/event reason string.
    pub fn as_str(self) -> &'static str {
        match self {
            TargetIdentityReason::TargetChanged => "TargetChanged",
            TargetIdentityReason::TargetIdentityUnavailable => "TargetIdentityUnavailable",
            TargetIdentityReason::TargetIdentityAppeared => "TargetIdentityAppeared",
            TargetIdentityReason::PhysicalIdentityRequired => "PhysicalIdentityRequired",
        }
    }

    /// Operator-facing explanation.
    pub fn message(self) -> &'static str {
        match self {
            TargetIdentityReason::TargetChanged => {
                "the database this plan was approved against is not the database it would now \
                 execute against"
            }
            TargetIdentityReason::TargetIdentityUnavailable => {
                "an identity bound at approval time can no longer be read from the target"
            }
            TargetIdentityReason::TargetIdentityAppeared => {
                "an identity that was unavailable at approval time is now readable, so the \
                 approval was never bound to it"
            }
            TargetIdentityReason::PhysicalIdentityRequired => {
                "requirePhysicalIdentity is set but pg_control_system().system_identifier could \
                 not be read from the target"
            }
        }
    }
}

/// What the observed target identity permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetIdentityVerdict {
    /// Both identities still answer as they did at approval.
    Proceed,
    /// The target moved. The plan is superseded and re-reviewed; a fresh
    /// approval is the sanctioned acknowledgement.
    Superseded(TargetIdentityReason),
    /// The deployment requires an identity it cannot obtain. Nothing
    /// progresses until that is fixed — this is a configuration fault, not a
    /// staleness event.
    Blocked(TargetIdentityReason),
}

/// Compare the identity an approval was bound to against the one observed now.
///
/// Pure by construction: the whole execution-time gate is this comparison, so
/// it is exhaustively testable without a database or a cluster.
pub fn evaluate_target_identity(
    approved: &TargetIdentity,
    observed: &TargetIdentity,
    require_physical_identity: bool,
) -> TargetIdentityVerdict {
    if require_physical_identity && (!observed.has_physical() || !approved.has_physical()) {
        return TargetIdentityVerdict::Blocked(TargetIdentityReason::PhysicalIdentityRequired);
    }

    for (approved, observed) in [
        (&approved.physical, &observed.physical),
        (&approved.logical, &observed.logical),
    ] {
        match (approved, observed) {
            (Some(approved), Some(observed)) if approved != observed => {
                return TargetIdentityVerdict::Superseded(TargetIdentityReason::TargetChanged);
            }
            (Some(_), None) => {
                return TargetIdentityVerdict::Superseded(
                    TargetIdentityReason::TargetIdentityUnavailable,
                );
            }
            (None, Some(_)) => {
                return TargetIdentityVerdict::Superseded(
                    TargetIdentityReason::TargetIdentityAppeared,
                );
            }
            _ => {}
        }
    }

    TargetIdentityVerdict::Proceed
}

/// Compute the canonical approval-effect digest for a set of changes.
///
/// The result is stable across recomputation of the same semantic effects and
/// independent of the order the diff engine emitted them in.
pub fn compute_change_digest(
    changes: &[Change],
    inputs: &EffectDigestInputs<'_>,
) -> Result<String, ApprovalDigestError> {
    Ok(sha256_prefixed(&canonical_change_set_bytes(
        changes, inputs,
    )?))
}

/// The exact bytes [`compute_change_digest`] hashes.
///
/// Exposed for two reasons: diagnosing *why* two digests differ without
/// re-deriving the encoding by hand, and letting tests assert on what actually
/// enters the hash. Asserting on the digest alone cannot show that password
/// material was excluded — a hash never contains its input literally, so such
/// a check passes whether or not the exclusion works.
pub fn canonical_change_set_bytes(
    changes: &[Change],
    inputs: &EffectDigestInputs<'_>,
) -> Result<Vec<u8>, ApprovalDigestError> {
    let mut effects = Vec::with_capacity(changes.len());
    for change in changes {
        effects.push(canonical_effect(change, inputs.password_source_versions)?);
    }

    // Dependency ordering is an execution concern; two plans with the same set
    // of effects are the same approval regardless of emission order.
    effects.sort_by_cached_key(ToString::to_string);

    // Management scope is a set: order is a listing artifact, duplicates say
    // nothing, and both would make equal scopes hash differently. `BTreeSet`
    // makes that canonicalisation the type's job rather than a call site's,
    // and serialises as a sorted JSON array.
    let owned_roles: BTreeSet<&str> = inputs.owned_roles.iter().map(String::as_str).collect();
    let owned_schemas: BTreeSet<&str> = inputs.owned_schemas.iter().map(String::as_str).collect();

    Ok(serde_json::to_vec(&CanonicalChangeSet {
        effect_encoding: APPROVAL_EFFECT_ENCODING_V2,
        reconciliation_mode: inputs.reconciliation_mode,
        target: inputs.target,
        target_physical_identity: inputs.target_identity.physical.as_deref(),
        target_logical_fingerprint: inputs.target_identity.logical.as_deref(),
        owned_roles,
        owned_schemas,
        effects,
    })
    .expect("canonical change set is serializable"))
}

/// Project one change onto its canonical, stable form.
fn canonical_effect(
    change: &Change,
    password_source_versions: &BTreeMap<String, String>,
) -> Result<Value, ApprovalDigestError> {
    if let Change::SetPassword { name, .. } = change {
        let source = password_source_versions
            .get(name)
            .ok_or_else(|| ApprovalDigestError::MissingPasswordSource { role: name.clone() })?;

        // The verifier is replaced by the source it was derived from: the same
        // source always yields the same effect, a rotated source never does.
        return Ok(serde_json::json!({
            "SetPassword": {
                "name": name,
                "password_source": source,
            }
        }));
    }

    Ok(serde_json::to_value(change).expect("change is serializable"))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    let digest = Sha256::digest(bytes);
    let mut hash = String::with_capacity(7 + digest.len() * 2);
    hash.push_str("sha256:");
    for byte in digest {
        write!(&mut hash, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ObjectType, Privilege};
    use crate::model::RoleState;

    fn versions(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(role, version)| ((*role).to_string(), (*version).to_string()))
            .collect()
    }

    /// Shared so the test helper can hand out a `&TargetIdentity` that
    /// outlives the borrow of the inputs it is embedded in.
    static TARGET_IDENTITY: std::sync::LazyLock<TargetIdentity> =
        std::sync::LazyLock::new(|| TargetIdentity {
            physical: Some("7412330000000000001".to_string()),
            logical: Some("sha256:fingerprint".to_string()),
        });

    fn inputs<'a>(
        password_source_versions: &'a BTreeMap<String, String>,
    ) -> EffectDigestInputs<'a> {
        EffectDigestInputs {
            reconciliation_mode: ReconciliationMode::Authoritative,
            target: "default/postgres-credentials:url",
            target_identity: &TARGET_IDENTITY,
            password_source_versions,
            owned_roles: &[],
            owned_schemas: &[],
        }
    }

    /// The lost-management review scenario: dropping a role from management
    /// produces no SQL at all, so scope must be bound for the digest — and
    /// therefore the approval — to notice.
    #[test]
    fn a_management_scope_change_changes_the_digest_with_identical_effects() {
        let changes = [create_role("reader")];
        let versions = BTreeMap::new();
        let narrow = ["app_reader".to_string()];
        let wide = ["app_reader".to_string(), "team_y_user".to_string()];
        let mut inputs_narrow = inputs(&versions);
        inputs_narrow.owned_roles = &narrow;
        let mut inputs_wide = inputs(&versions);
        inputs_wide.owned_roles = &wide;
        assert_ne!(
            compute_change_digest(&changes, &inputs_narrow).expect("digest"),
            compute_change_digest(&changes, &inputs_wide).expect("digest"),
        );
    }

    /// Scope is a set: listing order and duplicates are canonicalised away.
    #[test]
    fn management_scope_order_and_duplicates_do_not_change_the_digest() {
        let changes = [create_role("reader")];
        let versions = BTreeMap::new();
        let forward = ["a".to_string(), "b".to_string()];
        let shuffled = ["b".to_string(), "a".to_string(), "b".to_string()];
        let mut inputs_forward = inputs(&versions);
        inputs_forward.owned_roles = &forward;
        let mut inputs_shuffled = inputs(&versions);
        inputs_shuffled.owned_roles = &shuffled;
        assert_eq!(
            compute_change_digest(&changes, &inputs_forward).expect("digest"),
            compute_change_digest(&changes, &inputs_shuffled).expect("digest"),
        );
    }

    fn set_password(name: &str, verifier: &str) -> Change {
        Change::SetPassword {
            name: name.to_string(),
            password: verifier.to_string(),
        }
    }

    fn create_role(name: &str) -> Change {
        Change::CreateRole {
            name: name.to_string(),
            state: RoleState {
                login: true,
                ..RoleState::default()
            },
        }
    }

    fn grant(role: &str) -> Change {
        Change::Grant {
            role: role.to_string(),
            privileges: [Privilege::Select].into_iter().collect(),
            object_type: ObjectType::Table,
            schema: Some("inventory".to_string()),
            name: Some("orders".to_string()),
        }
    }

    /// The regression that motivates this module (#174): a fresh SCRAM salt on
    /// every diff must not change the approval identity.
    #[test]
    fn password_verifier_does_not_affect_the_digest() {
        let versions = versions(&[("app", "role-passwords:app:7")]);
        let inputs = inputs(&versions);

        let first = compute_change_digest(
            &[set_password(
                "app",
                "SCRAM-SHA-256$4096:saltA$storedA:serverA",
            )],
            &inputs,
        )
        .expect("digest");
        let second = compute_change_digest(
            &[set_password(
                "app",
                "SCRAM-SHA-256$4096:saltB$storedB:serverB",
            )],
            &inputs,
        )
        .expect("digest");

        assert_eq!(
            first, second,
            "a re-derived verifier for an unchanged source must keep the same approval identity"
        );
    }

    #[test]
    fn rotating_the_password_source_changes_the_digest() {
        let before = versions(&[("app", "role-passwords:app:7")]);
        let after = versions(&[("app", "role-passwords:app:8")]);
        let change = [set_password("app", "SCRAM-SHA-256$4096:salt$stored:server")];

        assert_ne!(
            compute_change_digest(&change, &inputs(&before)).expect("digest"),
            compute_change_digest(&change, &inputs(&after)).expect("digest"),
            "an approval must not carry over to a different password source"
        );
    }

    #[test]
    fn a_password_change_without_a_source_version_fails_closed() {
        let empty = BTreeMap::new();

        assert_eq!(
            compute_change_digest(&[set_password("app", "SCRAM-SHA-256$...")], &inputs(&empty)),
            Err(ApprovalDigestError::MissingPasswordSource {
                role: "app".to_string()
            })
        );
    }

    #[test]
    fn emission_order_does_not_affect_the_digest() {
        let versions = BTreeMap::new();
        let inputs = inputs(&versions);
        let forward = [create_role("reporting"), grant("reporting")];
        let reversed = [grant("reporting"), create_role("reporting")];

        assert_eq!(
            compute_change_digest(&forward, &inputs).expect("digest"),
            compute_change_digest(&reversed, &inputs).expect("digest"),
        );
    }

    #[test]
    fn effects_are_bound_to_the_reconciliation_mode() {
        let versions = BTreeMap::new();
        let changes = [grant("reporting")];

        let authoritative = compute_change_digest(&changes, &inputs(&versions)).expect("digest");
        let additive = compute_change_digest(
            &changes,
            &EffectDigestInputs {
                reconciliation_mode: ReconciliationMode::Additive,
                ..inputs(&versions)
            },
        )
        .expect("digest");

        assert_ne!(authoritative, additive);
    }

    #[test]
    fn effects_are_bound_to_the_target() {
        let versions = BTreeMap::new();
        let changes = [grant("reporting")];

        let original = compute_change_digest(&changes, &inputs(&versions)).expect("digest");
        let repointed = compute_change_digest(
            &changes,
            &EffectDigestInputs {
                target: "default/other-credentials:url",
                ..inputs(&versions)
            },
        )
        .expect("digest");

        assert_ne!(
            original, repointed,
            "an approval must not carry over to a different database"
        );
    }

    #[test]
    fn effects_are_bound_to_both_halves_of_the_target_identity() {
        let versions = BTreeMap::new();
        let changes = [grant("reporting")];

        let baseline = compute_change_digest(&changes, &inputs(&versions)).expect("digest");

        // A clone or a branch: same storage lineage, different endpoint.
        let cloned = TargetIdentity {
            logical: Some("sha256:other-endpoint".to_string()),
            ..TARGET_IDENTITY.clone()
        };
        // A restore from elsewhere behind an unchanged endpoint.
        let restored = TargetIdentity {
            physical: Some("7412330000000000002".to_string()),
            ..TARGET_IDENTITY.clone()
        };
        // Physical identity no longer readable — a downgrade, not a match.
        let downgraded = TargetIdentity {
            physical: None,
            ..TARGET_IDENTITY.clone()
        };

        for moved in [cloned, restored, downgraded] {
            assert_ne!(
                baseline,
                compute_change_digest(
                    &changes,
                    &EffectDigestInputs {
                        target_identity: &moved,
                        ..inputs(&versions)
                    },
                )
                .expect("digest"),
                "an approval must not carry over to a different target identity"
            );
        }
    }

    #[test]
    fn an_unchanged_target_identity_keeps_the_digest() {
        let versions = BTreeMap::new();
        let changes = [grant("reporting")];
        let same = TARGET_IDENTITY.clone();

        assert_eq!(
            compute_change_digest(&changes, &inputs(&versions)).expect("digest"),
            compute_change_digest(
                &changes,
                &EffectDigestInputs {
                    target_identity: &same,
                    ..inputs(&versions)
                },
            )
            .expect("digest"),
        );
    }

    fn identity(physical: Option<&str>, logical: Option<&str>) -> TargetIdentity {
        TargetIdentity {
            physical: physical.map(str::to_string),
            logical: logical.map(str::to_string),
        }
    }

    #[test]
    fn an_unchanged_identity_proceeds() {
        let approved = identity(Some("id-1"), Some("fp-1"));
        assert_eq!(
            evaluate_target_identity(&approved, &approved.clone(), false),
            TargetIdentityVerdict::Proceed
        );
        assert_eq!(
            evaluate_target_identity(&approved, &approved, true),
            TargetIdentityVerdict::Proceed
        );
    }

    /// The ordinary shape on engines without `pg_control_system()`: no
    /// physical identity at either end is not an anomaly.
    #[test]
    fn consistent_physical_unavailability_proceeds() {
        let logical_only = identity(None, Some("fp-1"));
        assert_eq!(
            evaluate_target_identity(&logical_only, &logical_only.clone(), false),
            TargetIdentityVerdict::Proceed
        );
    }

    #[test]
    fn a_changed_physical_identity_supersedes() {
        assert_eq!(
            evaluate_target_identity(
                &identity(Some("id-1"), Some("fp-1")),
                &identity(Some("id-2"), Some("fp-1")),
                false,
            ),
            TargetIdentityVerdict::Superseded(TargetIdentityReason::TargetChanged)
        );
    }

    #[test]
    fn a_changed_logical_fingerprint_supersedes() {
        assert_eq!(
            evaluate_target_identity(
                &identity(Some("id-1"), Some("fp-1")),
                &identity(Some("id-1"), Some("fp-2")),
                false,
            ),
            TargetIdentityVerdict::Superseded(TargetIdentityReason::TargetChanged)
        );
    }

    /// Revoking `EXECUTE` between approval and execution must not buy a silent
    /// demotion to the logical answer alone.
    #[test]
    fn a_physical_downgrade_supersedes() {
        assert_eq!(
            evaluate_target_identity(
                &identity(Some("id-1"), Some("fp-1")),
                &identity(None, Some("fp-1")),
                false,
            ),
            TargetIdentityVerdict::Superseded(TargetIdentityReason::TargetIdentityUnavailable)
        );
    }

    /// The mirror case: the approval was never bound to an identity that is
    /// now readable, so it is re-reviewed exactly once.
    #[test]
    fn a_physical_upgrade_supersedes_once() {
        assert_eq!(
            evaluate_target_identity(
                &identity(None, Some("fp-1")),
                &identity(Some("id-1"), Some("fp-1")),
                false,
            ),
            TargetIdentityVerdict::Superseded(TargetIdentityReason::TargetIdentityAppeared)
        );
    }

    #[test]
    fn require_physical_identity_blocks_when_it_is_unavailable() {
        // Unavailable now.
        assert_eq!(
            evaluate_target_identity(
                &identity(Some("id-1"), Some("fp-1")),
                &identity(None, Some("fp-1")),
                true,
            ),
            TargetIdentityVerdict::Blocked(TargetIdentityReason::PhysicalIdentityRequired)
        );
        // Never bound at approval.
        assert_eq!(
            evaluate_target_identity(
                &identity(None, Some("fp-1")),
                &identity(Some("id-1"), Some("fp-1")),
                true,
            ),
            TargetIdentityVerdict::Blocked(TargetIdentityReason::PhysicalIdentityRequired)
        );
        // Consistently unavailable — ordinary elsewhere, blocked here.
        assert_eq!(
            evaluate_target_identity(
                &identity(None, Some("fp-1")),
                &identity(None, Some("fp-1")),
                true,
            ),
            TargetIdentityVerdict::Blocked(TargetIdentityReason::PhysicalIdentityRequired)
        );
    }

    /// A physical mismatch is reported as a mismatch even under
    /// `requirePhysicalIdentity`, since both identities are readable.
    #[test]
    fn require_physical_identity_still_reports_a_mismatch_as_a_supersede() {
        assert_eq!(
            evaluate_target_identity(
                &identity(Some("id-1"), Some("fp-1")),
                &identity(Some("id-2"), Some("fp-1")),
                true,
            ),
            TargetIdentityVerdict::Superseded(TargetIdentityReason::TargetChanged)
        );
    }

    #[test]
    fn different_effects_produce_different_digests() {
        let versions = BTreeMap::new();
        let inputs = inputs(&versions);

        assert_ne!(
            compute_change_digest(&[grant("reporting")], &inputs).expect("digest"),
            compute_change_digest(&[grant("analytics")], &inputs).expect("digest"),
        );
    }

    #[test]
    fn an_empty_change_set_has_a_stable_digest() {
        let versions = BTreeMap::new();
        let inputs = inputs(&versions);

        assert_eq!(
            compute_change_digest(&[], &inputs).expect("digest"),
            compute_change_digest(&[], &inputs).expect("digest"),
        );
    }

    #[test]
    fn the_digest_is_prefixed_and_hex_encoded() {
        let versions = BTreeMap::new();
        let digest =
            compute_change_digest(&[grant("reporting")], &inputs(&versions)).expect("digest");

        let hex = digest.strip_prefix("sha256:").expect("sha256: prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Pin the exact canonical bytes for a fixed input.
    ///
    /// The digest is only stable if the serialization is. `serde_json` emits
    /// object keys in declaration order by default, but its `preserve_order`
    /// feature switches to insertion order — and any dependency in the graph
    /// can enable it, silently changing every digest without changing
    /// `APPROVAL_EFFECT_ENCODING_V2`. Pending approvals would then be
    /// superseded across an unrelated dependency bump.
    ///
    /// Note the object keys come out *alphabetically*, not in struct
    /// declaration order, because effects round-trip through
    /// `serde_json::Value`, whose `Object` is `BTreeMap`-backed. That is a
    /// useful property — reordering fields in `Change` cannot change a digest
    /// — and `preserve_order` is exactly what would take it away.
    ///
    /// If this test fails, the encoding changed: bump the encoding constant
    /// deliberately rather than updating the expected bytes in place.
    #[test]
    fn canonical_bytes_are_pinned_for_a_fixed_input() {
        let versions = versions(&[("app", "role-passwords:app:7")]);
        let changes = [
            grant("reporting"),
            set_password("app", "SCRAM-SHA-256$4096:salt$stored:server"),
        ];

        let bytes = canonical_change_set_bytes(&changes, &inputs(&versions)).expect("bytes");
        let encoded = String::from_utf8(bytes).expect("canonical bytes are UTF-8 JSON");

        // The management-scope fields joined this encoding before v2 ever
        // shipped in a release, so the constant keeps its name; from the
        // first released v2 onward, any change here means a new constant.
        assert_eq!(
            encoded,
            r#"{"effect_encoding":"pgroles.io/approval-effect/v2","reconciliation_mode":"Authoritative","target":"default/postgres-credentials:url","target_physical_identity":"7412330000000000001","target_logical_fingerprint":"sha256:fingerprint","owned_roles":[],"owned_schemas":[],"effects":[{"Grant":{"name":"orders","object_type":"table","privileges":["SELECT"],"role":"reporting","schema":"inventory"}},{"SetPassword":{"name":"app","password_source":"role-passwords:app:7"}}]}"#,
            "canonical encoding changed; bump the encoding constant rather than \
             editing this fixture"
        );
    }

    #[test]
    fn the_digest_never_contains_password_material() {
        let versions = versions(&[("app", "role-passwords:app:7")]);
        let verifier = "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy";

        // The canonical form is what gets hashed; assert on it directly so a
        // future refactor cannot quietly reintroduce the verifier.
        let effect = canonical_effect(&set_password("app", verifier), &versions).expect("effect");
        let rendered = effect.to_string();

        assert!(!rendered.contains(verifier));
        assert!(!rendered.contains("SCRAM-SHA-256"));
        assert!(rendered.contains("role-passwords:app:7"));
    }
}
