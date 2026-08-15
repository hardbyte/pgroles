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
//! - the target database identity, so an approval cannot be reused against a
//!   different server
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

use std::collections::BTreeMap;

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
    /// Identity of the database the effects were computed against.
    pub target: &'a str,
    /// Stable password source identity per role, keyed by role name — for the
    /// operator this is `secret:key:resourceVersion`. Every role named by a
    /// `SetPassword` change must have an entry.
    pub password_source_versions: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct CanonicalChangeSet<'a> {
    effect_encoding: &'a str,
    reconciliation_mode: ReconciliationMode,
    target: &'a str,
    effects: Vec<Value>,
}

/// Compute the canonical approval-effect digest for a set of changes.
///
/// The result is stable across recomputation of the same semantic effects and
/// independent of the order the diff engine emitted them in.
pub fn compute_change_digest(
    changes: &[Change],
    inputs: &EffectDigestInputs<'_>,
) -> Result<String, ApprovalDigestError> {
    let mut effects = Vec::with_capacity(changes.len());
    for change in changes {
        effects.push(canonical_effect(change, inputs.password_source_versions)?);
    }

    // Dependency ordering is an execution concern; two plans with the same set
    // of effects are the same approval regardless of emission order.
    effects.sort_by_cached_key(ToString::to_string);

    let bytes = serde_json::to_vec(&CanonicalChangeSet {
        effect_encoding: APPROVAL_EFFECT_ENCODING_V1,
        reconciliation_mode: inputs.reconciliation_mode,
        target: inputs.target,
        effects,
    })
    .expect("canonical change set is serializable");

    Ok(sha256_prefixed(&bytes))
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

    fn inputs<'a>(
        password_source_versions: &'a BTreeMap<String, String>,
    ) -> EffectDigestInputs<'a> {
        EffectDigestInputs {
            reconciliation_mode: ReconciliationMode::Authoritative,
            target: "default/postgres-credentials:url",
            password_source_versions,
        }
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
