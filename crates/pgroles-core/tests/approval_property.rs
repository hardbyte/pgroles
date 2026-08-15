//! Property tests for the canonical approval-effect digest
//! (`pgroles_core::approval`).
//!
//! The digest is an *approval gate* for SQL executed against production
//! databases, so its contract is adversarial rather than merely functional:
//!
//! - **stable** where it must be — recomputation of unchanged effects yields
//!   the same digest, including when the rendered SQL would differ (#174)
//! - **sensitive** where it must be — any change to the effects, the password
//!   source, the reconciliation mode, or the target database changes it
//! - **injective in practice** — distinct effect sets do not collide, because
//!   a collision would let an approval for one change authorise another
//!
//! Unit tests in `src/approval.rs` pin these on hand-written examples. This
//! suite checks them across a large pseudo-random space of change sets, which
//! is where an encoding mistake (a field omitted from serialization, two
//! variants flattening to the same shape) would actually show up.
//!
//! Following `diff_property.rs`, this uses a tiny seeded xorshift64* PRNG so
//! runs are reproducible with no extra dependencies; failures print the seed.

use std::collections::{BTreeMap, BTreeSet};

use pgroles_core::approval::{
    EffectDigestInputs, TargetIdentity, canonical_change_set_bytes, compute_change_digest,
};
use pgroles_core::diff::{Change, ReconciliationMode};
use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::{RoleAttribute, RoleState};

const CASES: usize = 400;

// ---------------------------------------------------------------------------
// PRNG (same shape as diff_property.rs)
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn usize(&mut self, modulus: usize) -> usize {
        if modulus == 0 {
            return 0;
        }
        (self.next_u64() as usize) % modulus
    }
    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

const ROLES: &[&str] = &["app", "reporting", "analytics", "owner", "legacy"];
const SCHEMAS: &[&str] = &["public", "inventory", "catalog"];
const OBJECTS: &[&str] = &["orders", "customers", "*"];

fn role(rng: &mut Rng) -> String {
    ROLES[rng.usize(ROLES.len())].to_string()
}

fn privileges(rng: &mut Rng) -> BTreeSet<Privilege> {
    const ALL: &[Privilege] = &[
        Privilege::Select,
        Privilege::Insert,
        Privilege::Update,
        Privilege::Delete,
        Privilege::Usage,
        Privilege::Execute,
        Privilege::Create,
        Privilege::Connect,
    ];
    let count = 1 + rng.usize(3);
    (0..count).map(|_| ALL[rng.usize(ALL.len())]).collect()
}

fn object_type(rng: &mut Rng) -> ObjectType {
    const ALL: &[ObjectType] = &[
        ObjectType::Table,
        ObjectType::View,
        ObjectType::MaterializedView,
        ObjectType::Sequence,
        ObjectType::Function,
        ObjectType::Schema,
    ];
    ALL[rng.usize(ALL.len())]
}

/// One arbitrary change. Covers every variant that carries semantics an
/// approval must bind.
fn change(rng: &mut Rng) -> Change {
    match rng.usize(17) {
        0 => Change::CreateRole {
            name: role(rng),
            state: RoleState {
                login: rng.bool(),
                superuser: rng.bool(),
                createdb: rng.bool(),
                connection_limit: rng.usize(4) as i32 - 1,
                comment: if rng.bool() {
                    Some("managed".to_string())
                } else {
                    None
                },
                ..RoleState::default()
            },
        },
        1 => Change::CreateSchema {
            name: SCHEMAS[rng.usize(SCHEMAS.len())].to_string(),
            owner: if rng.bool() { Some(role(rng)) } else { None },
        },
        2 => Change::AlterSchemaOwner {
            name: SCHEMAS[rng.usize(SCHEMAS.len())].to_string(),
            owner: role(rng),
        },
        3 => Change::AlterRole {
            name: role(rng),
            attributes: vec![
                RoleAttribute::Login(rng.bool()),
                RoleAttribute::ConnectionLimit(rng.usize(8) as i32 - 1),
            ],
        },
        4 => Change::SetComment {
            name: role(rng),
            comment: if rng.bool() {
                Some(format!("note-{}", rng.usize(4)))
            } else {
                None
            },
        },
        5 => Change::Grant {
            role: role(rng),
            privileges: privileges(rng),
            object_type: object_type(rng),
            schema: Some(SCHEMAS[rng.usize(SCHEMAS.len())].to_string()),
            name: Some(OBJECTS[rng.usize(OBJECTS.len())].to_string()),
        },
        6 => Change::Revoke {
            role: role(rng),
            privileges: privileges(rng),
            object_type: object_type(rng),
            schema: Some(SCHEMAS[rng.usize(SCHEMAS.len())].to_string()),
            name: Some(OBJECTS[rng.usize(OBJECTS.len())].to_string()),
        },
        7 => Change::SetDefaultPrivilege {
            owner: role(rng),
            schema: SCHEMAS[rng.usize(SCHEMAS.len())].to_string(),
            on_type: object_type(rng),
            grantee: role(rng),
            privileges: privileges(rng),
        },
        8 => Change::RevokeDefaultPrivilege {
            owner: role(rng),
            schema: SCHEMAS[rng.usize(SCHEMAS.len())].to_string(),
            on_type: object_type(rng),
            grantee: role(rng),
            privileges: privileges(rng),
        },
        9 => Change::AddMember {
            role: role(rng),
            member: role(rng),
            inherit: rng.bool(),
            admin: rng.bool(),
        },
        10 => Change::RemoveMember {
            role: role(rng),
            member: role(rng),
        },
        11 => Change::ReassignOwned {
            from_role: role(rng),
            to_role: role(rng),
        },
        12 => Change::DropRole { name: role(rng) },
        // DropOwned and TerminateSessions both carry a single `role` field,
        // so they are the likeliest pair to flatten to the same encoded shape
        // — exactly the collision this suite exists to rule out.
        13 => Change::DropOwned { role: role(rng) },
        14 => Change::TerminateSessions { role: role(rng) },
        15 => Change::EnsureSchemaOwnerPrivileges {
            name: SCHEMAS[rng.usize(SCHEMAS.len())].to_string(),
            owner: role(rng),
            privileges: privileges(rng),
        },
        _ => Change::SetPassword {
            name: role(rng),
            // Stands in for a freshly salted SCRAM verifier.
            password: format!("SCRAM-SHA-256$4096:salt{}$stored:server", rng.next_u64()),
        },
    }
}

fn change_set(rng: &mut Rng) -> Vec<Change> {
    let count = rng.usize(8);
    (0..count).map(|_| change(rng)).collect()
}

/// Every role gets a source version, so any generated `SetPassword` is bound.
fn all_password_versions(tag: &str) -> BTreeMap<String, String> {
    ROLES
        .iter()
        .map(|r| ((*r).to_string(), format!("role-passwords:{r}:{tag}")))
        .collect()
}

/// The identity the operator would observe against a fixed target.
fn target_identity() -> TargetIdentity {
    TargetIdentity {
        physical: Some("7412330000000000001".to_string()),
        logical: Some("sha256:fingerprint".to_string()),
    }
}

fn digest(changes: &[Change], versions: &BTreeMap<String, String>) -> String {
    compute_change_digest(
        changes,
        &EffectDigestInputs {
            reconciliation_mode: ReconciliationMode::Authoritative,
            target: "default/postgres-credentials:url",
            target_identity: &target_identity(),
            password_source_versions: versions,
        },
    )
    .expect("every generated role has a password source version")
}

/// Re-derive every password verifier, as a fresh reconcile would.
fn resalt(changes: &[Change], rng: &mut Rng) -> Vec<Change> {
    changes
        .iter()
        .map(|c| match c {
            Change::SetPassword { name, .. } => Change::SetPassword {
                name: name.clone(),
                password: format!("SCRAM-SHA-256$4096:salt{}$stored:server", rng.next_u64()),
            },
            other => other.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// Recomputing the same effects yields the same digest — including when every
/// SCRAM verifier is re-derived. This is #174 as a property: an unchanged
/// password source must not churn the approval identity.
#[test]
fn digest_is_stable_under_verifier_rederivation() {
    let versions = all_password_versions("7");
    for seed in 1..=CASES as u64 {
        let mut rng = Rng::new(seed);
        let changes = change_set(&mut rng);
        let resalted = resalt(&changes, &mut rng);

        assert_eq!(
            digest(&changes, &versions),
            digest(&resalted, &versions),
            "seed {seed}: re-deriving verifiers changed the approval identity"
        );
    }
}

/// The digest does not depend on the order the diff engine emitted changes in.
#[test]
fn digest_is_independent_of_emission_order() {
    let versions = all_password_versions("7");
    for seed in 1..=CASES as u64 {
        let mut rng = Rng::new(seed);
        let changes = change_set(&mut rng);
        if changes.len() < 2 {
            continue;
        }

        let mut shuffled = changes.clone();
        for i in (1..shuffled.len()).rev() {
            shuffled.swap(i, rng.usize(i + 1));
        }

        assert_eq!(
            digest(&changes, &versions),
            digest(&shuffled, &versions),
            "seed {seed}: reordering identical effects changed the digest"
        );
    }
}

/// Distinct effect sets must not collide: a collision would let an approval
/// for one change set authorise a different one.
#[test]
fn distinct_effect_sets_do_not_collide() {
    let versions = all_password_versions("7");
    let mut seen: BTreeMap<String, Vec<Change>> = BTreeMap::new();

    for seed in 1..=(CASES * 4) as u64 {
        let mut rng = Rng::new(seed);
        let changes = change_set(&mut rng);
        let d = digest(&changes, &versions);

        // Canonicalise for comparison the same way the digest does — as a
        // multiset of effects, with password verifiers reduced to the role
        // they act on (the verifier is deliberately not part of identity).
        let key = canonical_key(&changes);

        if let Some(previous) = seen.get(&d) {
            assert_eq!(
                canonical_key(previous),
                key,
                "seed {seed}: two different effect sets produced the same digest {d}"
            );
        } else {
            seen.insert(d, changes);
        }
    }
}

/// Rotating any password source changes the digest, so an approval never
/// carries across a credential rotation.
#[test]
fn rotating_a_password_source_changes_the_digest() {
    let before = all_password_versions("7");
    let after = all_password_versions("8");

    for seed in 1..=CASES as u64 {
        let mut rng = Rng::new(seed);
        let changes = change_set(&mut rng);
        if !changes
            .iter()
            .any(|c| matches!(c, Change::SetPassword { .. }))
        {
            continue;
        }

        assert_ne!(
            digest(&changes, &before),
            digest(&changes, &after),
            "seed {seed}: an approval survived a password source rotation"
        );
    }
}

/// The reconciliation mode and the target database are part of the identity:
/// the same effects under a different mode, or against a different server,
/// are a different approval.
#[test]
fn digest_binds_mode_and_target() {
    let versions = all_password_versions("7");

    for seed in 1..=CASES as u64 {
        let mut rng = Rng::new(seed);
        let changes = change_set(&mut rng);
        if changes.is_empty() {
            continue;
        }

        let base = digest(&changes, &versions);

        let other_mode = compute_change_digest(
            &changes,
            &EffectDigestInputs {
                reconciliation_mode: ReconciliationMode::Additive,
                target: "default/postgres-credentials:url",
                target_identity: &target_identity(),
                password_source_versions: &versions,
            },
        )
        .expect("digest");

        let other_target = compute_change_digest(
            &changes,
            &EffectDigestInputs {
                reconciliation_mode: ReconciliationMode::Authoritative,
                target: "default/other-credentials:url",
                target_identity: &target_identity(),
                password_source_versions: &versions,
            },
        )
        .expect("digest");

        let moved_physical = compute_change_digest(
            &changes,
            &EffectDigestInputs {
                reconciliation_mode: ReconciliationMode::Authoritative,
                target: "default/postgres-credentials:url",
                target_identity: &TargetIdentity {
                    physical: Some("7412330000000000002".to_string()),
                    ..target_identity()
                },
                password_source_versions: &versions,
            },
        )
        .expect("digest");

        let moved_logical = compute_change_digest(
            &changes,
            &EffectDigestInputs {
                reconciliation_mode: ReconciliationMode::Authoritative,
                target: "default/postgres-credentials:url",
                target_identity: &TargetIdentity {
                    logical: Some("sha256:other-endpoint".to_string()),
                    ..target_identity()
                },
                password_source_versions: &versions,
            },
        )
        .expect("digest");

        assert_ne!(base, other_mode, "seed {seed}: mode not bound into digest");
        assert_ne!(
            base, other_target,
            "seed {seed}: target not bound into digest"
        );
        assert_ne!(
            base, moved_physical,
            "seed {seed}: physical target identity not bound into digest"
        );
        assert_ne!(
            base, moved_logical,
            "seed {seed}: logical target fingerprint not bound into digest"
        );
    }
}

/// Adding or removing any single effect changes the digest.
#[test]
fn every_effect_contributes_to_the_digest() {
    let versions = all_password_versions("7");

    for seed in 1..=CASES as u64 {
        let mut rng = Rng::new(seed);
        let changes = change_set(&mut rng);
        if changes.is_empty() {
            continue;
        }

        let full = digest(&changes, &versions);
        let dropped_index = rng.usize(changes.len());
        let mut reduced = changes.clone();
        let removed = reduced.remove(dropped_index);

        // Removing a duplicate leaves the multiset otherwise intact only when
        // no identical effect remains; skip those cases rather than assert a
        // property the encoding does not claim.
        if reduced.contains(&removed) {
            continue;
        }

        assert_ne!(
            full,
            digest(&reduced, &versions),
            "seed {seed}: dropping an effect left the digest unchanged"
        );
    }
}

/// No password material may reach the bytes that are hashed.
///
/// This asserts on the canonical bytes rather than the digest: a hash never
/// contains its input literally, so checking the digest string would pass even
/// if the verifier were being hashed in.
#[test]
fn password_material_never_reaches_the_hashed_bytes() {
    let versions = all_password_versions("7");

    for seed in 1..=CASES as u64 {
        let mut rng = Rng::new(seed);
        let secret = format!("SUPERSECRET{}", rng.next_u64());
        let mut changes = change_set(&mut rng);
        changes.push(Change::SetPassword {
            name: role(&mut rng),
            password: secret.clone(),
        });

        let bytes = canonical_change_set_bytes(
            &changes,
            &EffectDigestInputs {
                reconciliation_mode: ReconciliationMode::Authoritative,
                target: "default/postgres-credentials:url",
                target_identity: &target_identity(),
                password_source_versions: &versions,
            },
        )
        .expect("digest inputs");
        let encoded = String::from_utf8(bytes).expect("canonical bytes are UTF-8 JSON");

        assert!(
            !encoded.contains(&secret),
            "seed {seed}: password material entered the hashed bytes"
        );
        assert!(
            !encoded.contains("SCRAM-SHA-256"),
            "seed {seed}: a SCRAM verifier entered the hashed bytes"
        );
        assert!(
            digest(&changes, &versions).starts_with("sha256:"),
            "seed {seed}: malformed digest"
        );
    }
}

/// Reduce a change set to what the digest treats as its identity.
fn canonical_key(changes: &[Change]) -> Vec<String> {
    let mut keys: Vec<String> = changes
        .iter()
        .map(|c| match c {
            Change::SetPassword { name, .. } => format!("SetPassword({name})"),
            other => format!("{other:?}"),
        })
        .collect();
    keys.sort();
    keys
}
