//! Canonical content digest for policy candidates.
//!
//! A `PostgresPolicyCandidate` is reviewed once and promoted later, by a
//! different actor, through a different channel (a Git merge). The only thing
//! that ties the promoted `PostgresPolicy.spec` back to the reviewed proposal
//! is a digest over the *content*, so the digest must depend on what the
//! content means and on nothing else.
//!
//! This module follows the discipline already established by
//! [`crate::approval`] and the ephemeral bundle hash: a named encoding
//! constant, a deterministic canonical byte form, and a `sha256:`-prefixed
//! digest over exactly those bytes.
//!
//! # What the canonical form does
//!
//! Content is projected to JSON and then normalised:
//!
//! - object keys are sorted lexicographically, so map iteration order and
//!   struct field order cannot change the digest;
//! - `null` values are dropped, so an explicitly-null optional field is the
//!   same content as an omitted one;
//! - empty arrays and empty objects are dropped, so `grants: []` is the same
//!   content as omitting `grants` — which it is, since every content
//!   collection defaults to empty;
//! - no whitespace is emitted.
//!
//! Dropping empties is what makes the digest survive the round trip through
//! the API server. The same manifest written by hand, by `kubectl apply`, and
//! by a GitOps controller differs in exactly these ways and in no other.
//!
//! # What the canonical form deliberately does not do
//!
//! It does not resolve defaults. `role_pattern` omitted and `role_pattern:
//! "{schema}-{profile}"` are *different* content, because resolving defaults
//! here would make the digest depend on a default value that may change — the
//! same hazard that motivates suppressing OpenAPI defaults under
//! `spec.content` (ADR-001, Decision 2).

use serde::Serialize;
use serde_json::{Map, Value};

/// Version tag for the canonical content encoding.
///
/// Any change to normalisation, ordering, or the envelope must introduce a new
/// constant. Digests computed under different encodings are never comparable,
/// so a candidate carrying an older encoding is replanned rather than silently
/// treated as matching.
pub const CANDIDATE_CONTENT_ENCODING_V1: &str = "pgroles.io/candidate-content/v1";

/// Compute the canonical content digest for candidate content.
///
/// Returns a `sha256:<hex>` string over [`canonical_content_bytes`].
pub fn compute_content_digest<T: Serialize>(content: &T) -> String {
    sha256_prefixed(&canonical_content_bytes(content))
}

/// The exact bytes [`compute_content_digest`] hashes.
///
/// Exposed for the same reason [`crate::approval::canonical_change_set_bytes`]
/// is: a digest never contains its input, so only the bytes can show what was
/// bound and what was normalised away.
pub fn canonical_content_bytes<T: Serialize>(content: &T) -> Vec<u8> {
    let value = serde_json::to_value(content).expect("policy content is serializable");

    let mut envelope = Map::new();
    envelope.insert(
        "encoding".to_string(),
        Value::String(CANDIDATE_CONTENT_ENCODING_V1.to_string()),
    );
    envelope.insert("content".to_string(), canonicalize(value));

    // `serde_json::Map` is a `BTreeMap` unless `preserve_order` is enabled, and
    // `canonicalize` rebuilds every nested object in sorted order regardless,
    // so serialization here is key-ordered either way.
    serde_json::to_vec(&Value::Object(envelope)).expect("canonical content is serializable")
}

/// Normalise a JSON value: sort object keys, drop nulls and empty containers.
fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, Value> = Default::default();
            for (key, entry) in map {
                let entry = canonicalize(entry);
                if is_empty(&entry) {
                    continue;
                }
                sorted.insert(key, entry);
            }
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize)
                // Elements are positional: dropping one would shift the rest,
                // so only *container-level* emptiness is normalised away.
                .collect(),
        ),
        other => other,
    }
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(map) => map.is_empty(),
        Value::Array(items) => items.is_empty(),
        _ => false,
    }
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

    fn json(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture is valid JSON")
    }

    /// Byte-level fixture pinning the encoding. This is the contract: changing
    /// it changes every stored digest, so it must be a deliberate act with a
    /// new encoding constant, not a side effect of an unrelated refactor.
    #[test]
    fn canonical_bytes_are_pinned() {
        let content = json(
            r#"{
                "roles": [{"name": "reporting-reader", "login": true}],
                "reconciliation_mode": "authoritative",
                "grants": [],
                "default_owner": null
            }"#,
        );

        assert_eq!(
            String::from_utf8(canonical_content_bytes(&content)).unwrap(),
            concat!(
                r#"{"content":{"reconciliation_mode":"authoritative","#,
                r#""roles":[{"login":true,"name":"reporting-reader"}]},"#,
                r#""encoding":"pgroles.io/candidate-content/v1"}"#,
            )
        );

        assert_eq!(
            compute_content_digest(&content),
            "sha256:5ef20a282cdaa20ea621f17cd5b83b61d789e27deacb72c3ccce7b2678743eba"
        );
    }

    #[test]
    fn key_order_does_not_change_the_digest() {
        assert_eq!(
            compute_content_digest(&json(r#"{"a": 1, "b": 2}"#)),
            compute_content_digest(&json(r#"{"b": 2, "a": 1}"#)),
        );
    }

    #[test]
    fn omitted_and_empty_collections_are_the_same_content() {
        assert_eq!(
            compute_content_digest(&json(r#"{"roles": [{"name": "a"}]}"#)),
            compute_content_digest(&json(
                r#"{"roles": [{"name": "a"}], "grants": [], "profiles": {}}"#
            )),
        );
    }

    #[test]
    fn explicit_null_and_omitted_are_the_same_content() {
        assert_eq!(
            compute_content_digest(&json(r#"{"roles": [{"name": "a"}]}"#)),
            compute_content_digest(&json(
                r#"{"roles": [{"name": "a"}], "default_owner": null}"#
            )),
        );
    }

    /// Defaults are *not* resolved: an omitted field and its default value are
    /// distinct content, so a change to a default value can never silently
    /// re-point an existing digest at different content.
    #[test]
    fn an_omitted_field_differs_from_its_written_default() {
        assert_ne!(
            compute_content_digest(&json(r#"{"schemas": [{"name": "app"}]}"#)),
            compute_content_digest(&json(
                r#"{"schemas": [{"name": "app", "role_pattern": "{schema}-{profile}"}]}"#
            )),
        );
    }

    #[test]
    fn list_order_is_significant() {
        assert_ne!(
            compute_content_digest(&json(r#"{"roles": [{"name": "a"}, {"name": "b"}]}"#)),
            compute_content_digest(&json(r#"{"roles": [{"name": "b"}, {"name": "a"}]}"#)),
        );
    }
}
