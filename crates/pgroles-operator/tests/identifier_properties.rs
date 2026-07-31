//! Property tests for every Kubernetes identifier the operator derives from
//! user input.
//!
//! The invariant is the one the API server enforces: whatever goes in, what
//! comes out is a *valid* identifier for its position. These are the rules
//! restated independently of the implementation, so a builder that regresses
//! fails here rather than in a cluster.
//!
//! Table tests pin the specific cases that broke in the past; these cover the
//! space around them. Both label values and resource names have been broken by
//! truncation landing on a separator, which is easy to miss by example and
//! immediate to catch by property.

use proptest::prelude::*;

use pgroles_operator::k8s_names::{
    LabelValue, MAX_LABEL_VALUE_LENGTH, MAX_RESOURCE_NAME_LENGTH, is_valid_label_value,
    is_valid_resource_name, sanitize_dns_label_segment, truncate_name_prefix,
};

/// The label-value rule as the API server states it:
/// `(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?` and at most 63 bytes.
fn is_label_value_per_apiserver(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > MAX_LABEL_VALUE_LENGTH {
        return false;
    }
    let first = value.chars().next().expect("non-empty");
    let last = value.chars().next_back().expect("non-empty");
    first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The RFC 1123 DNS subdomain rule, restated: dot-separated labels, each
/// non-empty, lowercase alphanumeric or `-`, starting and ending alphanumeric.
fn is_resource_name_per_apiserver(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_RESOURCE_NAME_LENGTH {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && label.chars().next().is_some_and(|c| c != '-')
            && label.chars().next_back().is_some_and(|c| c != '-')
    })
}

/// Inputs that stress the separator and boundary logic: the alphabet is biased
/// towards the characters that actually break things, plus multi-byte UTF-8.
fn hostile_input() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just('a'),
            Just('9'),
            Just('Z'),
            Just('_'),
            Just('.'),
            Just('-'),
            Just('/'),
            Just('='),
            Just('\0'),
            Just(' '),
            Just('é'),
            Just('日'),
            any::<char>(),
        ],
        0..200usize,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    /// `LabelValue::sanitize` must accept anything and always produce a value
    /// the API server accepts.
    #[test]
    fn sanitized_label_values_are_always_valid(input in hostile_input()) {
        let value = LabelValue::sanitize(&input);
        let s = value.as_str();

        prop_assert!(
            is_label_value_per_apiserver(s),
            "sanitize({input:?}) produced invalid label value {s:?}"
        );
        // Cross-check the module's own validator against the restated rule.
        prop_assert_eq!(is_valid_label_value(s), is_label_value_per_apiserver(s));
        // The byte length is what Kubernetes counts, not the character count.
        prop_assert!(s.len() <= MAX_LABEL_VALUE_LENGTH);
    }

    /// Sanitizing is idempotent: feeding a sanitized value back through must
    /// not change it. Selectors are built by sanitizing, so a non-idempotent
    /// builder would make lookups disagree with writes.
    #[test]
    fn sanitizing_a_label_value_is_idempotent(input in hostile_input()) {
        let once = LabelValue::sanitize(&input);
        let twice = LabelValue::sanitize(once.as_str());
        prop_assert_eq!(once, twice);
    }

    /// Any already-valid label value must survive sanitizing untouched.
    #[test]
    fn valid_label_values_are_unchanged(
        value in "[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?"
    ) {
        prop_assume!(is_label_value_per_apiserver(&value));
        let sanitized = LabelValue::sanitize(&value);
        prop_assert_eq!(sanitized.as_str(), value.as_str());
        prop_assert!(LabelValue::try_new(&value).is_ok());
    }

    /// `truncate_name_prefix` must respect the budget, never split a character,
    /// and never leave a trailing separator for a caller's suffix to collide
    /// with.
    #[test]
    fn truncated_name_prefixes_are_suffixable(
        input in hostile_input(),
        max_bytes in 0..300usize,
    ) {
        let prefix = truncate_name_prefix(&input, max_bytes);

        prop_assert!(prefix.len() <= max_bytes);
        prop_assert!(!prefix.ends_with('.'), "trailing dot in {prefix:?}");
        prop_assert!(!prefix.ends_with('-'), "trailing dash in {prefix:?}");
        // The result is a prefix of the input (no characters invented).
        prop_assert!(input.starts_with(prefix));
    }

    /// The real composition: a legal policy name in, a legal resource name out.
    /// This is the shape that was broken — a `.` landing on the cut made the
    /// appended `-plan-...` start a new DNS label with `-`.
    ///
    /// Every cut position is checked rather than a random one. A randomly
    /// chosen budget almost never lands on a separator, so the dangerous case
    /// would be sampled too rarely to catch a regression.
    #[test]
    fn suffixed_truncated_names_are_valid_resource_names(
        name in "[a-z0-9]([a-z0-9.-]{0,60}[a-z0-9])?",
    ) {
        prop_assume!(is_resource_name_per_apiserver(&name));

        for max_prefix in 1..=name.len() {
            let prefix = truncate_name_prefix(&name, max_prefix);
            if prefix.is_empty() {
                continue;
            }

            let composed = format!("{prefix}-plan-20260731-212739-abcdef012345");
            prop_assert!(
                is_resource_name_per_apiserver(&composed),
                "composing {:?} at budget {} gave invalid name {:?}",
                name,
                max_prefix,
                composed
            );
            prop_assert_eq!(
                is_valid_resource_name(&composed),
                is_resource_name_per_apiserver(&composed)
            );
        }
    }

    /// A sanitised segment must always be a usable DNS label on its own: the
    /// fallback guarantees it is never empty, so a composed name can never grow
    /// an empty label.
    #[test]
    fn sanitized_segments_are_valid_dns_labels(input in hostile_input()) {
        let segment = sanitize_dns_label_segment(&input, "fallback");

        prop_assert!(!segment.is_empty());
        prop_assert!(
            is_resource_name_per_apiserver(&segment),
            "segment {:?} from {:?} is not a valid DNS label",
            segment,
            input
        );
        // A single label contains no dots, so it stays one label when composed.
        prop_assert!(!segment.contains('.'));
    }

    /// The real composition in `default_generated_secret_name`: two sanitised
    /// segments joined by `-pgr-` and truncated to the resource-name limit must
    /// always be a name the API server accepts.
    #[test]
    fn composed_generated_secret_names_are_valid(
        policy in hostile_input(),
        role in hostile_input(),
    ) {
        let policy_segment = sanitize_dns_label_segment(&policy, "policy");
        let role_segment = sanitize_dns_label_segment(&role, "role");
        let composed = format!("{policy_segment}-pgr-{role_segment}");
        let truncated = truncate_name_prefix(&composed, MAX_RESOURCE_NAME_LENGTH);

        prop_assert!(!truncated.is_empty());
        prop_assert!(
            is_resource_name_per_apiserver(truncated),
            "composed secret name {:?} is invalid",
            truncated
        );
        prop_assert_eq!(
            is_valid_resource_name(truncated),
            is_resource_name_per_apiserver(truncated)
        );
    }

    /// The module's resource-name validator must agree with the restated rule
    /// on arbitrary input, including inputs that are not remotely valid.
    #[test]
    fn resource_name_validator_matches_apiserver_rule(input in hostile_input()) {
        prop_assert_eq!(
            is_valid_resource_name(&input),
            is_resource_name_per_apiserver(&input),
            "disagreement on {:?}",
            input
        );
    }
}
