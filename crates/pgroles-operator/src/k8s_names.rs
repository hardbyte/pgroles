//! Construction and validation of Kubernetes identifiers.
//!
//! The API server rejects objects whose names or label values break the rules
//! in the [object names reference][names]. Client-side builders that truncate a
//! long input are the usual source of invalid values: the cut can land on a
//! separator and leave a value that no longer starts and ends with an
//! alphanumeric, and the resulting rejection surfaces as a policy that stops
//! reconciling rather than as an obvious bug.
//!
//! Every identifier the operator derives from user input goes through this
//! module so those rules live in exactly one place. Two shapes matter:
//!
//! - **Label values** ([`LabelValue`]) — at most 63 characters of
//!   alphanumerics, `.`, `-`, and `_`, starting and ending alphanumeric. The
//!   empty string is also valid.
//! - **Resource names** ([`ResourceName`]) — RFC 1123 DNS subdomains: at most
//!   253 characters of dot-separated labels, each label lowercase
//!   alphanumerics and `-`, starting and ending alphanumeric.
//!
//! [names]: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/

use std::fmt;

/// Maximum length of a Kubernetes label value.
pub const MAX_LABEL_VALUE_LENGTH: usize = 63;

/// Maximum length of a Kubernetes resource name (RFC 1123 DNS subdomain).
pub const MAX_RESOURCE_NAME_LENGTH: usize = 253;

/// An identifier that does not satisfy the Kubernetes rules for its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIdentifier {
    /// What kind of identifier was expected (e.g. `"label value"`).
    pub kind: &'static str,
    /// The offending value.
    pub value: String,
}

impl fmt::Display for InvalidIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Kubernetes {}: {:?}", self.kind, self.value)
    }
}

impl std::error::Error for InvalidIdentifier {}

/// Is `value` a valid Kubernetes label value?
///
/// Label values are at most 63 characters of alphanumerics, `.`, `-`, and `_`,
/// and must start and end with an alphanumeric. The empty string is valid.
pub fn is_valid_label_value(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > MAX_LABEL_VALUE_LENGTH {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Is `value` a valid RFC 1123 DNS label (one dot-free segment of a name)?
fn is_dns1123_label(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_lower_alnum(bytes[0]) || !is_lower_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|b| is_lower_alnum(*b) || *b == b'-')
}

/// Is `value` a valid Kubernetes resource name (RFC 1123 DNS subdomain)?
///
/// Stricter than a first/last character check: every dot-separated label must
/// itself be non-empty and start and end with a lowercase alphanumeric, so
/// names such as `db..creds` and `db-.creds` are correctly rejected.
pub fn is_valid_resource_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_RESOURCE_NAME_LENGTH {
        return false;
    }
    value.split('.').all(is_dns1123_label)
}

/// Truncate a resource-name prefix to at most `max_bytes`, then trim any `.`
/// or `-` the cut exposed.
///
/// Truncation respects UTF-8 boundaries so the result is always a valid `str`.
/// Trailing separators must go because callers append their own suffix: a
/// prefix ending in `.` would start a new DNS label with the suffix's leading
/// `-`, which the API server rejects. Only `.` and `-` are trimmed, so a
/// prefix that starts with an alphanumeric can never be emptied.
pub fn truncate_name_prefix(prefix: &str, max_bytes: usize) -> &str {
    let cut = if prefix.len() <= max_bytes {
        prefix.len()
    } else {
        // Largest char boundary at or below max_bytes.
        (0..=max_bytes)
            .rev()
            .find(|idx| prefix.is_char_boundary(*idx))
            .unwrap_or(0)
    };
    prefix[..cut].trim_end_matches(['.', '-'])
}

/// Derive a single RFC 1123 DNS label from arbitrary input, for use as one
/// segment of a composed resource name.
///
/// Input is lowercased; every run of characters outside `[a-z0-9]` collapses to
/// a single `-`; leading and trailing `-` are dropped. `fallback` is returned if
/// nothing survives, so the result is always a usable segment.
///
/// Like [`LabelValue::sanitize`] this is lossy and **not injective** — callers
/// composing several segments must not treat the result as an identity.
///
/// `fallback` is returned verbatim and is the one value this function cannot
/// make safe, so it must already be a valid DNS 1123 label. Debug builds assert
/// it; callers pass literals.
pub fn sanitize_dns_label_segment(input: &str, fallback: &str) -> String {
    debug_assert!(
        is_dns1123_label(fallback),
        "fallback {fallback:?} is not a valid DNS label"
    );
    let mut result = String::with_capacity(input.len());
    let mut last_was_dash = false;

    for ch in input.chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_lowercase() || normalized.is_ascii_digit() {
            result.push(normalized);
            last_was_dash = false;
        } else if !last_was_dash && !result.is_empty() {
            result.push('-');
            last_was_dash = true;
        }
    }

    let trimmed = result.trim_matches('-');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

/// A validated Kubernetes label value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelValue(String);

impl LabelValue {
    /// Derive a valid label value from arbitrary input.
    ///
    /// Characters outside the permitted set become `_`, leading separators are
    /// dropped before the 63-character cut so they do not consume budget that
    /// is then discarded, and any separator the cut exposes is trimmed.
    ///
    /// This is lossy and therefore **not injective**: distinct inputs can
    /// produce the same label value. Do not use the result as the sole identity
    /// for anything that drives deletion — see [`crate::plan`] for the
    /// hash-based approach used where uniqueness matters.
    pub fn sanitize(value: &str) -> Self {
        let sanitized: String = value
            .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .take(MAX_LABEL_VALUE_LENGTH)
            .collect();
        let trimmed = sanitized.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
        Self(trimmed.to_string())
    }

    /// Accept `value` only if it is already a valid label value.
    pub fn try_new(value: &str) -> Result<Self, InvalidIdentifier> {
        if is_valid_label_value(value) {
            Ok(Self(value.to_string()))
        } else {
            Err(InvalidIdentifier {
                kind: "label value",
                value: value.to_string(),
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for LabelValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<LabelValue> for String {
    fn from(value: LabelValue) -> Self {
        value.0
    }
}

/// A validated Kubernetes resource name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceName(String);

impl ResourceName {
    /// Accept `value` only if it is a valid resource name.
    pub fn try_new(value: impl Into<String>) -> Result<Self, InvalidIdentifier> {
        let value = value.into();
        if is_valid_resource_name(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidIdentifier {
                kind: "resource name",
                value,
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ResourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<ResourceName> for String {
    fn from(value: ResourceName) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_value_sanitize_maps_and_trims() {
        assert_eq!(
            LabelValue::sanitize("orders-service").as_str(),
            "orders-service"
        );
        assert_eq!(
            LabelValue::sanitize("default/db-creds/DATABASE_URL").as_str(),
            "default_db-creds_DATABASE_URL"
        );
        assert_eq!(
            LabelValue::sanitize("_params_literal_appdb_").as_str(),
            "params_literal_appdb"
        );
        // Only separators collapses to the empty string, which is a valid label.
        assert_eq!(LabelValue::sanitize("___").as_str(), "");
    }

    #[test]
    fn label_value_sanitize_trims_leading_before_truncating() {
        // Leading separators must not consume the 63-character budget.
        let value = LabelValue::sanitize(&format!("__{}", "a".repeat(70)));
        assert_eq!(value.as_str(), "a".repeat(MAX_LABEL_VALUE_LENGTH));
    }

    #[test]
    fn label_value_sanitize_trims_separator_exposed_by_truncation() {
        let value = LabelValue::sanitize(&format!("{}_x", "a".repeat(62)));
        assert_eq!(value.as_str(), "a".repeat(62));
    }

    #[test]
    fn label_value_try_new_rejects_invalid() {
        assert!(LabelValue::try_new("orders").is_ok());
        assert!(LabelValue::try_new("").is_ok());
        assert!(LabelValue::try_new("_orders").is_err());
        assert!(LabelValue::try_new("orders_").is_err());
        assert!(LabelValue::try_new("orders/svc").is_err());
        assert!(LabelValue::try_new(&"a".repeat(64)).is_err());
    }

    #[test]
    fn resource_name_rejects_malformed_labels() {
        assert!(is_valid_resource_name("db-creds"));
        assert!(is_valid_resource_name("9db-creds"));
        assert!(is_valid_resource_name("team.alpha.orders"));

        assert!(!is_valid_resource_name(""));
        assert!(!is_valid_resource_name("db..creds"));
        assert!(!is_valid_resource_name("db-.creds"));
        assert!(!is_valid_resource_name("-db-creds"));
        assert!(!is_valid_resource_name("db-creds-"));
        assert!(!is_valid_resource_name("DB-creds"));
        assert!(!is_valid_resource_name("db_creds"));
        assert!(!is_valid_resource_name(
            &"a".repeat(MAX_RESOURCE_NAME_LENGTH + 1)
        ));
    }

    #[test]
    fn truncate_name_prefix_trims_exposed_separators() {
        assert_eq!(truncate_name_prefix("orders", 10), "orders");
        assert_eq!(truncate_name_prefix("orders-service", 7), "orders");
        assert_eq!(truncate_name_prefix("team.alpha", 5), "team");
        // Interior separators are preserved.
        assert_eq!(truncate_name_prefix("team.alpha", 10), "team.alpha");
    }

    #[test]
    fn truncate_name_prefix_respects_utf8_boundaries() {
        // `é` is two bytes: an odd budget must not split it.
        let input = "é".repeat(5);
        let truncated = truncate_name_prefix(&input, 5);
        assert_eq!(truncated, "é".repeat(2));
        assert!(truncated.len() <= 5);
    }
}
