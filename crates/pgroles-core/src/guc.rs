//! Handling for list-valued PostgreSQL configuration parameters.
//!
//! PostgreSQL flags some GUCs with `GUC_LIST_QUOTE`: their values are lists
//! whose elements are individually quoted when `ALTER ROLE ... SET` serializes
//! them into `pg_db_role_setting` (e.g. `search_path="$user", public`). The
//! flag is not exposed in any catalog, so — like `pg_dump`, which faces the
//! same problem — we hard-code the set of parameters that carry it.
//!
//! Getting this wrong is not cosmetic. `ALTER ROLE r SET search_path = 'a, b'`
//! (one string literal) stores `"a, b"` — a path with a single schema literally
//! named `a, b` — whereas `ALTER ROLE r SET search_path = 'a', 'b'` stores
//! `a, b`, a two-schema path. List parameters must therefore be split into one
//! SQL argument per element when rendering, and re-split when reading
//! `pg_roles.rolconfig` back.

/// Parameters PostgreSQL marks `GUC_LIST_QUOTE`. Mirrors `pg_dump`'s
/// `variable_is_guc_list_quote` (src/fe_utils/string_utils.c), which maintains
/// the same hard-coded list for the same reason.
const LIST_QUOTE_PARAMETERS: [&str; 5] = [
    "local_preload_libraries",
    "search_path",
    "session_preload_libraries",
    "shared_preload_libraries",
    "temp_tablespaces",
];

/// Whether `parameter` (already lowercased) is a list-quoted GUC whose value
/// must be handled element-wise.
pub fn is_list_quote_parameter(parameter: &str) -> bool {
    LIST_QUOTE_PARAMETERS.contains(&parameter)
}

/// Split a GUC list value into elements.
///
/// Port of PostgreSQL's `SplitGUCList`: elements are separated by commas
/// and/or whitespace; an element may be double-quoted, with `""` as an escaped
/// quote inside. Unlike `SplitIdentifierString`, unquoted elements are *not*
/// case-folded, so values round-trip verbatim. Returns `None` on an
/// unterminated quote.
pub fn split_guc_list(value: &str) -> Option<Vec<String>> {
    let mut elements = Vec::new();
    let mut chars = value.chars().peekable();

    loop {
        // Skip leading separators.
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            return Some(elements);
        };

        let mut element = String::new();
        if first == '"' {
            chars.next();
            loop {
                match chars.next() {
                    None => return None, // unterminated quote
                    Some('"') => {
                        if chars.peek() == Some(&'"') {
                            chars.next();
                            element.push('"');
                        } else {
                            break;
                        }
                    }
                    Some(c) => element.push(c),
                }
            }
        } else {
            while matches!(chars.peek(), Some(c) if !c.is_whitespace() && *c != ',') {
                element.push(chars.next().expect("peeked"));
            }
        }
        elements.push(element);
    }
}

/// Quote a list element the way PostgreSQL's serializer would need it quoted
/// for unambiguous round-tripping: elements that are not simple lowercase
/// identifiers are wrapped in double quotes with `"` doubled.
///
/// This does not have to match PostgreSQL's `quote_identifier` byte-for-byte
/// (e.g. keyword quoting): both the desired and the inspected value are
/// canonicalized with this same function before comparison, so only
/// self-consistency matters.
fn quote_element_if_needed(element: &str) -> String {
    let mut chars = element.chars();
    let simple = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if simple {
        element.to_string()
    } else {
        format!("\"{}\"", element.replace('"', "\"\""))
    }
}

/// Canonicalize a list-GUC value for comparison and rendering: split into
/// elements, re-quote elements that need it, and join with `", "`.
///
/// Both the manifest's desired value and the value read back from
/// `pg_roles.rolconfig` pass through this function, so `search_path: "$user",
/// public` in a manifest compares equal to PostgreSQL's stored
/// `"$user", public` regardless of spacing or quoting style. A value with an
/// unterminated quote is returned verbatim (it will simply never compare
/// equal to a well-formed value).
pub fn canonicalize_list_guc_value(value: &str) -> String {
    match split_guc_list(value) {
        Some(elements) => elements
            .iter()
            .map(|element| quote_element_if_needed(element))
            .collect::<Vec<_>>()
            .join(", "),
        None => value.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_list_parameters() {
        assert!(is_list_quote_parameter("search_path"));
        assert!(is_list_quote_parameter("temp_tablespaces"));
        assert!(!is_list_quote_parameter("role"));
        assert!(!is_list_quote_parameter("statement_timeout"));
        assert!(!is_list_quote_parameter("app.tenant"));
    }

    #[test]
    fn split_handles_bare_quoted_and_escaped_elements() {
        assert_eq!(
            split_guc_list(r#""$user", public"#),
            Some(vec!["$user".to_string(), "public".to_string()])
        );
        assert_eq!(
            split_guc_list("a,b , c"),
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
        assert_eq!(
            split_guc_list(r#""has, comma", plain"#),
            Some(vec!["has, comma".to_string(), "plain".to_string()])
        );
        assert_eq!(
            split_guc_list(r#""say ""hi""""#),
            Some(vec![r#"say "hi""#.to_string()])
        );
        assert_eq!(split_guc_list(""), Some(vec![]));
        assert_eq!(split_guc_list(r#""unterminated"#), None);
    }

    #[test]
    fn canonicalization_is_quoting_and_spacing_insensitive() {
        // All spellings of the same two-element path agree.
        for spelling in [
            r#""$user", public"#,
            r#""$user",public"#,
            r#"  "$user" , public "#,
            r#"$user, public"#, // bare $user still splits as one element
        ] {
            assert_eq!(
                canonicalize_list_guc_value(spelling),
                r#""$user", public"#,
                "spelling: {spelling}"
            );
        }
        assert_eq!(canonicalize_list_guc_value("app, public"), "app, public");
        // A single element containing a comma stays one quoted element —
        // semantically distinct from the two-element list.
        assert_eq!(
            canonicalize_list_guc_value(r#""app, public""#),
            r#""app, public""#
        );
        // Mixed case and specials get quoted.
        assert_eq!(
            canonicalize_list_guc_value("MySchema, public"),
            r#""MySchema", public"#
        );
    }
}
