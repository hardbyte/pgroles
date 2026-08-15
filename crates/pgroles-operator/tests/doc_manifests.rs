//! Validate every copy-pasteable CRD manifest in the docs against the schemas
//! the operator actually generates.
//!
//! Documentation examples are the first thing a user pastes into a cluster, and
//! a wrong one fails in a confusing way: the API server prunes unknown fields
//! under a structural schema, so a bad example is *admitted* and then misbehaves
//! rather than being rejected. Two such examples shipped before this test
//! existed — a `connection.url` that does not exist, and a membership using
//! `member`/`on`/`to` instead of `members[].name`/`object`/`role`.
//!
//! The schemas come from `CustomResourceExt::crd()`, the same source `crdgen`
//! writes to disk, so this cannot drift from the committed CRDs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use kube::CustomResourceExt;
use pgroles_operator::crd::{
    EphemeralAccessPolicy, EphemeralAccessRequest, PostgresPolicy, PostgresPolicyPlan,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Blocks containing this marker are deliberate templates rather than complete
/// manifests — for example "paste the rendered manifest body here" — so they are
/// not expected to validate.
const ELISION_MARKER: &str = "# ...";

/// Every tree that ships copy-pasteable manifests to a reader, relative to the
/// repository root. Add to this rather than to the test body.
const MARKDOWN_ROOTS: [&str; 2] = ["docs/src/pages", "skills"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should exist relative to the crate")
}

/// Every Markdown file under the documented roots, sorted for stable output.
fn markdown_pages() -> Vec<PathBuf> {
    let root = repo_root();
    let mut pages = Vec::new();
    let mut queue: Vec<PathBuf> = MARKDOWN_ROOTS.iter().map(|dir| root.join(dir)).collect();

    while let Some(dir) = queue.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("{} should be readable: {err}", dir.display()));
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                queue.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                pages.push(path);
            }
        }
    }

    pages.sort();
    pages
}

/// Translate a Kubernetes structural schema into plain JSON Schema.
///
/// Two OpenAPI-isms need handling. `x-kubernetes-*` extensions are dropped: a
/// JSON Schema validator does not understand them. `nullable: true` is
/// translated rather than dropped — the API server accepts an explicit `null`
/// for such a field, so dropping it would make the validator reject a manifest
/// the cluster would take.
///
/// The translation widens `type` to include `"null"` instead of wrapping the
/// schema in an `anyOf`. That keeps `properties` where it is, which matters:
/// [`pruned_fields`] walks the same schema and would stop descending — silently
/// checking nothing — if a nullable object's properties moved inside a branch.
fn to_json_schema(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let nullable = map.get("nullable") == Some(&Value::Bool(true));
            let mut out: serde_json::Map<String, Value> = map
                .iter()
                .filter(|(k, _)| !k.starts_with("x-kubernetes-") && k.as_str() != "nullable")
                .map(|(k, v)| (k.clone(), to_json_schema(v)))
                .collect();

            if nullable {
                // Every nullable schema the CRDs generate carries a single
                // string `type`; anything else is left alone rather than
                // guessed at, since an untyped schema already accepts null.
                if let Some(Value::String(ty)) = out.get("type") {
                    let ty = ty.clone();
                    out.insert("type".to_string(), json!([ty, "null"]));
                }
                // A nullable enum must list null, or the enum re-excludes it.
                if let Some(Value::Array(variants)) = out.get_mut("enum")
                    && !variants.contains(&Value::Null)
                {
                    variants.push(Value::Null);
                }
            }

            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(to_json_schema).collect()),
        other => other.clone(),
    }
}

/// The generated CRD schemas, keyed by kind, ready to validate a whole manifest.
fn schemas() -> BTreeMap<String, (Validator, Value)> {
    let crds = [
        PostgresPolicy::crd(),
        PostgresPolicyPlan::crd(),
        EphemeralAccessPolicy::crd(),
        EphemeralAccessRequest::crd(),
    ];

    crds.into_iter()
        .map(|crd| {
            let kind = crd.spec.names.kind.clone();
            let version = crd
                .spec
                .versions
                .first()
                .expect("CRD should declare a version")
                .clone();
            let schema = version
                .schema
                .and_then(|s| s.open_api_v3_schema)
                .expect("CRD version should carry an OpenAPI schema");
            let mut schema =
                to_json_schema(&serde_json::to_value(schema).expect("schema should serialize"));

            // apiVersion/kind/metadata are supplied by the API server rather
            // than the CRD schema, so accept them without constraint.
            let properties = schema
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .expect("CRD schema should have properties");
            for key in ["apiVersion", "kind", "metadata"] {
                properties.insert(key.to_string(), json!({}));
            }

            let validator = jsonschema::validator_for(&schema)
                .unwrap_or_else(|err| panic!("{kind} schema should compile: {err}"));
            (kind, (validator, schema))
        })
        .collect()
}

/// Report fields the API server would silently prune.
///
/// Structural schemas do not set `additionalProperties: false`; Kubernetes
/// instead *prunes* undeclared fields on write. A JSON Schema validator
/// therefore accepts them, which is why this walk exists separately: an
/// undeclared field is the failure mode that admits a manifest and then makes
/// it behave unlike the documentation says.
fn pruned_fields(instance: &Value, schema: &Value, path: &str, out: &mut Vec<String>) {
    let (Some(object), Some(schema)) = (instance.as_object(), schema.as_object()) else {
        return;
    };
    if schema.contains_key("x-kubernetes-preserve-unknown-fields") {
        return;
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return;
    };

    for (key, value) in object {
        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        let Some(child_schema) = properties.get(key) else {
            out.push(child_path);
            continue;
        };
        match value {
            Value::Object(_) => pruned_fields(value, child_schema, &child_path, out),
            Value::Array(items) => {
                if let Some(item_schema) = child_schema.get("items") {
                    for (index, item) in items.iter().enumerate() {
                        pruned_fields(item, item_schema, &format!("{child_path}[{index}]"), out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Extract fenced YAML blocks from Markdown, skipping deliberate templates.
fn yaml_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;

    for line in markdown.lines() {
        match current {
            None => {
                let fence = line.trim_start();
                if fence.starts_with("```yaml") || fence.starts_with("```yml") {
                    current = Some(String::new());
                }
            }
            Some(ref mut body) => {
                if line.trim_start().starts_with("```") {
                    let body = current.take().expect("block is open");
                    if !body.contains(ELISION_MARKER) {
                        blocks.push(body);
                    }
                } else {
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
    }
    blocks
}

#[test]
fn doc_manifests_match_generated_crd_schemas() {
    let schemas = schemas();
    let mut checked = 0usize;
    let mut failures = Vec::new();

    let pages = markdown_pages();
    assert!(
        !pages.is_empty(),
        "expected documentation pages to validate"
    );

    let root = repo_root();
    for page in pages {
        let name = page.strip_prefix(&root).unwrap_or(&page).display();
        let markdown = std::fs::read_to_string(&page).expect("page should be readable");

        for block in yaml_blocks(&markdown) {
            for document in serde_yaml::Deserializer::from_str(&block) {
                let Ok(value) = Value::deserialize(document) else {
                    // Not all YAML in the docs is a Kubernetes object; blocks
                    // that do not parse as a mapping are covered elsewhere.
                    continue;
                };
                let Some(kind) = value.get("kind").and_then(Value::as_str) else {
                    continue;
                };
                let Some((validator, schema)) = schemas.get(kind) else {
                    continue;
                };

                checked += 1;
                for error in validator.iter_errors(&value) {
                    let path = error.instance_path().to_string();
                    let path = if path.is_empty() { "<root>" } else { &path };
                    failures.push(format!("{name}: {kind} at {path}: {error}"));
                }
                let mut pruned = Vec::new();
                pruned_fields(&value, schema, "", &mut pruned);
                for field in pruned {
                    failures.push(format!(
                        "{name}: {kind} field `{field}` is not in the schema and would be \
                         silently pruned by the API server"
                    ));
                }
            }
        }
    }

    assert!(
        checked > 0,
        "no CRD manifests found in the docs — the extractor is probably broken"
    );
    assert!(
        failures.is_empty(),
        "documentation manifests do not match the generated CRD schemas:\n  {}",
        failures.join("\n  ")
    );
}

/// Negative tests: each encodes a mistake that actually shipped, so a
/// regression in the extractor or the schema walk fails loudly rather than
/// quietly passing everything.
mod regressions {
    use super::*;

    #[test]
    fn elided_template_blocks_are_skipped() {
        let markdown = "```yaml\nspec:\n  profiles:\n    editor:\n      # ...\n```\n";
        assert!(
            yaml_blocks(markdown).is_empty(),
            "a block marked as a template should not be validated"
        );
    }

    #[test]
    fn yaml_blocks_are_extracted_without_fences() {
        let markdown = "text\n\n```yaml\nkind: PostgresPolicy\n```\n\nmore\n";
        assert_eq!(yaml_blocks(markdown), vec!["kind: PostgresPolicy\n"]);
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let schemas = schemas();
        let (_, schema) = schemas
            .get("PostgresPolicy")
            .expect("PostgresPolicy schema should exist");
        // `connection.url` does not exist; this is the shape that shipped once.
        let manifest = json!({
            "apiVersion": "pgroles.io/v1alpha1",
            "kind": "PostgresPolicy",
            "metadata": {"name": "example"},
            "spec": {"connection": {"url": {"secretName": "db", "secretKey": "url"}}}
        });
        let mut pruned = Vec::new();
        pruned_fields(&manifest, schema, "", &mut pruned);
        assert_eq!(
            pruned,
            vec!["spec.connection.url".to_string()],
            "an undeclared connection field should be reported as pruned"
        );
    }

    #[test]
    fn an_explicit_null_is_accepted_where_the_api_server_accepts_one() {
        let schemas = schemas();
        let (validator, _) = schemas
            .get("PostgresPolicy")
            .expect("PostgresPolicy schema should exist");
        // `spec.approval` is `nullable: true` with an enum, so it is the shape
        // that regresses first if the nullable translation is dropped.
        let manifest = json!({
            "apiVersion": "pgroles.io/v1alpha1",
            "kind": "PostgresPolicy",
            "metadata": {"name": "example"},
            "spec": {
                "connection": {"secretRef": {"name": "db"}, "secretKey": "url"},
                "approval": Value::Null
            }
        });
        let errors: Vec<_> = validator
            .iter_errors(&manifest)
            .map(|error| error.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "an explicit null on a nullable field should validate: {errors:?}"
        );
    }

    #[test]
    fn a_missing_required_field_is_rejected() {
        let schemas = schemas();
        let (validator, _) = schemas
            .get("PostgresPolicy")
            .expect("PostgresPolicy schema should exist");
        // memberships[] requires both `role` and `members`.
        let manifest = json!({
            "apiVersion": "pgroles.io/v1alpha1",
            "kind": "PostgresPolicy",
            "metadata": {"name": "example"},
            "spec": {
                "connection": {"secretRef": {"name": "db"}, "secretKey": "url"},
                "memberships": [{"role": "reader"}]
            }
        });
        assert!(
            validator.iter_errors(&manifest).next().is_some(),
            "a membership without members should fail validation"
        );
    }
}
