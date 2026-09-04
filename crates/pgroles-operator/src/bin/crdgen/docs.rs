//! Deterministic documentation of the served OpenAPI schemas, including CEL.
use serde_json::Value;

fn text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
        .replace("{%", "&#123;%")
        .replace('\n', " ")
}

fn walk(
    schema: &Value,
    path: &str,
    required: bool,
    field: bool,
    output: &mut String,
) -> Result<(), String> {
    if field || !path.is_empty() {
        let description = schema
            .get("description")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty());
        if field && description.is_none() {
            return Err(format!("missing schema description: {path}"));
        }
        let description = description
            .unwrap_or("Constraints on this array item, map value, or conditional schema.");
        let kind = schema
            .get("type")
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| v.to_string())
            })
            .unwrap_or_else(|| "union".into());
        let constraints: serde_json::Map<String, Value> = [
            "format",
            "nullable",
            "enum",
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "multipleOf",
            "minLength",
            "maxLength",
            "pattern",
            "minItems",
            "maxItems",
            "uniqueItems",
            "minProperties",
            "maxProperties",
            "const",
            "x-kubernetes-list-type",
            "x-kubernetes-list-map-keys",
            "x-kubernetes-map-type",
        ]
        .into_iter()
        .filter_map(|key| schema.get(key).map(|v| (key.into(), v.clone())))
        .collect();
        let presence = if !field {
            "item or branch"
        } else if required {
            "required"
        } else {
            "optional"
        };
        let default = schema
            .get("default")
            .map(|v| format!(" **Default:** {}.", text(&v.to_string())))
            .unwrap_or_default();
        let limits = if constraints.is_empty() {
            String::new()
        } else {
            format!(
                " **Constraints:** {}.",
                text(&Value::Object(constraints).to_string())
            )
        };
        output.push_str(&format!(
            "| `{}` | **{}; {}.** {}{}{} |\n",
            text(path),
            text(&kind),
            presence,
            text(description),
            default,
            limits
        ));
    }
    if let Some(rules) = schema
        .get("x-kubernetes-validations")
        .and_then(Value::as_array)
    {
        for rule in rules {
            output.push_str(&format!(
                "| `{}` | **CEL:** {}. {} |\n",
                text(path),
                text(&rule.to_string()),
                "Evaluated with self at this path; oldSelf refers to the previous value on update."
            ));
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        let required = schema.get("required").and_then(Value::as_array);
        // serde_json's default map is ordered; explicitly sort to preserve the
        // contract even if another dependency enables preserve_order later.
        let mut keys: Vec<_> = properties.keys().collect();
        keys.sort();
        for key in keys {
            walk(
                &properties[key],
                &format!("{path}.{key}"),
                required.is_some_and(|names| names.iter().any(|n| n.as_str() == Some(key))),
                true,
                output,
            )?;
        }
    }
    if let Some(items) = schema.get("items") {
        walk(items, &format!("{path}[]"), false, false, output)?;
    }
    if let Some(map) = schema.get("additionalProperties").filter(|v| v.is_object()) {
        walk(map, &format!("{path}.<name>"), false, false, output)?;
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            for (index, branch) in branches.iter().enumerate() {
                // Branch fields retain the real field path; the branch label
                // states their conditional requiredness without inventing an API path.
                output.push_str(&format!("| `{}` | **{} branch {} (conditional).** Fields below apply within this branch. |\n", text(path), keyword, index + 1));
                walk(branch, path, false, false, output)?;
            }
        }
    }
    Ok(())
}

pub fn render(crd: &Value) -> Result<Vec<(String, String)>, String> {
    let kind = crd
        .pointer("/spec/names/kind")
        .and_then(Value::as_str)
        .ok_or("CRD lacks kind")?;
    let versions = crd
        .pointer("/spec/versions")
        .and_then(Value::as_array)
        .ok_or("CRD lacks versions")?;
    let mut pages = Vec::new();
    for version in versions.iter().filter(|v| v["served"] == true) {
        let name = version["name"]
            .as_str()
            .ok_or("served version lacks name")?;
        let schema = version
            .pointer("/schema/openAPIV3Schema")
            .ok_or("served version lacks schema")?;
        let mut body = format!(
            "---\ntitle: {kind}\ndescription: Generated field reference for the served {name} API.\n---\n\n[CRD API reference](/docs/operator-api-reference) · Served version `{name}`.\n\nRequired fields apply when their containing object is present. Defaults shown are API-server defaults; null requires `nullable`. Standard metadata follows [Kubernetes conventions](https://kubernetes.io/docs/concepts/overview/working-with-objects/). Status is controller-owned except documented decisions.\n\nFor workflows, see [operator guidance](/docs/operator), [approval](/docs/operator-plan-approval), [candidates](/docs/operator-candidates), and [ephemeral access](/docs/ephemeral-access).\n"
        );
        for section in ["spec", "status"] {
            let Some(subschema) = schema.pointer(&format!("/properties/{section}")) else {
                continue;
            };
            body.push_str(&format!(
                "\n## {}\n\n| Path | Definition |\n| --- | --- |\n",
                if section == "spec" {
                    "Spec"
                } else {
                    "Status (read-only except decisions)"
                }
            ));
            walk(
                subschema,
                section,
                schema["required"]
                    .as_array()
                    .is_some_and(|names| names.iter().any(|n| n == section)),
                true,
                &mut body,
            )
            .map_err(|error| format!("{kind}/{name}: {error}"))?;
        }
        let schema_name = format!("{}-{name}.json", kind.to_lowercase());
        body.push_str(&format!("\n[Download the complete served OpenAPI schema](/crd-reference/{schema_name}) for structural composition and all Kubernetes extensions.\n\nGenerated with `crdgen --docs-dir`; edit the Rust schema descriptions to change this reference.\n"));
        pages.push((format!("{}-{name}.md", kind.to_lowercase()), body));
    }
    if pages.is_empty() {
        return Err(format!("{kind}: no served versions"));
    }
    pages.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(pages)
}

pub fn schemas(crd: &Value) -> Result<Vec<(String, String)>, String> {
    let kind = crd
        .pointer("/spec/names/kind")
        .and_then(Value::as_str)
        .ok_or("CRD lacks kind")?;
    let versions = crd
        .pointer("/spec/versions")
        .and_then(Value::as_array)
        .ok_or("CRD lacks versions")?;
    versions
        .iter()
        .filter(|v| v["served"] == true)
        .map(|v| {
            let name = v["name"].as_str().ok_or("served version lacks name")?;
            let schema = v
                .pointer("/schema/openAPIV3Schema")
                .ok_or("served version lacks schema")?;
            Ok((
                format!("{}-{name}.json", kind.to_lowercase()),
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(schema).map_err(|e| e.to_string())?
                ),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn crd(schema: Value) -> Value {
        json!({"spec":{"names":{"kind":"Example"},"versions":[{"name":"v1","served":true,"schema":{"openAPIV3Schema":{"properties":{"spec":schema}}}}]}})
    }
    #[test]
    fn walks_arrays_maps_constraints_and_cel_at_their_paths() {
        let schema = json!({"type":"object","description":"Spec","required":["roles"],"properties":{
            "roles":{"type":"array","description":"Roles","maxItems":3,"items":{"type":"object","properties":{"name":{"type":"string","description":"A | B <name>","pattern":"a|b"}}}},
            "profiles":{"type":"object","description":"Profiles","additionalProperties":{"type":"object","properties":{"enabled":{"type":"boolean","description":"Enabled","default":false,"nullable":true,"x-kubernetes-validations":[{"rule":"self == oldSelf","message":"Immutable"}]}}}}
        }});
        let pages = render(&crd(schema)).unwrap();
        let body = &pages[0].1;
        for expected in [
            "`spec.roles` | **array; required",
            "spec.roles[].name",
            "spec.profiles.&lt;name&gt;.enabled",
            "maxItems",
            "self == oldSelf",
            "A &#124; B &lt;name&gt;",
        ] {
            // JSON strings retain ordinary quotes in Markdown text.
            let expected = expected.replace("&quot;", "\"");
            assert!(body.contains(&expected), "{expected}: {body}");
        }
    }
    #[test]
    fn preserves_union_requiredness_and_full_schema() {
        let schema = json!({"description":"Spec", "oneOf":[
            {"required":["kind"],"properties":{"kind":{"description":"Variant tag","const":"a","type":"string"}}},
            {"required":["value"],"properties":{"value":{"description":"Value","type":"integer","minimum":1}}}
        ],"x-kubernetes-validations":[{"rule":"self == oldSelf","optionalOldSelf":true}]});
        let body = &render(&crd(schema.clone())).unwrap()[0].1;
        assert!(body.contains("oneOf branch 1"));
        assert!(body.contains("`spec.kind` | **string; required"));
        assert!(body.contains("optionalOldSelf"));
        let assets = schemas(&crd(schema.clone())).unwrap();
        let parsed: Value = serde_json::from_str(&assets[0].1).unwrap();
        assert_eq!(parsed["properties"]["spec"], schema);
    }
    #[test]
    fn all_product_schemas_have_descriptions() {
        for crd in crate::generate() {
            render(&serde_json::from_str(&crd.json).unwrap()).unwrap();
        }
    }
    #[test]
    fn rejects_missing_field_descriptions() {
        let error = render(&crd(
            json!({"description":"Spec","properties":{"missing":{"type":"string"}}}),
        ))
        .unwrap_err();
        assert!(error.contains("spec.missing"));
    }
    #[test]
    fn renders_every_served_version_deterministically() {
        let mut value = crd(json!({"type":"object","description":"Spec"}));
        let mut second = value["spec"]["versions"][0].clone();
        second["name"] = json!("v2");
        value["spec"]["versions"]
            .as_array_mut()
            .unwrap()
            .push(second);
        assert_eq!(render(&value).unwrap().len(), 2);
        assert_eq!(render(&value), render(&value));
    }
}
