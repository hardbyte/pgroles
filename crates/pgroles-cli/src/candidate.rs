//! `pgroles candidate` — file, list, inspect and diff `PostgresPolicyCandidate`
//! objects.
//!
//! These commands cover the review side of the candidate workflow documented in
//! `docs/src/pages/docs/operator-candidates.md`: propose content, see what the
//! operator planned for it, and read the SQL a reviewer would be approving.
//!
//! **Deciding a plan is deliberately not here.** A decision is a write to the
//! plan's status subresource, gated by admission so that `decidedBy` records an
//! authenticated identity. Wrapping that in a CLI verb would blur who
//! authenticated it, so approval and rejection stay `kubectl`-shaped — see
//! [Deciding a plan](/docs/operator-plan-approval#deciding-a-plan).
//!
//! The Kubernetes objects are read as [`DynamicObject`] rather than through the
//! operator's typed CRD structs: the CLI does not depend on `pgroles-operator`,
//! and a second copy of those types in this crate would be a second definition
//! of the API. Everything below therefore navigates `serde_json::Value`, which
//! also makes the formatting and selection logic unit-testable against literals.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{ApiResource, DynamicObject, ListParams, PostParams};
use kube::core::GroupVersionKind;
use kube::{Api, Client, ResourceExt};
use serde_json::{Map, Value, json};

use crate::{read_manifest_file, validate_manifest};

// ---------------------------------------------------------------------------
// API resources
// ---------------------------------------------------------------------------

const GROUP: &str = "pgroles.io";
const VERSION: &str = "v1alpha1";

fn candidate_api(client: Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk(GROUP, VERSION, "PostgresPolicyCandidate");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "postgrespolicycandidates");
    Api::namespaced_with(client, namespace, &resource)
}

fn plan_api(client: Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk(GROUP, VERSION, "PostgresPolicyPlan");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "postgrespolicyplans");
    Api::namespaced_with(client, namespace, &resource)
}

fn policy_api(client: Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk(GROUP, VERSION, "PostgresPolicy");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "postgrespolicies");
    Api::namespaced_with(client, namespace, &resource)
}

// ---------------------------------------------------------------------------
// Content extraction (pure)
// ---------------------------------------------------------------------------

/// The keys `PostgresPolicyCandidate.spec.content` accepts, in the CRD's own
/// spelling. Anything outside this set is either dropped as execution config
/// (see [`POLICY_EXECUTION_KEYS`]) or rejected — never silently pruned by the
/// API server, which would change the content digest without saying so.
pub const CONTENT_KEYS: &[&str] = &[
    "default_owner",
    "role_pattern",
    "default_privileges",
    "grants",
    "memberships",
    "profiles",
    "reconciliation_mode",
    "retirements",
    "roles",
    "schemas",
];

/// `PostgresPolicy.spec` keys that describe *execution*, not content. A
/// candidate always takes these from its parent policy, so they are dropped
/// when a whole policy manifest is filed as a candidate.
pub const POLICY_EXECUTION_KEYS: &[&str] =
    &["connection", "interval", "mode", "suspend", "approval"];

/// Extract the `spec.content` mapping from a local manifest.
///
/// Three input shapes are accepted, matching what
/// [`pgroles_core::manifest::parse_manifest`] already tolerates plus the
/// candidate wrapper:
///
/// - a bare pgroles manifest (`roles:`, `grants:`, …),
/// - a `PostgresPolicy` CR, whose execution fields are dropped,
/// - a `PostgresPolicyCandidate` CR, whose `spec.content` is taken verbatim.
///
/// Keys that are none of the above fail the command. `auth_providers`, for
/// instance, is a valid manifest key with no candidate counterpart: a
/// structural CRD schema would prune it server-side and the stored content
/// would quietly mean something other than the file on disk.
pub fn extract_candidate_content(yaml: &str) -> Result<Value> {
    let document: serde_yaml::Value =
        serde_yaml::from_str(yaml).context("failed to parse manifest YAML")?;
    let body = candidate_content_body(&document)?;

    let mapping = body.as_mapping().ok_or_else(|| {
        anyhow::anyhow!("policy content must be a YAML mapping of content keys (roles, grants, …)")
    })?;

    let mut content = Map::new();
    let mut unsupported = Vec::new();

    for (key, value) in mapping {
        let Some(key) = key.as_str() else {
            anyhow::bail!("policy content keys must be strings");
        };

        if POLICY_EXECUTION_KEYS.contains(&key) {
            // Execution config always comes from the parent policy.
            continue;
        }
        if !CONTENT_KEYS.contains(&key) {
            unsupported.push(key.to_string());
            continue;
        }
        if value.is_null() {
            anyhow::bail!(
                "policy content key `{key}` has no value; remove it or give it a value \
                 (a candidate stores exactly what it is given)"
            );
        }

        let json = serde_json::to_value(value)
            .with_context(|| format!("failed to convert policy content key `{key}` to JSON"))?;
        content.insert(key.to_string(), json);
    }

    if !unsupported.is_empty() {
        anyhow::bail!(
            "manifest key(s) {} cannot be carried by a PostgresPolicyCandidate; \
             `spec.content` accepts only: {}",
            unsupported
                .iter()
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>()
                .join(", "),
            CONTENT_KEYS.join(", "),
        );
    }

    if content.is_empty() {
        anyhow::bail!(
            "manifest declares no policy content; a candidate proposing nothing has \
             nothing to review"
        );
    }

    Ok(Value::Object(content))
}

/// Locate the mapping that holds policy content within a parsed document.
fn candidate_content_body(document: &serde_yaml::Value) -> Result<&serde_yaml::Value> {
    let Some(map) = document.as_mapping() else {
        anyhow::bail!("manifest must be a YAML mapping");
    };

    let get = |key: &str| map.get(serde_yaml::Value::String(key.to_string()));

    let is_cr = get("apiVersion").is_some() && get("spec").is_some();
    if !is_cr {
        return Ok(document);
    }

    let spec = get("spec").expect("checked above");
    let kind = get("kind").and_then(serde_yaml::Value::as_str);

    if kind == Some("PostgresPolicyCandidate") {
        return spec
            .as_mapping()
            .and_then(|spec| spec.get(serde_yaml::Value::String("content".to_string())))
            .ok_or_else(|| {
                anyhow::anyhow!("PostgresPolicyCandidate manifest has no `spec.content`")
            });
    }

    Ok(spec)
}

/// Build the `PostgresPolicyCandidate` object to create.
///
/// `generateName` rather than a fixed name: two reviewers filing against the
/// same policy at the same moment must not collide, and a candidate is a
/// one-shot object that is never re-applied.
pub fn build_candidate_object(policy: &str, replaces: Option<&str>, content: Value) -> Value {
    let mut spec = Map::new();
    spec.insert("policyRef".to_string(), json!({ "name": policy }));
    if let Some(replaces) = replaces {
        spec.insert("replaces".to_string(), Value::String(replaces.to_string()));
    }
    spec.insert("content".to_string(), content);

    json!({
        "apiVersion": format!("{GROUP}/{VERSION}"),
        "kind": "PostgresPolicyCandidate",
        "metadata": { "generateName": generate_name_prefix(policy) },
        "spec": Value::Object(spec),
    })
}

/// Kubernetes appends five random characters to `generateName` and rejects the
/// result past 253 characters, so the prefix is capped to leave room.
pub fn generate_name_prefix(policy: &str) -> String {
    const MAX_GENERATE_NAME_PREFIX: usize = 248;

    let mut prefix = format!("{policy}-");
    if prefix.len() > MAX_GENERATE_NAME_PREFIX {
        prefix.truncate(MAX_GENERATE_NAME_PREFIX);
    }
    prefix
}

// ---------------------------------------------------------------------------
// Status navigation (pure)
// ---------------------------------------------------------------------------

/// A condition read off a candidate or plan status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub status: String,
    pub reason: Option<String>,
    pub message: Option<String>,
}

impl Condition {
    /// `True/Planned`-style summary for table cells.
    pub fn summary(&self) -> String {
        match &self.reason {
            Some(reason) => format!("{}/{}", self.status, reason),
            None => self.status.clone(),
        }
    }
}

/// Read a condition of the given type from an object's `status.conditions`.
pub fn find_condition(object: &Value, condition_type: &str) -> Option<Condition> {
    object
        .get("status")?
        .get("conditions")?
        .as_array()?
        .iter()
        .find(|condition| condition.get("type").and_then(Value::as_str) == Some(condition_type))
        .map(|condition| Condition {
            status: condition
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("Unknown")
                .to_string(),
            reason: condition
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_string),
            message: condition
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
}

/// Read a dotted path of string-keyed fields, e.g. `status.planRef.name`.
pub fn string_at(object: &Value, path: &str) -> Option<String> {
    let mut current = object;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    current.as_str().map(str::to_string)
}

/// Shorten a `sha256:…` digest for table display. Full digests are 71
/// characters and would swamp every other column.
pub fn abbreviate_digest(digest: &str) -> String {
    const KEEP: usize = 12;

    // Truncation is by character, not byte: these values come from
    // `status.contentDigest` and `spec.origin.baseContentDigest`, which are
    // cluster data rather than anything this process validated. A byte slice
    // landing inside a multi-byte character would panic the whole listing
    // instead of printing one degraded cell.
    fn head(value: &str) -> Option<&str> {
        value
            .char_indices()
            .nth(KEEP)
            .map(|(boundary, _)| &value[..boundary])
    }

    match digest.split_once(':') {
        Some((algorithm, hex)) => match head(hex) {
            Some(head) => format!("{algorithm}:{head}…"),
            None => digest.to_string(),
        },
        None => match head(digest) {
            Some(head) => format!("{head}…"),
            None => digest.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Listing (pure)
// ---------------------------------------------------------------------------

/// One row of `pgroles candidate list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRow {
    pub name: String,
    pub phase: String,
    pub digest: String,
    pub plan: String,
    pub ready: String,
    pub superseded: String,
    pub promoted: String,
}

/// Placeholder for a cell with no value. Never blank: a blank cell in a plain
/// table is indistinguishable from a value that failed to render.
const NONE_CELL: &str = "-";

fn cell(value: Option<String>) -> String {
    value.unwrap_or_else(|| NONE_CELL.to_string())
}

/// Project a candidate object into a table row.
pub fn candidate_row(candidate: &Value, name: &str) -> CandidateRow {
    CandidateRow {
        name: name.to_string(),
        phase: cell(string_at(candidate, "status.phase")),
        digest: cell(string_at(candidate, "status.contentDigest").map(|d| abbreviate_digest(&d))),
        plan: cell(string_at(candidate, "status.planRef.name")),
        ready: cell(find_condition(candidate, "Ready").map(|c| c.summary())),
        superseded: cell(find_condition(candidate, "Superseded").map(|c| c.summary())),
        promoted: cell(find_condition(candidate, "Promoted").map(|c| c.summary())),
    }
}

/// Render rows as a padded table. `kubectl`-shaped so the output can be read
/// beside `kubectl get pgcand` without retraining the eye.
pub fn format_candidate_table(rows: &[CandidateRow]) -> String {
    let headers = [
        "NAME",
        "PHASE",
        "DIGEST",
        "PLAN",
        "READY",
        "SUPERSEDED",
        "PROMOTED",
    ];
    let columns: Vec<[&str; 7]> = rows
        .iter()
        .map(|row| {
            [
                row.name.as_str(),
                row.phase.as_str(),
                row.digest.as_str(),
                row.plan.as_str(),
                row.ready.as_str(),
                row.superseded.as_str(),
                row.promoted.as_str(),
            ]
        })
        .collect();

    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in &columns {
        for (index, value) in row.iter().enumerate() {
            widths[index] = widths[index].max(value.chars().count());
        }
    }

    let mut output = String::new();
    let mut push_row = |values: &[&str]| {
        let mut line = String::new();
        for (index, value) in values.iter().enumerate() {
            if index + 1 == values.len() {
                line.push_str(value);
            } else {
                let pad = widths[index].saturating_sub(value.chars().count()) + 2;
                line.push_str(value);
                line.push_str(&" ".repeat(pad));
            }
        }
        output.push_str(line.trim_end());
        output.push('\n');
    };

    push_row(&headers);
    for row in &columns {
        push_row(row);
    }
    output
}

// ---------------------------------------------------------------------------
// SQL selection (pure)
// ---------------------------------------------------------------------------

/// Where a plan's reviewed SQL actually lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanSqlSource {
    /// Small plans are stored whole in `status.sqlInline`.
    Inline(String),
    /// Larger plans spill to a gzipped ConfigMap named by `status.sqlRef`.
    ConfigMap {
        name: String,
        key: String,
        gzip: bool,
    },
}

/// Decide where to read a plan's SQL from.
///
/// `sqlInline` wins when it holds the whole preview. A *truncated* inline
/// preview is never returned: it is a fragment of the SQL, and printing a
/// fragment under a command that answers "what would approving this do?" would
/// be worse than printing nothing.
pub fn select_plan_sql(plan: &Value) -> Result<PlanSqlSource> {
    let status = plan.get("status");
    let inline = status
        .and_then(|status| status.get("sqlInline"))
        .and_then(Value::as_str)
        .filter(|sql| !sql.is_empty());
    let truncated = status
        .and_then(|status| status.get("sqlTruncated"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let sql_ref = status.and_then(|status| status.get("sqlRef"));

    if let Some(inline) = inline
        && !truncated
    {
        return Ok(PlanSqlSource::Inline(inline.to_string()));
    }

    if let Some(sql_ref) = sql_ref.filter(|value| !value.is_null()) {
        let name = sql_ref.get("name").and_then(Value::as_str);
        let key = sql_ref.get("key").and_then(Value::as_str);
        match (name, key) {
            (Some(name), Some(key)) if !name.is_empty() && !key.is_empty() => {
                let gzip = sql_ref.get("compression").and_then(Value::as_str) == Some("gzip");
                return Ok(PlanSqlSource::ConfigMap {
                    name: name.to_string(),
                    key: key.to_string(),
                    gzip,
                });
            }
            _ => anyhow::bail!(
                "plan has an incomplete status.sqlRef (name={:?}, key={:?}); \
                 the stored SQL cannot be located",
                name.unwrap_or_default(),
                key.unwrap_or_default(),
            ),
        }
    }

    if inline.is_some() && truncated {
        anyhow::bail!(
            "plan stores only a truncated SQL preview (status.sqlTruncated=true) and no \
             status.sqlRef ConfigMap, so the full reviewed SQL is not recoverable from the \
             cluster; read the operator log for the plan, or reduce the size of the change"
        );
    }

    anyhow::bail!(
        "plan has no SQL recorded yet (neither status.sqlInline nor status.sqlRef); \
         it has probably not finished computing — check `pgroles candidate status`"
    )
}

/// Read the SQL out of the ConfigMap a plan's `sqlRef` names.
///
/// Compressed SQL lives in `binaryData`; the legacy uncompressed shape lives in
/// `data`. A missing key is an error rather than an empty plan: an empty string
/// here would read as "this change does nothing".
pub fn decode_configmap_sql(configmap: &ConfigMap, key: &str, gzip: bool) -> Result<String> {
    let name = configmap.metadata.name.as_deref().unwrap_or("<unnamed>");

    if gzip {
        let bytes = configmap
            .binary_data
            .as_ref()
            .and_then(|data| data.get(key))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "ConfigMap {name} has no binaryData key `{key}`; \
                     the plan's SQL artifact is missing or was pruned"
                )
            })?;

        let mut sql = String::new();
        flate2::read::GzDecoder::new(bytes.0.as_slice())
            .read_to_string(&mut sql)
            .with_context(|| format!("failed to decompress SQL from ConfigMap {name}/{key}"))?;
        return Ok(sql);
    }

    configmap
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "ConfigMap {name} has no data key `{key}`; \
                 the plan's SQL artifact is missing or was pruned"
            )
        })
}

// ---------------------------------------------------------------------------
// Detail rendering (pure)
// ---------------------------------------------------------------------------

/// Render `pgroles candidate status` for one candidate and its plan.
///
/// `plan` is `None` when the candidate has not been planned yet — the caller
/// reports that as a hard error for `diff`, but `status` is exactly the command
/// that should be able to explain an unplanned candidate.
pub fn format_candidate_status(
    name: &str,
    namespace: &str,
    candidate: &Value,
    plan_name: Option<&str>,
    plan: Option<&Value>,
) -> String {
    let mut output = String::new();

    output.push_str(&format!("Candidate:  {name}\n"));
    output.push_str(&format!("Namespace:  {namespace}\n"));
    output.push_str(&format!(
        "Policy:     {}\n",
        cell(string_at(candidate, "spec.policyRef.name"))
    ));
    if let Some(replaces) = string_at(candidate, "spec.replaces") {
        output.push_str(&format!("Replaces:   {replaces}\n"));
    }
    if let Some(secret) = string_at(candidate, "spec.target.connectionRef.secretName") {
        let key = cell(string_at(candidate, "spec.target.connectionRef.key"));
        output.push_str(&format!(
            "Target:     override — Secret {secret} key {key} (a preview, never a cutover)\n"
        ));
    }
    output.push_str(&format!(
        "Phase:      {}\n",
        cell(string_at(candidate, "status.phase"))
    ));
    output.push_str(&format!(
        "Digest:     {}\n",
        cell(string_at(candidate, "status.contentDigest"))
    ));

    output.push_str("\nConditions:\n");
    let mut any_condition = false;
    for condition_type in ["Ready", "Superseded", "Promoted"] {
        if let Some(condition) = find_condition(candidate, condition_type) {
            any_condition = true;
            output.push_str(&format!(
                "  {condition_type}={} ({})\n",
                condition.status,
                condition.reason.as_deref().unwrap_or("no reason recorded"),
            ));
            if let Some(message) = &condition.message {
                output.push_str(&format!("    {message}\n"));
            }
        }
    }
    if !any_condition {
        output.push_str("  none recorded yet — the operator has not observed this candidate\n");
    }

    match (plan_name, plan) {
        (None, _) => {
            output.push_str(
                "\nPlan:       none yet.\n  \
                 The operator publishes a plan on the parent policy's next reconcile. \
                 A candidate blocked by its parent reports Ready=False, \
                 reason=BlockedByActivePolicy above.\n",
            );
        }
        (Some(plan_name), None) => {
            output.push_str(&format!(
                "\nPlan:       {plan_name} (NOT READABLE)\n  \
                 The candidate names this plan but it could not be read — it may have been \
                 pruned by plan retention.\n",
            ));
        }
        (Some(plan_name), Some(plan)) => {
            output.push_str(&format!("\nPlan:       {plan_name}\n"));
            output.push_str(&format!(
                "  Phase:         {}\n",
                cell(string_at(plan, "status.phase"))
            ));
            output.push_str(&format!(
                "  Decision:      {}\n",
                format_plan_decision(plan)
            ));
            output.push_str(&format!(
                "  Change digest: {}\n",
                cell(string_at(plan, "status.changeDigest"))
            ));
            output.push_str(&format!(
                "  Computed at:   {}\n",
                cell(string_at(plan, "status.computedAt"))
            ));
            output.push_str(&format!(
                "  Staleness:     {}\n",
                format_plan_staleness(plan)
            ));
            output.push_str(&format!(
                "  Base pinned:   {}\n",
                cell(
                    string_at(plan, "spec.origin.baseContentDigest")
                        .map(|digest| abbreviate_digest(&digest))
                )
            ));
            if let Some(error) = string_at(plan, "status.lastError") {
                output.push_str(&format!("  Last error:    {error}\n"));
            }
        }
    }

    output.push_str(&format!(
        "\nPromotion:  {}\n",
        format_promotion_outcome(candidate)
    ));
    output
}

/// The plan's write-once decision, and who made it.
pub fn format_plan_decision(plan: &Value) -> String {
    let decided_by = string_at(plan, "status.decidedBy.username");

    for (condition_type, verb) in [("Approved", "approved"), ("Denied", "denied")] {
        if let Some(condition) = find_condition(plan, condition_type)
            && condition.status == "True"
        {
            return match decided_by {
                Some(username) => format!("{verb} by {username}"),
                // The CRD requires decidedBy alongside a terminal decision, so
                // its absence is a real anomaly and worth naming.
                None => format!("{verb}, but no decidedBy identity is recorded"),
            };
        }
    }

    "none recorded — awaiting review (decide with kubectl, see the plan-approval docs)".to_string()
}

/// Whether the plan still describes the candidate's effects.
pub fn format_plan_staleness(plan: &Value) -> String {
    if let Some(condition) = find_condition(plan, "Superseded")
        && condition.status == "True"
    {
        let reason = condition.reason.as_deref().unwrap_or("no reason recorded");
        return format!("STALE — superseded ({reason}); the candidate is replanned from scratch");
    }

    match string_at(plan, "status.revalidatedAt") {
        Some(at) => format!("current — last revalidated {at}"),
        None => "current — not revalidated since it was computed".to_string(),
    }
}

/// What promotion has to say about this candidate, if anything.
pub fn format_promotion_outcome(candidate: &Value) -> String {
    match find_condition(candidate, "Promoted") {
        Some(condition) if condition.status == "True" => format!(
            "promoted and executed ({})",
            condition.reason.as_deref().unwrap_or("Promoted")
        ),
        Some(condition) => format!(
            "did NOT complete ({}): {}",
            condition.reason.as_deref().unwrap_or("no reason recorded"),
            condition
                .message
                .as_deref()
                .unwrap_or("no message recorded on the condition"),
        ),
        None => "not promoted — the content has not been merged into the policy".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `pgroles candidate create` — validate a local manifest and file it.
pub async fn cmd_create(
    policy: &str,
    file: &Path,
    replaces: Option<&str>,
    namespace: &str,
) -> Result<()> {
    let yaml = read_manifest_file(file)?;
    let content = extract_candidate_content(&yaml)?;

    // Validate exactly the bytes about to be filed, through the same path
    // `pgroles validate` uses: a candidate the API server would reject on
    // bounds must fail here first, with the same field-level message.
    let content_yaml =
        serde_yaml::to_string(&content).context("failed to re-serialize policy content")?;
    let validated = validate_manifest(&content_yaml)
        .with_context(|| format!("policy content in {} is not valid", file.display()))?;

    let client = Client::try_default()
        .await
        .context("failed to create Kubernetes client")?;
    let candidates = candidate_api(client.clone(), namespace);

    // A typo in --policy would otherwise produce a candidate that sits Pending
    // forever with no explanation.
    policy_api(client, namespace)
        .get(policy)
        .await
        .with_context(|| {
            format!("failed to read postgrespolicy/{policy} in namespace {namespace}")
        })?;

    if let Some(replaces) = replaces {
        let replaced = candidates.get(replaces).await.with_context(|| {
            format!(
                "failed to read the candidate named by --replaces \
                 (postgrespolicycandidate/{replaces} in namespace {namespace})"
            )
        })?;
        let replaced_policy = string_at(&replaced.data, "spec.policyRef.name");
        if replaced_policy.as_deref() != Some(policy) {
            anyhow::bail!(
                "candidate {replaces} proposes content for policy {}, not {policy}; \
                 supersession is only meaningful within one policy",
                replaced_policy.as_deref().unwrap_or("<unknown>"),
            );
        }
    }

    let manifest = build_candidate_object(policy, replaces, content);
    let mut object: DynamicObject =
        serde_json::from_value(manifest).context("failed to build the candidate object")?;
    // `generateName` and `name` are mutually exclusive; the server assigns one.
    object.metadata.name = None;

    let created = candidates
        .create(&PostParams::default(), &object)
        .await
        .with_context(|| {
            format!("failed to create PostgresPolicyCandidate for policy {policy} in {namespace}")
        })?;

    let name = created.name_any();
    println!("Created postgrespolicycandidate/{name} in namespace {namespace}.");
    println!(
        "  policy: {policy}, {} role(s), {} grant(s), {} membership(s) after expansion",
        validated.expanded.roles.len(),
        validated.expanded.grants.len(),
        validated.expanded.memberships.len(),
    );
    if let Some(replaces) = replaces {
        println!("  supersedes: {replaces}");
    }
    println!("  review with: pgroles candidate status {name} -n {namespace}");

    Ok(())
}

/// `pgroles candidate list` — candidates filed against one policy.
pub async fn cmd_list(policy: &str, namespace: &str) -> Result<()> {
    let client = Client::try_default()
        .await
        .context("failed to create Kubernetes client")?;

    // Distinguishing "no such policy" from "no candidates" is the whole point
    // of looking the policy up before listing.
    policy_api(client.clone(), namespace)
        .get(policy)
        .await
        .with_context(|| {
            format!("failed to read postgrespolicy/{policy} in namespace {namespace}")
        })?;

    let candidates = candidate_api(client, namespace)
        .list(&ListParams::default())
        .await
        .with_context(|| format!("failed to list candidates in namespace {namespace}"))?;

    let mut rows: Vec<CandidateRow> = candidates
        .items
        .iter()
        .filter(|candidate| {
            string_at(&candidate.data, "spec.policyRef.name").as_deref() == Some(policy)
        })
        .map(|candidate| candidate_row(&candidate.data, &candidate.name_any()))
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    if rows.is_empty() {
        println!("No candidates for postgrespolicy/{policy} in namespace {namespace}.");
        return Ok(());
    }

    print!("{}", format_candidate_table(&rows));
    Ok(())
}

/// `pgroles candidate status` — one candidate and its plan in detail.
pub async fn cmd_status(name: &str, namespace: &str) -> Result<()> {
    let client = Client::try_default()
        .await
        .context("failed to create Kubernetes client")?;
    let candidate = candidate_api(client.clone(), namespace)
        .get(name)
        .await
        .with_context(|| {
            format!("failed to read postgrespolicycandidate/{name} in namespace {namespace}")
        })?;

    let plan_name = string_at(&candidate.data, "status.planRef.name");
    let plan = match &plan_name {
        Some(plan_name) => plan_api(client, namespace).get(plan_name).await.ok(),
        None => None,
    };

    print!(
        "{}",
        format_candidate_status(
            name,
            namespace,
            &candidate.data,
            plan_name.as_deref(),
            plan.as_ref().map(|plan| &plan.data),
        )
    );

    Ok(())
}

/// `pgroles candidate diff` — the SQL approving this candidate's plan would run.
pub async fn cmd_diff(name: &str, namespace: &str) -> Result<()> {
    let client = Client::try_default()
        .await
        .context("failed to create Kubernetes client")?;
    let candidate = candidate_api(client.clone(), namespace)
        .get(name)
        .await
        .with_context(|| {
            format!("failed to read postgrespolicycandidate/{name} in namespace {namespace}")
        })?;

    let plan_name = string_at(&candidate.data, "status.planRef.name").ok_or_else(|| {
        let phase = string_at(&candidate.data, "status.phase").unwrap_or_else(|| "?".to_string());
        anyhow::anyhow!(
            "candidate {name} has no plan yet (phase {phase}); there is nothing to diff. \
             Run `pgroles candidate status {name} -n {namespace}` to see why"
        )
    })?;

    let plan = plan_api(client.clone(), namespace)
        .get(&plan_name)
        .await
        .with_context(|| {
            format!("failed to read postgrespolicyplan/{plan_name} named by candidate {name}")
        })?;

    let sql = match select_plan_sql(&plan.data)
        .with_context(|| format!("cannot show the SQL for plan {plan_name}"))?
    {
        PlanSqlSource::Inline(sql) => sql,
        PlanSqlSource::ConfigMap {
            name: configmap_name,
            key,
            gzip,
        } => {
            let configmaps: Api<ConfigMap> = Api::namespaced(client, namespace);
            let configmap = configmaps.get(&configmap_name).await.with_context(|| {
                format!(
                    "failed to read ConfigMap {configmap_name} holding the SQL for plan {plan_name}"
                )
            })?;
            decode_configmap_sql(&configmap, &key, gzip)?
        }
    };

    if sql.trim().is_empty() {
        anyhow::bail!(
            "plan {plan_name} recorded an empty SQL preview; that is not the same as a plan \
             with no changes, which would report Ready=True, reason=NoEffects on the candidate"
        );
    }

    // Context on stderr so stdout stays pipeable into a file or psql review.
    eprintln!("-- candidate {name}, plan {plan_name}, namespace {namespace}");
    eprintln!(
        "-- this is what approving the plan would execute (passwords redacted by the operator)"
    );
    print!("{sql}");
    if !sql.ends_with('\n') {
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;
    use std::io::Write;

    fn gzip(input: &str) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(input.as_bytes()).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    // -----------------------------------------------------------------------
    // Content extraction
    // -----------------------------------------------------------------------

    #[test]
    fn extract_content_takes_a_bare_manifest_verbatim() {
        let content = extract_candidate_content(
            r#"
default_owner: app_owner
role_pattern: "{schema}_{profile}"
roles:
  - name: reporting_reader
    login: true
"#,
        )
        .expect("bare manifest should extract");

        assert_eq!(content["default_owner"], json!("app_owner"));
        assert_eq!(content["role_pattern"], json!("{schema}_{profile}"));
        assert_eq!(content["roles"][0]["name"], json!("reporting_reader"));
    }

    #[test]
    fn extract_content_drops_execution_fields_from_a_policy_cr() {
        let content = extract_candidate_content(
            r#"
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: orders
spec:
  connection:
    secretRef:
      name: postgres-credentials
  interval: "5m"
  mode: apply
  suspend: false
  approval: manual
  reconciliation_mode: authoritative
  roles:
    - name: reporting_reader
      login: true
"#,
        )
        .expect("policy CR should extract");

        let object = content.as_object().expect("content is an object");
        assert_eq!(
            object.keys().collect::<Vec<_>>(),
            vec!["reconciliation_mode", "roles"]
        );
    }

    #[test]
    fn extract_content_unwraps_a_candidate_cr() {
        let content = extract_candidate_content(
            r#"
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata:
  generateName: orders-change-
spec:
  policyRef:
    name: orders
  content:
    roles:
      - name: reporting_reader
        login: true
"#,
        )
        .expect("candidate CR should extract");

        assert_eq!(content["roles"][0]["name"], json!("reporting_reader"));
    }

    #[test]
    fn extract_content_rejects_keys_a_candidate_cannot_carry() {
        let error = extract_candidate_content(
            r#"
auth_providers:
  - type: cloud_sql_iam
roles:
  - name: reporting_reader
"#,
        )
        .expect_err("auth_providers has no candidate counterpart");

        let message = error.to_string();
        assert!(message.contains("auth_providers"), "unexpected: {message}");
        assert!(message.contains("spec.content"), "unexpected: {message}");
    }

    #[test]
    fn extract_content_rejects_an_empty_manifest() {
        let error = extract_candidate_content("mode: apply\n")
            .expect_err("a candidate proposing nothing should fail");

        assert!(
            error.to_string().contains("no policy content"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn extract_content_rejects_a_valueless_content_key() {
        let error =
            extract_candidate_content("roles:\n").expect_err("a null content key should fail");

        assert!(error.to_string().contains("`roles`"), "unexpected: {error}");
    }

    // -----------------------------------------------------------------------
    // Argument shaping
    // -----------------------------------------------------------------------

    #[test]
    fn build_candidate_object_uses_generate_name_and_omits_absent_replaces() {
        let object = build_candidate_object("orders", None, json!({ "roles": [] }));

        assert_eq!(object["metadata"]["generateName"], json!("orders-"));
        assert_eq!(object["metadata"].get("name"), None);
        assert_eq!(object["spec"]["policyRef"]["name"], json!("orders"));
        assert_eq!(object["spec"].get("replaces"), None);
        assert_eq!(object["kind"], json!("PostgresPolicyCandidate"));
    }

    #[test]
    fn build_candidate_object_records_replaces_when_given() {
        let object = build_candidate_object("orders", Some("orders-x7k2p"), json!({ "roles": [] }));

        assert_eq!(object["spec"]["replaces"], json!("orders-x7k2p"));
    }

    #[test]
    fn generate_name_prefix_leaves_room_for_the_server_suffix() {
        let long_policy = "a".repeat(253);
        let prefix = generate_name_prefix(&long_policy);

        assert_eq!(prefix.len(), 248);
        assert!(prefix.len() + 5 <= 253);
    }

    // -----------------------------------------------------------------------
    // Output formatting
    // -----------------------------------------------------------------------

    #[test]
    fn abbreviate_digest_keeps_the_algorithm_prefix() {
        assert_eq!(
            abbreviate_digest("sha256:0123456789abcdef0123456789abcdef"),
            "sha256:0123456789ab…"
        );
        assert_eq!(abbreviate_digest("short"), "short");
    }

    #[test]
    fn abbreviate_digest_does_not_panic_on_a_malformed_multibyte_digest() {
        // The digest is read from the cluster, so a listing must degrade rather
        // than abort if it is not the hex string it is supposed to be. Byte 12
        // falls inside a character in both of these.
        assert_eq!(
            abbreviate_digest("sha256:ααααααααααααααα"),
            "sha256:αααααααααααα…"
        );
        assert_eq!(abbreviate_digest("ααααααααααααααα"), "αααααααααααα…");
        // Exactly KEEP characters is not truncated, multi-byte or not.
        assert_eq!(abbreviate_digest("αααααααααααα"), "αααααααααααα");
    }

    fn planned_candidate() -> Value {
        json!({
            "spec": { "policyRef": { "name": "orders" } },
            "status": {
                "phase": "Planned",
                "contentDigest": "sha256:0123456789abcdef0123456789abcdef",
                "planRef": { "name": "orders-change-plan-9f21c4" },
                "conditions": [
                    { "type": "Ready", "status": "True", "reason": "Planned",
                      "message": "a current plan exists" }
                ]
            }
        })
    }

    #[test]
    fn candidate_row_fills_absent_cells_with_a_placeholder() {
        let row = candidate_row(&planned_candidate(), "orders-change-x7k2p");

        assert_eq!(row.phase, "Planned");
        assert_eq!(row.digest, "sha256:0123456789ab…");
        assert_eq!(row.plan, "orders-change-plan-9f21c4");
        assert_eq!(row.ready, "True/Planned");
        // Never blank: a blank cell reads as a rendering failure.
        assert_eq!(row.superseded, NONE_CELL);
        assert_eq!(row.promoted, NONE_CELL);
    }

    #[test]
    fn candidate_row_of_an_unobserved_candidate_is_all_placeholders() {
        let row = candidate_row(&json!({ "spec": {} }), "orders-change-new");

        assert_eq!(row.phase, NONE_CELL);
        assert_eq!(row.digest, NONE_CELL);
        assert_eq!(row.plan, NONE_CELL);
        assert_eq!(row.ready, NONE_CELL);
    }

    #[test]
    fn format_candidate_table_aligns_columns_under_headers() {
        let rows = vec![candidate_row(&planned_candidate(), "orders-change-x7k2p")];
        let table = format_candidate_table(&rows);
        let mut lines = table.lines();

        let header = lines.next().expect("header row");
        let row = lines.next().expect("data row");
        assert!(header.starts_with("NAME"));
        assert!(row.starts_with("orders-change-x7k2p"));
        assert_eq!(
            header.find("PHASE"),
            row.find("Planned"),
            "PHASE column is misaligned:\n{table}"
        );
        assert!(lines.next().is_none(), "unexpected extra rows:\n{table}");
    }

    #[test]
    fn format_plan_decision_names_the_decider() {
        let plan = json!({
            "status": {
                "decidedBy": { "username": "e2e-reviewer" },
                "conditions": [{ "type": "Approved", "status": "True", "reason": "Approved" }]
            }
        });

        assert_eq!(format_plan_decision(&plan), "approved by e2e-reviewer");
    }

    #[test]
    fn format_plan_decision_reports_an_undecided_plan_explicitly() {
        let plan = json!({ "status": { "phase": "Pending", "conditions": [] } });

        assert!(format_plan_decision(&plan).starts_with("none recorded"));
    }

    #[test]
    fn format_plan_staleness_names_the_supersede_reason() {
        let plan = json!({
            "status": {
                "conditions": [
                    { "type": "Superseded", "status": "True", "reason": "EffectsChanged" }
                ]
            }
        });

        let rendered = format_plan_staleness(&plan);
        assert!(rendered.contains("STALE"), "unexpected: {rendered}");
        assert!(
            rendered.contains("EffectsChanged"),
            "unexpected: {rendered}"
        );
    }

    #[test]
    fn format_promotion_outcome_distinguishes_incomplete_promotion() {
        let candidate = json!({
            "status": {
                "conditions": [{
                    "type": "Promoted",
                    "status": "False",
                    "reason": "PromotionDigestMismatch",
                    "message": "the merged spec is not being enforced"
                }]
            }
        });

        let rendered = format_promotion_outcome(&candidate);
        assert!(
            rendered.contains("did NOT complete"),
            "unexpected: {rendered}"
        );
        assert!(
            rendered.contains("PromotionDigestMismatch"),
            "unexpected: {rendered}"
        );
    }

    #[test]
    fn format_candidate_status_explains_a_candidate_with_no_plan() {
        let candidate = json!({
            "spec": { "policyRef": { "name": "orders" } },
            "status": { "phase": "Pending" }
        });

        let rendered = format_candidate_status("orders-new", "default", &candidate, None, None);
        assert!(rendered.contains("Plan:       none yet"), "{rendered}");
        assert!(rendered.contains("none recorded yet"), "{rendered}");
        assert!(rendered.contains("not promoted"), "{rendered}");
    }

    #[test]
    fn format_candidate_status_renders_the_plan_decision_and_target_override() {
        let mut candidate = planned_candidate();
        candidate["spec"]["target"] = json!({
            "connectionRef": { "secretName": "orders-new-postgres", "key": "url" }
        });
        let plan = json!({
            "spec": { "origin": { "baseContentDigest": "sha256:fedcba9876543210" } },
            "status": {
                "phase": "Approved",
                "changeDigest": "sha256:aaaa",
                "computedAt": "2026-08-17T00:00:00Z",
                "decidedBy": { "username": "reviewer" },
                "conditions": [{ "type": "Approved", "status": "True", "reason": "Approved" }]
            }
        });

        let rendered = format_candidate_status(
            "orders-change-x7k2p",
            "default",
            &candidate,
            Some("orders-change-plan-9f21c4"),
            Some(&plan),
        );

        assert!(rendered.contains("approved by reviewer"), "{rendered}");
        assert!(rendered.contains("orders-new-postgres"), "{rendered}");
        assert!(
            rendered.contains("Base pinned:   sha256:fedcba987654"),
            "{rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // sqlInline / sqlRef selection
    // -----------------------------------------------------------------------

    #[test]
    fn select_plan_sql_prefers_a_complete_inline_preview() {
        let plan = json!({ "status": { "sqlInline": "CREATE ROLE a;\n" } });

        assert_eq!(
            select_plan_sql(&plan).expect("inline SQL should be selected"),
            PlanSqlSource::Inline("CREATE ROLE a;\n".to_string())
        );
    }

    #[test]
    fn select_plan_sql_falls_back_to_the_configmap_when_inline_is_truncated() {
        let plan = json!({
            "status": {
                "sqlInline": "CREATE ROLE a; -- truncated",
                "sqlTruncated": true,
                "sqlRef": { "name": "plan-sql", "key": "plan.sql.gz", "compression": "gzip" }
            }
        });

        assert_eq!(
            select_plan_sql(&plan).expect("sqlRef should win over a truncated preview"),
            PlanSqlSource::ConfigMap {
                name: "plan-sql".to_string(),
                key: "plan.sql.gz".to_string(),
                gzip: true,
            }
        );
    }

    #[test]
    fn select_plan_sql_reads_an_uncompressed_legacy_configmap() {
        let plan = json!({
            "status": { "sqlRef": { "name": "plan-sql", "key": "plan.sql" } }
        });

        assert_eq!(
            select_plan_sql(&plan).expect("legacy sqlRef should be selected"),
            PlanSqlSource::ConfigMap {
                name: "plan-sql".to_string(),
                key: "plan.sql".to_string(),
                gzip: false,
            }
        );
    }

    #[test]
    fn select_plan_sql_refuses_a_truncated_preview_with_no_configmap() {
        let plan = json!({
            "status": { "sqlInline": "CREATE ROLE a; -- trunc", "sqlTruncated": true }
        });

        let error = select_plan_sql(&plan).expect_err("a fragment must not be shown as the plan");
        assert!(
            error.to_string().contains("truncated"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn select_plan_sql_refuses_a_plan_with_no_sql_at_all() {
        let error = select_plan_sql(&json!({ "status": { "phase": "Pending" } }))
            .expect_err("a plan with no SQL must not render as an empty diff");

        assert!(
            error.to_string().contains("no SQL recorded"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn select_plan_sql_refuses_a_half_populated_sql_ref() {
        let plan = json!({ "status": { "sqlRef": { "name": "plan-sql" } } });

        let error = select_plan_sql(&plan).expect_err("an incomplete sqlRef must fail loudly");
        assert!(
            error.to_string().contains("incomplete"),
            "unexpected: {error}"
        );
    }

    // -----------------------------------------------------------------------
    // ConfigMap decoding
    // -----------------------------------------------------------------------

    #[test]
    fn decode_configmap_sql_inflates_gzipped_binary_data() {
        let configmap = ConfigMap {
            binary_data: Some(BTreeMap::from([(
                "plan.sql.gz".to_string(),
                ByteString(gzip("CREATE ROLE reporting_reader;\n")),
            )])),
            ..Default::default()
        };

        assert_eq!(
            decode_configmap_sql(&configmap, "plan.sql.gz", true).expect("should inflate"),
            "CREATE ROLE reporting_reader;\n"
        );
    }

    #[test]
    fn decode_configmap_sql_reads_uncompressed_data() {
        let configmap = ConfigMap {
            data: Some(BTreeMap::from([(
                "plan.sql".to_string(),
                "CREATE ROLE a;\n".to_string(),
            )])),
            ..Default::default()
        };

        assert_eq!(
            decode_configmap_sql(&configmap, "plan.sql", false).expect("should read"),
            "CREATE ROLE a;\n"
        );
    }

    #[test]
    fn decode_configmap_sql_fails_when_the_key_is_missing() {
        let configmap = ConfigMap::default();

        let error = decode_configmap_sql(&configmap, "plan.sql.gz", true)
            .expect_err("a missing artifact must not read as empty SQL");
        assert!(
            error.to_string().contains("plan.sql.gz"),
            "unexpected: {error}"
        );
    }
}
