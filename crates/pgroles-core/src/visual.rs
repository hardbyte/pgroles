//! Visualization model and renderers for `RoleGraph`.
//!
//! Converts a [`RoleGraph`] into a [`VisualGraph`] — a graph-oriented DTO
//! suitable for JSON export, DOT/Mermaid rendering, and terminal tree output.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::manifest::{ObjectType, Privilege};
use crate::model::{DefaultPrivKey, GrantKey, RoleGraph};

// ---------------------------------------------------------------------------
// DTO types
// ---------------------------------------------------------------------------

/// Top-level visualization graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualGraph {
    pub meta: VisualMeta,
    pub nodes: Vec<VisualNode>,
    pub edges: Vec<VisualEdge>,
}

/// Metadata about the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualMeta {
    pub source: VisualSource,
    pub role_count: usize,
    pub grant_count: usize,
    pub default_privilege_count: usize,
    pub membership_count: usize,
    pub collapsed: bool,
}

/// Where the graph data came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisualSource {
    Desired,
    Current,
}

/// A node in the visual graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualNode {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privileges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The kind of a visual node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Role,
    ExternalPrincipal,
    GrantTarget,
    DefaultPrivilegeTarget,
}

/// An edge in the visual graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualEdge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    pub label: String,
}

/// The kind of a visual edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Membership,
    Grant,
    DefaultPrivilege,
}

// ---------------------------------------------------------------------------
// RoleGraph -> VisualGraph transformation
// ---------------------------------------------------------------------------

/// Build a [`VisualGraph`] from a [`RoleGraph`].
///
/// Grant targets are collapsed by schema and object type by default:
/// individual object names become `schema.tables[*]` etc.
pub fn build_visual_graph(graph: &RoleGraph, source: VisualSource) -> VisualGraph {
    let mut nodes: Vec<VisualNode> = Vec::new();
    let mut edges: Vec<VisualEdge> = Vec::new();
    let mut node_ids: BTreeSet<String> = BTreeSet::new();

    // Track which members are external (referenced in memberships but not in roles).
    let managed_role_names: BTreeSet<&str> = graph.roles.keys().map(|name| name.as_str()).collect();

    // --- Role nodes ---
    for (name, state) in &graph.roles {
        let node_id = format!("role:{name}");
        nodes.push(VisualNode {
            id: node_id.clone(),
            label: name.clone(),
            kind: NodeKind::Role,
            managed: Some(true),
            login: Some(state.login),
            privileges: Vec::new(),
            comment: state.comment.clone(),
        });
        node_ids.insert(node_id);
    }

    // --- External principal nodes (from memberships) ---
    for edge in &graph.memberships {
        if !managed_role_names.contains(edge.member.as_str()) {
            let node_id = format!("external:{}", edge.member);
            if node_ids.insert(node_id.clone()) {
                nodes.push(VisualNode {
                    id: node_id,
                    label: edge.member.clone(),
                    kind: NodeKind::ExternalPrincipal,
                    managed: Some(false),
                    login: None,
                    privileges: Vec::new(),
                    comment: None,
                });
            }
        }
    }

    // --- Membership edges ---
    for edge in &graph.memberships {
        let source_id = if managed_role_names.contains(edge.member.as_str()) {
            format!("role:{}", edge.member)
        } else {
            format!("external:{}", edge.member)
        };
        let target_id = format!("role:{}", edge.role);

        let label = membership_label(edge.inherit, edge.admin);
        edges.push(VisualEdge {
            source: source_id,
            target: target_id,
            kind: EdgeKind::Membership,
            label,
        });
    }

    // --- Collapsed grant target nodes and edges ---
    // Group grants by (role, object_type, schema_or_db) to collapse.
    let collapsed_grants = collapse_grants(&graph.grants);
    for (collapsed_key, privileges) in &collapsed_grants {
        let node_id = collapsed_key.node_id();
        if node_ids.insert(node_id.clone()) {
            nodes.push(VisualNode {
                id: node_id.clone(),
                label: collapsed_key.label(),
                kind: NodeKind::GrantTarget,
                managed: None,
                login: None,
                privileges: privileges.iter().map(|p| p.to_string()).collect(),
                comment: None,
            });
        } else {
            // Node already exists from another role — merge privileges.
            if let Some(existing) = nodes.iter_mut().find(|n| n.id == node_id) {
                for priv_str in privileges.iter().map(|p| p.to_string()) {
                    if !existing.privileges.contains(&priv_str) {
                        existing.privileges.push(priv_str);
                    }
                }
                existing.privileges.sort();
            }
        }

        let privilege_label = privileges
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        edges.push(VisualEdge {
            source: format!("role:{}", collapsed_key.role),
            target: node_id,
            kind: EdgeKind::Grant,
            label: privilege_label,
        });
    }

    // --- Default privilege nodes and edges ---
    for (key, state) in &graph.default_privileges {
        let node_id = default_priv_node_id(key);
        let node_label = format!("defaults: {} -> {}.{}s", key.owner, key.schema, key.on_type);

        if node_ids.insert(node_id.clone()) {
            nodes.push(VisualNode {
                id: node_id.clone(),
                label: node_label,
                kind: NodeKind::DefaultPrivilegeTarget,
                managed: None,
                login: None,
                privileges: state.privileges.iter().map(|p| p.to_string()).collect(),
                comment: None,
            });
        }

        let privilege_label = state
            .privileges
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        edges.push(VisualEdge {
            source: node_id,
            target: format!("role:{}", key.grantee),
            kind: EdgeKind::DefaultPrivilege,
            label: privilege_label,
        });
    }

    // Sort nodes and edges for deterministic output.
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    edges.sort_by(|a, b| (&a.source, &a.target, &a.kind).cmp(&(&b.source, &b.target, &b.kind)));

    VisualGraph {
        meta: VisualMeta {
            source,
            role_count: graph.roles.len(),
            grant_count: graph.grants.len(),
            default_privilege_count: graph.default_privileges.len(),
            membership_count: graph.memberships.len(),
            collapsed: true,
        },
        nodes,
        edges,
    }
}

// ---------------------------------------------------------------------------
// Grant collapsing
// ---------------------------------------------------------------------------

/// Key for a collapsed grant group: (role, object_type, schema_or_db).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CollapsedGrantKey {
    role: String,
    object_type: ObjectType,
    /// Schema name for schema-scoped grants, or the database/object name for
    /// schema-level and database-level grants.
    scope: String,
}

impl CollapsedGrantKey {
    fn node_id(&self) -> String {
        match self.object_type {
            ObjectType::Schema => format!("grant:schema:{}:{}", self.scope, self.scope),
            ObjectType::Database => format!("grant:database:{}:{}", self.scope, self.scope),
            _ => format!("grant:{}:{}:*", self.object_type, self.scope),
        }
    }

    fn label(&self) -> String {
        match self.object_type {
            ObjectType::Schema => format!("{}.schema", self.scope),
            ObjectType::Database => format!("{}.database", self.scope),
            _ => format!("{}.{}s[*]", self.scope, self.object_type),
        }
    }
}

fn collapse_grants(
    grants: &BTreeMap<GrantKey, crate::model::GrantState>,
) -> BTreeMap<CollapsedGrantKey, BTreeSet<Privilege>> {
    let mut collapsed: BTreeMap<CollapsedGrantKey, BTreeSet<Privilege>> = BTreeMap::new();

    for (key, state) in grants {
        let scope = match key.object_type {
            // Schema-level grants: the schema name is in key.name (from manifest expansion).
            ObjectType::Schema => key
                .name
                .as_deref()
                .or(key.schema.as_deref())
                .unwrap_or("public")
                .to_string(),
            // Database-level grants: the database name is in key.name.
            ObjectType::Database => key.name.as_deref().unwrap_or("db").to_string(),
            // Object-level grants: use the schema.
            _ => key.schema.as_deref().unwrap_or("public").to_string(),
        };

        let collapsed_key = CollapsedGrantKey {
            role: key.role.clone(),
            object_type: key.object_type,
            scope,
        };

        collapsed
            .entry(collapsed_key)
            .or_default()
            .extend(&state.privileges);
    }

    collapsed
}

fn default_priv_node_id(key: &DefaultPrivKey) -> String {
    format!(
        "default:{}:{}:{}:{}",
        key.owner, key.schema, key.on_type, key.grantee
    )
}

fn membership_label(inherit: bool, admin: bool) -> String {
    let mut parts = vec!["member"];
    if !inherit {
        parts.push("NOINHERIT");
    }
    if admin {
        parts.push("ADMIN");
    }
    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

/// Render the graph as pretty-printed JSON.
pub fn render_json(graph: &VisualGraph) -> String {
    serde_json::to_string_pretty(graph).expect("VisualGraph serialization should not fail")
}

/// Render the graph as Graphviz DOT.
pub fn render_dot(graph: &VisualGraph) -> String {
    let mut out = String::new();
    writeln!(out, "digraph roles {{").unwrap();
    writeln!(out, "  rankdir=LR;").unwrap();
    writeln!(out, "  node [fontname=\"sans-serif\" fontsize=10];").unwrap();
    writeln!(out, "  edge [fontname=\"sans-serif\" fontsize=9];").unwrap();
    writeln!(out).unwrap();

    for node in &graph.nodes {
        let dot_id = dot_escape_id(&node.id);
        let label = dot_escape_label(&node.label);
        let shape = match node.kind {
            NodeKind::Role => {
                if node.login == Some(true) {
                    "box"
                } else {
                    "ellipse"
                }
            }
            NodeKind::ExternalPrincipal => "hexagon",
            NodeKind::GrantTarget => "note",
            NodeKind::DefaultPrivilegeTarget => "component",
        };
        let style = match node.kind {
            NodeKind::Role => "filled",
            NodeKind::ExternalPrincipal => "dashed,filled",
            NodeKind::GrantTarget => "filled",
            NodeKind::DefaultPrivilegeTarget => "filled",
        };
        let fillcolor = match node.kind {
            NodeKind::Role => {
                if node.login == Some(true) {
                    "#e0f2fe" // light blue for login roles
                } else {
                    "#f0fdf4" // light green for group roles
                }
            }
            NodeKind::ExternalPrincipal => "#fef3c7", // light amber
            NodeKind::GrantTarget => "#f5f5f4",       // stone-100
            NodeKind::DefaultPrivilegeTarget => "#f0fdfa", // teal-50
        };
        writeln!(
            out,
            "  {dot_id} [label=\"{label}\" shape={shape} style=\"{style}\" fillcolor=\"{fillcolor}\"];",
        )
        .unwrap();
    }

    writeln!(out).unwrap();

    for edge in &graph.edges {
        let source = dot_escape_id(&edge.source);
        let target = dot_escape_id(&edge.target);
        let label = dot_escape_label(&edge.label);
        let style = match edge.kind {
            EdgeKind::Membership => "solid",
            EdgeKind::Grant => "solid",
            EdgeKind::DefaultPrivilege => "dashed",
        };
        let color = match edge.kind {
            EdgeKind::Membership => "#1e3a5f",
            EdgeKind::Grant => "#374151",
            EdgeKind::DefaultPrivilege => "#0d9488",
        };
        writeln!(
            out,
            "  {source} -> {target} [label=\"{label}\" style={style} color=\"{color}\" fontcolor=\"{color}\"];",
        )
        .unwrap();
    }

    writeln!(out, "}}").unwrap();
    out
}

/// Render the graph as Mermaid flowchart syntax.
pub fn render_mermaid(graph: &VisualGraph) -> String {
    let mut out = String::new();
    writeln!(out, "graph LR").unwrap();

    for node in &graph.nodes {
        let mermaid_id = mermaid_escape_id(&node.id);
        let label = mermaid_escape_label(&node.label);
        let shape = match node.kind {
            NodeKind::Role => {
                if node.login == Some(true) {
                    format!("[{label}]")
                } else {
                    format!("([{label}])")
                }
            }
            NodeKind::ExternalPrincipal => format!("{{{{{label}}}}}"),
            NodeKind::GrantTarget => format!("[/{label}/]"),
            NodeKind::DefaultPrivilegeTarget => format!("[\\{label}\\]"),
        };
        writeln!(out, "  {mermaid_id}{shape}").unwrap();
    }

    for edge in &graph.edges {
        let source = mermaid_escape_id(&edge.source);
        let target = mermaid_escape_id(&edge.target);
        let label = mermaid_escape_label(&edge.label);
        let arrow = match edge.kind {
            EdgeKind::Membership => "-->",
            EdgeKind::Grant => "-->",
            EdgeKind::DefaultPrivilege => "-.->",
        };
        if label.is_empty() {
            writeln!(out, "  {source} {arrow} {target}").unwrap();
        } else {
            writeln!(out, "  {source} {arrow}|{label}| {target}").unwrap();
        }
    }

    out
}

/// Render the graph as an indented text tree for terminal display.
pub fn render_tree(graph: &VisualGraph) -> String {
    let mut out = String::new();

    // Build lookup structures for edges by role.
    let mut membership_edges: BTreeMap<&str, Vec<&VisualEdge>> = BTreeMap::new();
    let mut grant_edges: BTreeMap<&str, Vec<&VisualEdge>> = BTreeMap::new();
    let mut default_priv_edges: BTreeMap<&str, Vec<&VisualEdge>> = BTreeMap::new();
    let node_map: BTreeMap<&str, &VisualNode> =
        graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    for edge in &graph.edges {
        match edge.kind {
            EdgeKind::Membership => {
                membership_edges
                    .entry(edge.target.as_str())
                    .or_default()
                    .push(edge);
            }
            EdgeKind::Grant => {
                grant_edges
                    .entry(edge.source.as_str())
                    .or_default()
                    .push(edge);
            }
            EdgeKind::DefaultPrivilege => {
                default_priv_edges
                    .entry(edge.target.as_str())
                    .or_default()
                    .push(edge);
            }
        }
    }

    // Collect role nodes in order.
    let role_nodes: Vec<&VisualNode> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Role)
        .collect();

    for (role_idx, role_node) in role_nodes.iter().enumerate() {
        let is_last_role = role_idx == role_nodes.len() - 1;
        let role_connector = if is_last_role { "\u{2514}" } else { "\u{251c}" };
        let role_tag = if role_node.login == Some(true) {
            " [LOGIN]"
        } else {
            ""
        };
        writeln!(
            out,
            "{role_connector}\u{2500}\u{2500} {}{role_tag}",
            role_node.label
        )
        .unwrap();

        let child_prefix = if is_last_role { "    " } else { "\u{2502}   " };

        // Count how many sections this role has for connector logic.
        let members = membership_edges.get(role_node.id.as_str());
        let grants = grant_edges.get(role_node.id.as_str());
        let default_privs = default_priv_edges.get(role_node.id.as_str());

        let section_count = members.is_some() as usize
            + grants.is_some() as usize
            + default_privs.is_some() as usize;
        let mut section_idx = 0;

        if let Some(member_list) = members {
            let is_last_section = section_idx == section_count - 1;
            render_tree_section(
                &mut out,
                child_prefix,
                is_last_section,
                "Members",
                member_list,
                &node_map,
                |edge, node_map| {
                    let label = node_map
                        .get(edge.source.as_str())
                        .map(|n| n.label.as_str())
                        .unwrap_or(&edge.source);
                    let flags = if edge.label != "member" {
                        format!(" ({0})", edge.label)
                    } else {
                        String::new()
                    };
                    format!("{label}{flags}")
                },
            );
            section_idx += 1;
        }

        if let Some(grant_list) = grants {
            let is_last_section = section_idx == section_count - 1;
            render_tree_section(
                &mut out,
                child_prefix,
                is_last_section,
                "Grants",
                grant_list,
                &node_map,
                |edge, node_map| {
                    let label = node_map
                        .get(edge.target.as_str())
                        .map(|n| n.label.as_str())
                        .unwrap_or(&edge.target);
                    format!("{label}: {}", edge.label)
                },
            );
            section_idx += 1;
        }

        if let Some(dp_list) = default_privs {
            let is_last_section = section_idx == section_count - 1;
            render_tree_section(
                &mut out,
                child_prefix,
                is_last_section,
                "Default Privileges",
                dp_list,
                &node_map,
                |edge, node_map| {
                    let label = node_map
                        .get(edge.source.as_str())
                        .map(|n| n.label.as_str())
                        .unwrap_or(&edge.source);
                    format!("{label}: {}", edge.label)
                },
            );
            let _ = section_idx;
        }
    }

    // Show external principals.
    let external_nodes: Vec<&VisualNode> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::ExternalPrincipal)
        .collect();

    if !external_nodes.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "External principals:").unwrap();
        for (idx, node) in external_nodes.iter().enumerate() {
            let is_last = idx == external_nodes.len() - 1;
            let connector = if is_last { "\u{2514}" } else { "\u{251c}" };
            writeln!(out, "{connector}\u{2500}\u{2500} {}", node.label).unwrap();
        }
    }

    out
}

/// Render a single section (Members, Grants, Default Privileges) under a role
/// in the tree output.
fn render_tree_section(
    out: &mut String,
    child_prefix: &str,
    is_last_section: bool,
    section_name: &str,
    edges: &[&VisualEdge],
    node_map: &BTreeMap<&str, &VisualNode>,
    format_item: impl Fn(&VisualEdge, &BTreeMap<&str, &VisualNode>) -> String,
) {
    let section_connector = if is_last_section {
        "\u{2514}"
    } else {
        "\u{251c}"
    };
    let item_prefix = if is_last_section {
        format!("{child_prefix}    ")
    } else {
        format!("{child_prefix}\u{2502}   ")
    };
    writeln!(
        out,
        "{child_prefix}{section_connector}\u{2500}\u{2500} {section_name}"
    )
    .unwrap();
    for (idx, edge) in edges.iter().enumerate() {
        let is_last = idx == edges.len() - 1;
        let connector = if is_last { "\u{2514}" } else { "\u{251c}" };
        let item_text = format_item(edge, node_map);
        writeln!(out, "{item_prefix}{connector}\u{2500}\u{2500} {item_text}").unwrap();
    }
}

// ---------------------------------------------------------------------------
// Escape helpers
// ---------------------------------------------------------------------------

fn dot_escape_id(id: &str) -> String {
    format!("\"{}\"", id.replace('\\', "\\\\").replace('"', "\\\""))
}

fn dot_escape_label(label: &str) -> String {
    label
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn mermaid_escape_id(id: &str) -> String {
    // Mermaid IDs must be alphanumeric + hyphens + underscores.
    // Use distinct substitutions to avoid collisions between IDs that
    // differ only by punctuation (e.g. "alice@x.com" vs "alice_x.com").
    let mut out = String::with_capacity(id.len());
    for ch in id.chars() {
        match ch {
            ':' => out.push_str("__"),
            '.' => out.push_str("_d_"),
            '@' => out.push_str("_at_"),
            '*' => out.push_str("_star_"),
            ' ' => out.push_str("_sp_"),
            '/' => out.push_str("_sl_"),
            '\\' => out.push_str("_bs_"),
            c if c.is_alphanumeric() || c == '-' || c == '_' => out.push(c),
            _ => {
                out.push_str(&format!("_x{:02x}_", ch as u32));
            }
        }
    }
    out
}

fn mermaid_escape_label(label: &str) -> String {
    // Mermaid labels: escape quotes and brackets.
    label.replace('"', "#quot;").replace(['[', ']'], "")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{expand_manifest, parse_manifest};
    use crate::model::RoleGraph;

    fn build_test_graph() -> RoleGraph {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table

schemas:
  - name: orders
    profiles: [editor]

roles:
  - name: analytics
    login: true
    comment: "Read-only analytics"

grants:
  - role: analytics
    privileges: [CONNECT]
    on: { type: database, name: mydb }

memberships:
  - role: orders-editor
    members:
      - name: "team@example.com"
      - name: analytics
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap()
    }

    #[test]
    fn visual_graph_has_correct_node_count() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);

        // Roles: orders-editor, analytics
        let role_nodes: Vec<_> = visual
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Role)
            .collect();
        assert_eq!(role_nodes.len(), 2);

        // External: team@example.com
        let external_nodes: Vec<_> = visual
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::ExternalPrincipal)
            .collect();
        assert_eq!(external_nodes.len(), 1);
        assert_eq!(external_nodes[0].label, "team@example.com");
    }

    #[test]
    fn visual_graph_login_flag_correct() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);

        let analytics = visual
            .nodes
            .iter()
            .find(|n| n.label == "analytics")
            .unwrap();
        assert_eq!(analytics.login, Some(true));

        let editor = visual
            .nodes
            .iter()
            .find(|n| n.label == "orders-editor")
            .unwrap();
        assert_eq!(editor.login, Some(false));
    }

    #[test]
    fn visual_graph_has_membership_edges() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);

        let membership_edges: Vec<_> = visual
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Membership)
            .collect();
        assert_eq!(membership_edges.len(), 2);
    }

    #[test]
    fn visual_graph_collapses_grants() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);

        let grant_targets: Vec<_> = visual
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::GrantTarget)
            .collect();

        // orders.schema, orders.tables[*], mydb.database
        assert_eq!(grant_targets.len(), 3, "grant targets: {grant_targets:?}");
    }

    #[test]
    fn visual_graph_has_default_privilege_nodes() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);

        let dp_nodes: Vec<_> = visual
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::DefaultPrivilegeTarget)
            .collect();
        assert_eq!(dp_nodes.len(), 1);
        assert!(dp_nodes[0].label.contains("app_owner"));
        assert!(dp_nodes[0].label.contains("orders"));
    }

    #[test]
    fn visual_graph_nodes_are_sorted() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);

        let ids: Vec<&str> = visual.nodes.iter().map(|n| n.id.as_str()).collect();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        assert_eq!(ids, sorted_ids, "nodes should be sorted by ID");
    }

    #[test]
    fn json_roundtrips() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);
        let json = render_json(&visual);
        let deserialized: VisualGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.nodes.len(), visual.nodes.len());
        assert_eq!(deserialized.edges.len(), visual.edges.len());
    }

    #[test]
    fn dot_output_is_valid() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);
        let dot = render_dot(&visual);

        assert!(dot.starts_with("digraph roles {"));
        assert!(dot.contains("orders-editor"));
        assert!(dot.contains("analytics"));
        assert!(dot.contains("team@example.com"));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn mermaid_output_is_valid() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);
        let mermaid = render_mermaid(&visual);

        assert!(mermaid.starts_with("graph LR\n"));
        assert!(mermaid.contains("orders-editor"));
        assert!(mermaid.contains("analytics"));
    }

    #[test]
    fn tree_output_shows_roles() {
        let graph = build_test_graph();
        let visual = build_visual_graph(&graph, VisualSource::Desired);
        let tree = render_tree(&visual);

        assert!(
            tree.contains("analytics"),
            "tree should contain analytics role"
        );
        assert!(
            tree.contains("orders-editor"),
            "tree should contain orders-editor role"
        );
        assert!(tree.contains("[LOGIN]"), "tree should show LOGIN tag");
        assert!(
            tree.contains("team@example.com"),
            "tree should show external member"
        );
    }

    #[test]
    fn membership_label_defaults_to_member() {
        assert_eq!(membership_label(true, false), "member");
    }

    #[test]
    fn membership_label_noinherit() {
        assert_eq!(membership_label(false, false), "member, NOINHERIT");
    }

    #[test]
    fn membership_label_admin() {
        assert_eq!(membership_label(true, true), "member, ADMIN");
    }

    #[test]
    fn membership_label_both_flags() {
        assert_eq!(membership_label(false, true), "member, NOINHERIT, ADMIN");
    }

    #[test]
    fn empty_graph_produces_empty_visual() {
        let graph = RoleGraph::default();
        let visual = build_visual_graph(&graph, VisualSource::Current);
        assert!(visual.nodes.is_empty());
        assert!(visual.edges.is_empty());
        assert_eq!(visual.meta.role_count, 0);
    }

    #[test]
    fn grant_node_privileges_merge_across_roles() {
        // Two roles granting different privileges to the same schema.tables[*] target.
        let yaml = r#"
roles:
  - name: role-a
  - name: role-b

grants:
  - role: role-a
    privileges: [SELECT]
    on: { type: table, schema: app, name: "*" }
  - role: role-b
    privileges: [SELECT, INSERT, UPDATE]
    on: { type: table, schema: app, name: "*" }
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, None).unwrap();
        let visual = build_visual_graph(&graph, VisualSource::Desired);

        let grant_nodes: Vec<_> = visual
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::GrantTarget && n.label.contains("tables"))
            .collect();

        // Should be one collapsed node, not two.
        assert_eq!(grant_nodes.len(), 1, "grant nodes: {grant_nodes:?}");

        // The node's privileges should be the union of both roles' privileges.
        let privs = &grant_nodes[0].privileges;
        assert!(
            privs.contains(&"INSERT".to_string()),
            "missing INSERT in {privs:?}"
        );
        assert!(
            privs.contains(&"SELECT".to_string()),
            "missing SELECT in {privs:?}"
        );
        assert!(
            privs.contains(&"UPDATE".to_string()),
            "missing UPDATE in {privs:?}"
        );
    }

    #[test]
    fn mermaid_ids_do_not_collide_for_similar_names() {
        let id_at = mermaid_escape_id("role:alice@example.com");
        let id_dot = mermaid_escape_id("role:alice.example.com");
        let id_under = mermaid_escape_id("role:alice_example_com");
        assert_ne!(id_at, id_dot, "@ and . should produce different IDs");
        assert_ne!(id_at, id_under, "@ and _ should produce different IDs");
        assert_ne!(id_dot, id_under, ". and _ should produce different IDs");
    }
}
