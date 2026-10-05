//! Box-drawing result tree rendered into the summary panel.
//!
//! Design notes:
//! - The tree is built from already-fetched `ResponseData` (no I/O here), so
//!   it can never disagree with the result HTML shown beside it.
//! - Rendering uses Unicode box-drawing connectors (`│ ├ └ ─`) inside a
//!   monospace block. There is no per-node collapse state, so a re-query
//!   simply swaps the whole rendered string.
//! - Recursion is bounded by `MAX_TREE_DEPTH` to keep the summary compact and
//!   to terminate safely on entity graphs that reference each other.
//! - `secureDNS`, `status`, `events` and `links` are response *metadata* and
//!   deliberately not tree nodes; they remain in the detail panel.

use icann_rdap_client::RdapClientError;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::prelude::{Entity, Nameserver, ObjectCommon, RdapResponse};

use super::common::entity_label;
use super::html::escape;

/// Depth cap for recursion into subordinate objects. The `depth` parameter
/// counts from the response node (the query root is depth 0, its responses
/// are depth 1); the `entities`/`nameservers` group node shares its parent
/// response's depth and its entity children start at `depth + 1`. With a cap
/// of 4 a domain's entity tree renders two tiers below the group (e.g.
/// registrar → reseller → abuse) before stopping, which keeps the summary
/// bounded and cycle-safe. See `depth_is_capped` for the tested shape.
const MAX_TREE_DEPTH: usize = 4;

/// One node of the summary result tree.
pub(crate) struct TreeNode {
    /// Short badge text, e.g. `domain`, `entities`, `referral`.
    pub kind: String,
    /// Primary text: the object's name/handle/url. Empty for group nodes.
    pub label: String,
    /// Secondary text rendered after a `·` separator (authority host,
    /// group count, error text).
    pub meta: Option<String>,
    /// When true the line is rendered with error styling (failed referral).
    pub failed: bool,
    pub children: Vec<TreeNode>,
}

/// The outcome of following one referral URL, kept so the tree can show
/// failed referrals exactly where the result panel notes them.
pub(crate) struct ReferralOutcome {
    pub url: String,
    pub result: Result<ResponseData, RdapClientError>,
}

fn node(kind: &str, label: String) -> TreeNode {
    TreeNode {
        kind: kind.to_string(),
        label,
        meta: None,
        failed: false,
        children: Vec::new(),
    }
}

fn handle_of(oc: &ObjectCommon) -> Option<String> {
    oc.handle.as_deref().map(|h| h.to_string())
}

/// Builds the full tree: query root → each response → subordinate objects.
pub(crate) fn build_tree(
    query: &str,
    main: &ResponseData,
    referrals: &[ReferralOutcome],
) -> TreeNode {
    let mut root = node("query", query.to_string());
    root.children.push(response_node(main, 1));
    for outcome in referrals {
        match &outcome.result {
            Ok(data) => root.children.push(response_node(data, 1)),
            Err(e) => {
                let mut failed = node("referral", outcome.url.clone());
                failed.failed = true;
                failed.meta = Some(super::describe_error(e));
                root.children.push(failed);
            }
        }
    }
    root
}

/// A response node: badge is the RDAP object class, meta the authority host.
/// The main response and each followed referral use this identically — the
/// first child of the root is the answer to the query, the rest are referrals.
fn response_node(data: &ResponseData, depth: usize) -> TreeNode {
    let mut n = match &data.rdap {
        RdapResponse::Domain(domain) => {
            let label = domain
                .ldh_name
                .clone()
                .or_else(|| handle_of(&domain.object_common))
                .unwrap_or_default();
            let mut n = node("domain", label);
            push_subordinates(
                &mut n,
                domain.object_common.entities.as_deref(),
                domain.nameservers.as_deref(),
                depth,
            );
            n
        }
        RdapResponse::Entity(entity) => entity_node(entity, depth),
        RdapResponse::Nameserver(ns) => {
            let label = ns
                .ldh_name
                .clone()
                .or_else(|| handle_of(&ns.object_common))
                .unwrap_or_default();
            node("nameserver", label)
        }
        RdapResponse::Network(network) => {
            let label = network
                .name
                .as_deref()
                .map(|s| s.to_string())
                .or_else(|| network.start_address.clone())
                .or_else(|| handle_of(&network.object_common))
                .unwrap_or_default();
            let mut n = node("network", label);
            if depth < MAX_TREE_DEPTH
                && let Some(entities) = &network.object_common.entities
            {
                let group = entities_group(entities, depth);
                if !group.children.is_empty() {
                    n.children.push(group);
                }
            }
            n
        }
        RdapResponse::Autnum(autnum) => {
            let label = autnum
                .start_autnum
                .as_ref()
                .map(|s| s.to_string())
                .or_else(|| handle_of(&autnum.object_common))
                .unwrap_or_default();
            node("autnum", label)
        }
        other => node(&data.rdap_type, other.to_string()),
    };
    // The authority host is the response's meta; a top-level entity node may
    // already carry its handle, so keep both rather than clobbering it.
    let host = data.http_data.host();
    n.meta = Some(match n.meta.take() {
        Some(handle) => format!("{handle} @ {host}"),
        None => host.to_string(),
    });
    n
}

/// Adds the `entities` and `nameservers` group nodes under a response.
fn push_subordinates(
    parent: &mut TreeNode,
    entities: Option<&[Entity]>,
    nameservers: Option<&[Nameserver]>,
    depth: usize,
) {
    if depth >= MAX_TREE_DEPTH {
        return;
    }
    if let Some(entities) = entities {
        let group = entities_group(entities, depth);
        if !group.children.is_empty() {
            parent.children.push(group);
        }
    }
    if let Some(nameservers) = nameservers
        && !nameservers.is_empty()
    {
        let mut group = node("nameservers", String::new());
        group.meta = Some(nameservers.len().to_string());
        for ns in nameservers {
            let label = ns
                .ldh_name
                .clone()
                .or_else(|| handle_of(&ns.object_common))
                .unwrap_or_default();
            group.children.push(node("nameserver", label));
        }
        parent.children.push(group);
    }
}

fn entities_group(entities: &[Entity], depth: usize) -> TreeNode {
    debug_assert!(
        depth < MAX_TREE_DEPTH,
        "entities_group must only be called within the depth cap"
    );
    let mut group = node("entities", String::new());
    group.meta = Some(entities.len().to_string());
    for entity in entities {
        group.children.push(entity_node(entity, depth + 1));
    }
    group
}

/// An entity node: label is its roles (else its handle), meta the handle
/// when the label came from roles. Nested entities become children.
fn entity_node(entity: &Entity, depth: usize) -> TreeNode {
    let label = entity_label(entity).unwrap_or_default();
    let meta = handle_of(&entity.object_common).filter(|h| *h != label);
    let mut n = node("entity", label);
    n.meta = meta;
    if depth < MAX_TREE_DEPTH
        && let Some(subs) = &entity.object_common.entities
    {
        for sub in subs {
            n.children.push(entity_node(sub, depth + 1));
        }
    }
    n
}

/// Renders the tree as a block of monospace box-drawing lines.
pub(crate) fn render_tree(root: &TreeNode) -> String {
    let mut out = String::new();
    render_node(root, "", true, true, &mut out);
    out
}

/// Wraps already-rendered tree lines in the collapsible "Result tree" block
/// that is embedded in the results panel beneath the host/received banner.
pub(crate) fn tree_block(lines: &str) -> String {
    format!(
        "<details class=\"tree_section\" open><summary class=\"tree_summary\">Result tree</summary>\
         <div class=\"tree_body\">{lines}</div></details>"
    )
}

fn render_node(node: &TreeNode, prefix: &str, is_last: bool, is_root: bool, out: &mut String) {
    // Connectors are our own literal box-drawing characters and are emitted
    // unescaped; every dynamic string goes through `escape`.
    let connector = if is_root {
        ""
    } else if is_last {
        "└─ "
    } else {
        "├─ "
    };
    let line_class = if node.failed {
        "tree_line tree_error"
    } else {
        "tree_line"
    };
    let label_part = if node.label.is_empty() {
        String::new()
    } else {
        format!(" <span class=\"tree_label\">{}</span>", escape(&node.label))
    };
    let meta_part = match &node.meta {
        Some(meta) => format!(" <span class=\"tree_meta\">· {}</span>", escape(meta)),
        None => String::new(),
    };
    out.push_str(&format!(
        "<div class=\"{line_class}\"><span class=\"tree_prefix\" aria-hidden=\"true\">{prefix}{connector}</span><span class=\"tree_kind\">{}</span>{label_part}{meta_part}</div>",
        escape(&node.kind)
    ));
    let child_prefix = if is_root {
        String::new()
    } else if is_last {
        format!("{prefix}   ")
    } else {
        format!("{prefix}│  ")
    };
    let count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        render_node(child, &child_prefix, i + 1 == count, false, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icann_rdap_common::httpdata::HttpData;

    fn http(host: &str) -> HttpData {
        HttpData::builder()
            .host(host.to_string())
            .status_code(200)
            .received(chrono::Utc::now())
            .build()
    }

    fn response(rdap_json: &str, rdap_type: &str, host: &str) -> ResponseData {
        let rdap: RdapResponse = serde_json::from_str(rdap_json).unwrap();
        ResponseData {
            rdap,
            rdap_type: rdap_type.to_string(),
            http_data: http(host),
        }
    }

    fn domain_fixture() -> ResponseData {
        response(
            r#"{
                "objectClassName": "domain",
                "handle": "EXAMPLE-COM",
                "ldhName": "example.com",
                "entities": [
                    {"objectClassName": "entity", "handle": "299", "roles": ["registrar"]},
                    {"objectClassName": "entity", "handle": "7018", "roles": ["technical"]}
                ],
                "nameservers": [
                    {"objectClassName": "nameserver", "ldhName": "ns1.example.com"},
                    {"objectClassName": "nameserver", "ldhName": "ns2.example.com"}
                ]
            }"#,
            "domain",
            "rdap.example",
        )
    }

    #[test]
    fn tree_renders_query_root_and_response() {
        let data = domain_fixture();
        let tree = build_tree("example.com", &data, &[]);
        let html = render_tree(&tree);
        assert!(html.contains(">query<"), "{html}");
        assert!(html.contains(">example.com<"), "{html}");
        assert!(html.contains(">domain<"), "{html}");
        assert!(html.contains("rdap.example"), "{html}");
    }

    #[test]
    fn tree_groups_entities_and_nameservers_with_counts() {
        let data = domain_fixture();
        let html = render_tree(&build_tree("example.com", &data, &[]));
        assert!(html.contains(">entities<"), "{html}");
        assert!(html.contains(">nameservers<"), "{html}");
        assert!(html.contains("· 2"), "{html}");
        assert!(html.contains("ns1.example.com"), "{html}");
        assert!(html.contains("registrar"), "{html}");
    }

    #[test]
    fn connectors_follow_box_drawing_grammar() {
        let data = domain_fixture();
        let html = render_tree(&build_tree("example.com", &data, &[]));
        // Middle children use ├─, the last uses └─, continuation uses │.
        assert!(html.contains("├─ "), "{html}");
        assert!(html.contains("└─ "), "{html}");
        assert!(html.contains("│  "), "{html}");
        // The root line carries no connector.
        let root_line = html.split("<div").nth(1).unwrap_or("");
        assert!(
            !root_line.contains("├─") && !root_line.contains("└─"),
            "{root_line}"
        );
    }

    #[test]
    fn failed_referral_renders_error_leaf() {
        let data = domain_fixture();
        let outcome = ReferralOutcome {
            url: "https://rdap.example/entity/299".to_string(),
            result: Err(RdapClientError::InvalidQueryValue),
        };
        let html = render_tree(&build_tree("example.com", &data, &[outcome]));
        assert!(html.contains("tree_error"), "{html}");
        assert!(html.contains("rdap.example/entity/299"), "{html}");
        // describe_error falls through to the thiserror Display text.
        assert!(html.contains("Query value is not valid"), "{html}");
    }

    #[test]
    fn depth_is_capped() {
        // GIVEN an entity chain deeper than MAX_TREE_DEPTH
        let deep = r#"{
            "objectClassName": "domain",
            "ldhName": "deep.test",
            "entities": [{
                "objectClassName": "entity", "handle": "L1", "roles": ["registrar"],
                "entities": [{
                    "objectClassName": "entity", "handle": "L2", "roles": ["reseller"],
                    "entities": [{
                        "objectClassName": "entity", "handle": "L3", "roles": ["abuse"],
                        "entities": [{
                            "objectClassName": "entity", "handle": "L4", "roles": ["cutoff"]
                        }]
                    }]
                }]
            }]
        }"#;
        let data = response(deep, "domain", "rdap.example");
        let html = render_tree(&build_tree("deep.test", &data, &[]));
        // L1..L3 render; L4 is beyond the cap and must not appear.
        assert!(html.contains("registrar"), "{html}");
        assert!(html.contains("reseller"), "{html}");
        assert!(html.contains("abuse"), "{html}");
        assert!(!html.contains("cutoff"), "depth cap breached: {html}");
    }

    #[test]
    fn labels_are_escaped() {
        let evil = r#"{
            "objectClassName": "domain",
            "ldhName": "<script>alert(1)</script>",
            "nameservers": [{"objectClassName": "nameserver", "ldhName": "<img src=x>"}]
        }"#;
        let data = response(evil, "domain", "rdap.example");
        let html = render_tree(&build_tree("<b>q</b>", &data, &[]));
        assert!(!html.contains("<script>"), "unescaped script tag: {html}");
        assert!(!html.contains("<img"), "unescaped img tag: {html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }

    #[test]
    fn top_level_entity_keeps_handle_alongside_host() {
        // GIVEN a query whose response is itself an entity
        let entity_json = r#"{
            "objectClassName": "entity",
            "handle": "299",
            "roles": ["registrar"]
        }"#;
        let data = response(entity_json, "entity", "rdap.example");
        let html = render_tree(&build_tree("299", &data, &[]));
        // THEN the node shows both its handle and the authority host.
        assert!(html.contains("299 @ rdap.example"), "{html}");
        assert!(html.contains("registrar"), "{html}");
    }

    #[test]
    fn empty_nameservers_omits_the_group() {
        // GIVEN a domain whose nameservers array is empty
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "bare.test",
            "nameservers": []
        }"#;
        let data = response(json, "domain", "rdap.example");
        let html = render_tree(&build_tree("bare.test", &data, &[]));
        // THEN no nameservers group node is rendered.
        assert!(!html.contains(">nameservers<"), "{html}");
    }

    #[test]
    fn unsupported_class_falls_back_to_rdap_type() {
        // GIVEN a response the tree has no dedicated node for (an error doc)
        let json = r#"{ "errorCode": 404, "title": "Not Found" }"#;
        let data = response(json, "error", "rdap.example");
        let html = render_tree(&build_tree("nope", &data, &[]));
        // THEN it still renders a node tagged with the rdap_type and host.
        assert!(html.contains(">error<"), "{html}");
        assert!(html.contains("rdap.example"), "{html}");
    }
}
