mod custom;
mod qtypes;

use std::collections::HashSet;
use std::sync::Mutex;

use icann_rdap_client::prelude::*;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_client::rdap::redacted::simplify_redactions;
use qtypes::{query_type_from_code, query_type_groups};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::*;

pub const DEFAULT_BOOTSTRAP_URL: &str = "https://rdap.org";

static BOOTSTRAP_URL: Mutex<Option<String>> = Mutex::new(None);

fn normalize_base_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn current_bootstrap_url() -> String {
    BOOTSTRAP_URL
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| DEFAULT_BOOTSTRAP_URL.to_string())
}

/// Sets the RDAP bootstrap URL (the redirector used for all lookups).
#[wasm_bindgen]
pub fn set_bootstrap_url(url: &str) {
    let mut guard = BOOTSTRAP_URL.lock().expect("bootstrap url lock poisoned");
    *guard = Some(normalize_base_url(url));
}

/// Returns the currently configured bootstrap URL.
#[wasm_bindgen(js_name = getBootstrapUrl)]
pub fn get_bootstrap_url() -> String {
    current_bootstrap_url()
}

async fn lookup_typed(code: &str, value: &str) -> Result<ResponseData, RdapClientError> {
    let config = ClientConfig::builder().exts_list(HashSet::new()).build();
    let client = create_client(&config)?;
    let query_type = query_type_from_code(code, value)?;
    let base_url = current_bootstrap_url();
    rdap_request(&base_url, &query_type, &client)
        .await
        .map(|res| ResponseData {
            rdap: simplify_redactions(res.rdap, false),
            ..res
        })
}

/// Auto-detecting lookup (preserves the original `parse::<QueryType>()` behavior).
#[allow(dead_code)]
async fn lookup(query: &str) -> Result<ResponseData, RdapClientError> {
    lookup_typed("auto", query).await
}

async fn lookup_url(url: &str) -> Result<ResponseData, RdapClientError> {
    let config = ClientConfig::builder().exts_list(HashSet::new()).build();
    let client = create_client(&config)?;
    rdap_url_request(url, &client)
        .await
        .map(|res| ResponseData {
            rdap: simplify_redactions(res.rdap, false),
            ..res
        })
}

/// Returns the grouped query-type options for the dropdown UI.
///
/// Resolves to an array of `{ label, options: [{ code, label }] }`.
#[wasm_bindgen(js_name = queryTypeGroups)]
pub fn query_type_groups_export() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&query_type_groups())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Runs an RDAP lookup in the browser and resolves with the full parsed
/// response as a JS object.
///
/// `query_type` selects the [`QueryType`] to build (see `queryTypeGroups`);
/// `None` (or `"auto"`) auto-detects from the query string.
#[wasm_bindgen]
pub async fn rdap_lookup(query: &str, query_type: Option<String>) -> Result<JsValue, JsValue> {
    let data = lookup_typed(query_type.as_deref().unwrap_or("auto"), query)
        .await
        .map_err(|e| JsValue::from_str(&custom::describe_error(&e)))?;
    serde_wasm_bindgen::to_value(&data).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Fetches the main response and follows its related referrals, collecting
/// each outcome so the result HTML and the summary tree are built from the
/// exact same data — one fetch, no possible disagreement between them.
async fn fetch_with_referrals(
    code: &str,
    value: &str,
) -> Result<(ResponseData, Vec<custom::ReferralOutcome>), JsValue> {
    let data = lookup_typed(code, value)
        .await
        .map_err(|e| JsValue::from_str(&custom::describe_error(&e)))?;
    if data.http_data.status_code >= 400 {
        return Err(JsValue::from_str(&custom::http_error_message(&data)));
    }
    let mut referrals = Vec::new();
    for url in custom::referral_urls(&data) {
        referrals.push(custom::ReferralOutcome {
            url: url.clone(),
            result: lookup_url(&url).await,
        });
    }
    Ok((data, referrals))
}

/// Renders the concatenated result HTML (main response + referrals).
fn render_result_html(data: &ResponseData, referrals: &[custom::ReferralOutcome]) -> String {
    let mut html = custom::render_response_html(data);
    for outcome in referrals {
        html.push_str(&custom::referral_divider());
        match &outcome.result {
            Ok(referral) => html.push_str(&custom::render_response_html(referral)),
            Err(e) => html.push_str(&custom::referral_error_note(&outcome.url, e)),
        }
    }
    html
}

/// Runs an RDAP lookup and resolves with an HTML fragment rendered by the
/// custom client-side logic in `custom.rs`.
///
/// `query_type` selects the [`QueryType`] to build (see `queryTypeGroups`);
/// `None` (or `"auto"`) auto-detects from the query string.
#[wasm_bindgen]
pub async fn rdap_lookup_html(query: &str, query_type: Option<String>) -> Result<String, JsValue> {
    let (data, referrals) =
        fetch_with_referrals(query_type.as_deref().unwrap_or("auto"), query).await?;
    Ok(render_result_html(&data, &referrals))
}

/// The payload returned by [`rdap_lookup_with_tree`].
#[derive(serde::Serialize)]
struct LookupResult {
    html: String,
    tree: String,
}

/// Runs an RDAP lookup and resolves with `{ html, tree }`. The `html` is the
/// result-panel fragment with the collapsible box-drawing result tree embedded
/// directly beneath the host/received banner and above the response body; the
/// `tree` field carries the same tree lines on their own. Everything derives
/// from a single fetch, so the tree can never disagree with the rendered body.
#[wasm_bindgen(js_name = rdapLookupWithTree)]
pub async fn rdap_lookup_with_tree(
    query: &str,
    query_type: Option<String>,
) -> Result<JsValue, JsValue> {
    let (data, referrals) =
        fetch_with_referrals(query_type.as_deref().unwrap_or("auto"), query).await?;
    let tree_node = custom::build_tree(query, &data, &referrals);
    let tree = custom::render_tree(&tree_node);
    // Result-panel order: host/received banner → result tree → response body
    // → followed referrals (each with its own banner).
    let mut html = custom::render_response_banner(&data);
    html.push_str(&custom::tree_block(&tree));
    html.push_str(&custom::render_response_body(&data));
    for outcome in &referrals {
        html.push_str(&custom::referral_divider());
        match &outcome.result {
            Ok(referral) => html.push_str(&custom::render_response_html(referral)),
            Err(e) => html.push_str(&custom::referral_error_note(&outcome.url, e)),
        }
    }
    serde_wasm_bindgen::to_value(&LookupResult { html, tree })
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_url_normalization() {
        assert_eq!(normalize_base_url("https://rdap.org"), "https://rdap.org");
        assert_eq!(normalize_base_url("https://rdap.org/"), "https://rdap.org");
        assert_eq!(
            normalize_base_url("  https://example.com/rdap//  "),
            "https://example.com/rdap"
        );
    }

    #[test]
    fn default_bootstrap_url() {
        assert_eq!(current_bootstrap_url(), DEFAULT_BOOTSTRAP_URL);
    }

    #[tokio::test]
    async fn native_lookup_domain() {
        let data = lookup("example.com").await.expect("domain lookup");
        println!("native domain ok: {}", data.rdap_type);
        println!("{}", custom::render_response_html(&data));
    }

    #[tokio::test]
    async fn native_lookup_ip() {
        let data = lookup("192.0.2.8").await.expect("ip lookup");
        println!("native ip ok: {}", data.rdap_type);
    }

    #[tokio::test]
    async fn native_domain_related_referral_is_followed() {
        let data = lookup("icann.org").await.expect("domain lookup");
        let urls = custom::referral_urls(&data);
        assert!(
            !urls.is_empty(),
            "expected at least one related referral link for icann.org"
        );
    }

    #[tokio::test]
    async fn native_domain_lookup_html_includes_referral_divider() {
        let html = rdap_lookup_html("icann.org", None)
            .await
            .expect("lookup html");
        assert!(
            html.contains("data_divider"),
            "expected a referral divider between results: {html}"
        );
    }

    #[tokio::test]
    async fn domain_summary_renders_table() {
        let data = lookup("example.com").await.expect("domain lookup");
        let html = custom::render_response_html(&data);
        assert!(
            html.contains("<table class=\"data_table\">"),
            "expected an rdap table, got: {html}"
        );
        assert!(
            html.contains("<td class=\"data_key\">Name</td>"),
            "missing Name row: {html}"
        );
    }

    #[tokio::test]
    async fn tree_embeds_between_banner_and_body() {
        // GIVEN the pieces the result panel composes
        let data = lookup("example.com").await.expect("domain lookup");
        let tree = custom::render_tree(&custom::build_tree("example.com", &data, &[]));
        let banner = custom::render_response_banner(&data);
        let block = custom::tree_block(&tree);
        let body = custom::render_response_body(&data);
        // WHEN assembled in the export's order
        let html = format!("{banner}{block}{body}");
        // THEN the tree sits after the host/received banner and before the body.
        let host = html.find("Received").expect("banner received row");
        let tree_at = html.find("Result tree").expect("tree block");
        let body_at = html.find("data_title").expect("response body title");
        assert!(host < tree_at, "tree must come after the banner: {html}");
        assert!(tree_at < body_at, "tree must come before the body: {html}");
    }

    #[tokio::test]
    async fn native_tree_from_real_data() {
        // GIVEN a real fetched domain response
        let data = lookup("example.com").await.expect("domain lookup");
        // WHEN the summary tree is built and rendered over it
        let tree = custom::render_tree(&custom::build_tree("example.com", &data, &[]));
        // THEN it shows the query root, the domain response, and box-drawing
        // connectors, with subordinate groups where the registry provides them.
        assert!(tree.contains(">query<"), "{tree}");
        assert!(tree.contains(">domain<"), "{tree}");
        assert!(tree.contains("example.com"), "{tree}");
        assert!(tree.contains("├─ ") || tree.contains("└─ "), "{tree}");
        // example.com carries a registrar entity and nameservers in practice.
        assert!(
            tree.contains("entities") || tree.contains("nameservers"),
            "{tree}"
        );
    }
}
