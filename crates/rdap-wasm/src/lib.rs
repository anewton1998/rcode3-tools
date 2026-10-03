mod custom;
mod qtypes;

use std::collections::HashSet;
use std::sync::Mutex;

use icann_rdap_client::prelude::*;
use qtypes::{query_type_from_code, query_type_groups};
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_client::rdap::redacted::simplify_redactions;
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

/// Runs an RDAP lookup and resolves with an HTML fragment rendered by the
/// custom client-side logic in `custom.rs`.
///
/// `query_type` selects the [`QueryType`] to build (see `queryTypeGroups`);
/// `None` (or `"auto"`) auto-detects from the query string.
#[wasm_bindgen]
pub async fn rdap_lookup_html(query: &str, query_type: Option<String>) -> Result<String, JsValue> {
    let data = lookup_typed(query_type.as_deref().unwrap_or("auto"), query)
        .await
        .map_err(|e| JsValue::from_str(&custom::describe_error(&e)))?;
    if data.http_data.status_code >= 400 {
        return Err(JsValue::from_str(&custom::http_error_message(&data)));
    }

    let mut html = custom::render_response_html(&data);
    for url in custom::referral_urls(&data) {
        html.push_str(&custom::referral_divider());
        match lookup_url(&url).await {
            Ok(referral) => html.push_str(&custom::render_response_html(&referral)),
            Err(e) => html.push_str(&custom::referral_error_note(&url, &e)),
        }
    }
    Ok(html)
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
}
