mod custom;

use std::collections::HashSet;
use std::sync::Mutex;

use icann_rdap_client::prelude::*;
use icann_rdap_client::rdap::ResponseData;
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

async fn lookup(query: &str) -> Result<ResponseData, String> {
    let config = ClientConfig::builder().exts_list(HashSet::new()).build();
    let client = create_client(&config).map_err(|e| e.to_string())?;
    let query_type = query
        .parse::<QueryType>()
        .map_err(|_| format!("invalid RDAP query: {query}"))?;
    let base_url = current_bootstrap_url();
    rdap_request(&base_url, &query_type, &client)
        .await
        .map_err(|e| e.to_string())
}

/// Runs an RDAP lookup in the browser and resolves with the full parsed
/// response as a JS object.
#[wasm_bindgen]
pub async fn rdap_lookup(query: &str) -> Result<JsValue, JsValue> {
    let data = lookup(query).await.map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&data).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Runs an RDAP lookup and resolves with an HTML fragment rendered by the
/// custom client-side logic in `custom.rs`.
#[wasm_bindgen]
pub async fn rdap_lookup_html(query: &str) -> Result<String, JsValue> {
    let data = lookup(query).await.map_err(|e| JsValue::from_str(&e))?;
    Ok(custom::domain_summary_html(&data))
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
        println!("{}", custom::domain_summary_html(&data));
    }

    #[tokio::test]
    async fn native_lookup_ip() {
        let data = lookup("192.0.2.8").await.expect("ip lookup");
        println!("native ip ok: {}", data.rdap_type);
    }

    #[tokio::test]
    async fn domain_summary_renders_table() {
        let data = lookup("example.com").await.expect("domain lookup");
        let html = custom::domain_summary_html(&data);
        assert!(
            html.contains("<table class=\"data_table\">"),
            "expected an rdap table, got: {html}"
        );
        assert!(
            html.contains("<th scope=\"row\">Name</th>"),
            "missing Name row: {html}"
        );
    }
}
