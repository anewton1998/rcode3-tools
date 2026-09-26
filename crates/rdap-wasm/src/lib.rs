mod custom;

use icann_rdap_client::iana::MemoryBootstrapStore;
use icann_rdap_client::prelude::*;
use icann_rdap_client::rdap::ResponseData;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::*;

fn init_panic_hook() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}

async fn lookup(query: &str) -> Result<ResponseData, String> {
    let client = create_client(&ClientConfig::default()).map_err(|e| e.to_string())?;
    let store = MemoryBootstrapStore::new();
    let query_type = query
        .parse::<QueryType>()
        .map_err(|_| format!("invalid RDAP query: {query}"))?;
    rdap_bootstrapped_request(&query_type, &client, &store, |_| {})
        .await
        .map_err(|e| e.to_string())
}

/// Runs an RDAP lookup in the browser and resolves with the full parsed
/// response as a JS object.
#[wasm_bindgen]
pub async fn rdap_lookup(query: &str) -> Result<JsValue, JsValue> {
    init_panic_hook();
    let data = lookup(query).await.map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&data).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Runs an RDAP lookup and resolves with an HTML fragment rendered by the
/// custom client-side logic in `custom.rs`.
#[wasm_bindgen]
pub async fn rdap_lookup_html(query: &str) -> Result<String, JsValue> {
    init_panic_hook();
    let data = lookup(query).await.map_err(|e| JsValue::from_str(&e))?;
    Ok(custom::domain_summary_html(&data))
}
#[cfg(test)]
mod tests {
    use super::*;

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
}
