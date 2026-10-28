mod custom;
mod qtypes;

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Mutex;

use icann_rdap_client::http::default_exts_list;
use icann_rdap_client::prelude::*;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_client::rdap::redacted::simplify_redactions;
use icann_rdap_client::rpsl::{RpslParams, ToRpsl};
use icann_rdap_common::httpdata::HttpData;
use icann_rdap_common::prelude::ExtensionId;
use qtypes::{query_type_from_code, query_type_groups};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::*;

pub const DEFAULT_BOOTSTRAP_URL: &str = "https://bootstrap.rcode3.com/rdap";

static BOOTSTRAP_URL: Mutex<Option<String>> = Mutex::new(None);

/// The `exts_list` extension-id set used in the RDAP media type.
/// `None` (the initial state) resolves to the library's default extension-id
/// set. An explicit empty set (via the `__none` sentinel) makes
/// `icann-rdap-client` omit the `exts_list` media-type parameter entirely.
static EXTS_LIST: Mutex<Option<HashSet<ExtensionId>>> = Mutex::new(None);

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

fn current_exts_list() -> HashSet<ExtensionId> {
    EXTS_LIST
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(default_exts_list)
}

/// Parses an exts-list spec into a set of RDAP extension ids.
///
/// - `__none` -> empty set (client omits the `exts_list` media-type parameter)
/// - `""` or `default` -> the library's default extension-id set
/// - otherwise -> comma- and/or space-separated IANA extension ids, e.g. `cidr0 jscontact`
fn parse_exts_list(spec: &str) -> Result<HashSet<ExtensionId>, String> {
    let s = spec.trim();
    if s == "__none" {
        return Ok(HashSet::new());
    }
    if s.is_empty() || s.eq_ignore_ascii_case("default") {
        return Ok(default_exts_list());
    }
    let mut set = HashSet::new();
    for token in s.split([',', ' ']).map(str::trim).filter(|t| !t.is_empty()) {
        let id = ExtensionId::from_str(token)
            .map_err(|_| format!("unknown RDAP extension id: {token}"))?;
        set.insert(id);
    }
    Ok(set)
}

/// Sets the RDAP `exts_list` (see [`parse_exts_list`] for accepted values).
#[wasm_bindgen(js_name = setExtsList)]
pub fn set_exts_list(spec: &str) -> Result<(), String> {
    let set = parse_exts_list(spec)?;
    *EXTS_LIST.lock().expect("exts list lock poisoned") = Some(set);
    Ok(())
}

/// Returns the currently configured extension ids (sorted IANA names).
#[wasm_bindgen(js_name = getExtsList)]
pub fn get_exts_list() -> Vec<String> {
    let mut ids: Vec<String> = current_exts_list().iter().map(|e| e.to_string()).collect();
    ids.sort();
    ids
}

async fn lookup_typed(code: &str, value: &str) -> Result<ResponseData, RdapClientError> {
    let config = ClientConfig::builder()
        .exts_list(current_exts_list())
        .build();
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
pub async fn rdap_explorer(query: &str, query_type: Option<String>) -> Result<JsValue, JsValue> {
    let data = lookup_typed(query_type.as_deref().unwrap_or("auto"), query)
        .await
        .map_err(|e| JsValue::from_str(&custom::describe_error(&e)))?;
    serde_wasm_bindgen::to_value(&data).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// The failure modes of a main-response fetch, distinguished so the result
/// panel can render a "no information" message for a non-RDAP body while
/// still throwing for genuine transport errors.
#[derive(Debug)]
enum FetchError {
    /// The server responded (we have HTTP data) but the body was not a
    /// parseable RDAP response — there is nothing to render but the status.
    NoInformation(Box<HttpData>),
    /// A transport-level error with no usable HTTP response.
    Transport(RdapClientError),
}

/// Fetches the main response and follows its related referrals, collecting
/// each outcome so the result HTML and the summary tree are built from the
/// exact same data — one fetch, no possible disagreement between them.
///
/// A non-200 status is *not* an error here: an error response is rendered in
/// the result panel by the caller. Only a body that fails to parse as RDAP
/// (`NoInformation`) or a transport failure short-circuits.
async fn fetch_with_referrals(
    code: &str,
    value: &str,
) -> Result<(ResponseData, Vec<custom::ReferralOutcome>), FetchError> {
    let data = lookup_typed(code, value).await.map_err(|e| match e {
        RdapClientError::ParsingError(info) => FetchError::NoInformation(Box::new(info.http_data)),
        other => FetchError::Transport(other),
    })?;
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
/// This path has no result tree, so it renders without in-page anchor ids.
fn render_result_html(data: &ResponseData, referrals: &[custom::ReferralOutcome]) -> String {
    let mut html = custom::render_response_html(data, "");
    for outcome in referrals {
        html.push_str(&custom::referral_divider());
        match &outcome.result {
            Ok(referral) => html.push_str(&custom::render_response_html(referral, "")),
            Err(e) => html.push_str(&custom::referral_error_note(&outcome.url, e)),
        }
    }
    html
}

/// Runs an RDAP lookup and resolves with an HTML fragment rendered by the
/// custom client-side logic in `custom.rs`.
///
/// Error responses (non-200 with an RDAP error body) and "no information"
/// responses render into the returned HTML; only a transport failure throws.
///
/// `query_type` selects the [`QueryType`] to build (see `queryTypeGroups`);
/// `None` (or `"auto"`) auto-detects from the query string.
#[wasm_bindgen]
pub async fn rdap_explorer_html(
    query: &str,
    query_type: Option<String>,
) -> Result<String, JsValue> {
    let code = query_type.as_deref().unwrap_or("auto");
    match fetch_with_referrals(code, query).await {
        Ok((data, referrals)) => Ok(render_result_html(&data, &referrals)),
        Err(FetchError::NoInformation(http)) => Ok(format!(
            "{}{}",
            custom::banner_from_http(&http),
            custom::no_information_html(http.status_code)
        )),
        Err(FetchError::Transport(e)) => Err(JsValue::from_str(&custom::describe_error(&e))),
    }
}

/// Builds the downloadable RPSL text for a lookup: the main response plus
/// every successfully-followed referral, concatenated. Each `to_rpsl`
/// carries its own `# Query / Received / From` header, so the concatenation
/// reads as a sequence of self-describing objects. Failed referrals are
/// skipped (there is no body to render).
fn build_rpsl(data: &ResponseData, referrals: &[custom::ReferralOutcome]) -> String {
    let mut rpsl = data.rdap.to_rpsl(RpslParams {
        http_data: &data.http_data,
    });
    for outcome in referrals {
        if let Ok(referral) = &outcome.result {
            rpsl.push_str(&referral.rdap.to_rpsl(RpslParams {
                http_data: &referral.http_data,
            }));
        }
    }
    rpsl
}

/// Builds the downloadable JSON for a lookup.
///
/// A single result (no followed referrals) serializes as one RDAP object;
/// two or more results (e.g. a domain query that followed a `related`
/// link) serialize as a JSON array `[main, referral, …]`, matching how the
/// result panel stacks them. Failed referrals are excluded.
fn build_json(
    data: &ResponseData,
    referrals: &[custom::ReferralOutcome],
) -> Result<String, serde_json::Error> {
    let ok: Vec<&ResponseData> = referrals
        .iter()
        .filter_map(|o| o.result.as_ref().ok())
        .collect();
    if ok.is_empty() {
        return serde_json::to_string_pretty(&data.rdap);
    }
    let mut arr = Vec::with_capacity(ok.len() + 1);
    arr.push(&data.rdap);
    for referral in &ok {
        arr.push(&referral.rdap);
    }
    serde_json::to_string_pretty(&arr)
}

/// The payload returned by [`rdap_explorer_with_tree`].
#[derive(serde::Serialize)]
struct LookupResult {
    html: String,
    tree: String,
    /// A short human-readable error for the red line in the input panel and
    /// the history entry; empty for a normal (200) response.
    error: String,
    /// Downloadable RPSL text (main response + followed referrals).
    rpsl: String,
    /// Downloadable JSON: a single RDAP object, or an array when the query
    /// produced multiple results.
    json: String,
}

/// Runs an RDAP lookup and resolves with `{ html, tree, error }`. The `html`
/// is the result-panel fragment with the collapsible box-drawing result tree
/// embedded directly beneath the host/received banner and above the response
/// body; the `tree` field carries the same tree lines on their own; the
/// `error` field is a short message for the red line / history when the
/// response is an error (empty otherwise). Everything derives from a single
/// fetch, so the tree can never disagree with the rendered body.
///
/// A non-200 with an RDAP error body renders in `html` (with `error` set);
/// a non-200 with no parseable RDAP body renders a "no information" panel;
/// only a transport failure throws.
#[wasm_bindgen(js_name = rdapExplorerWithTree)]
pub async fn rdap_explorer_with_tree(
    query: &str,
    query_type: Option<String>,
) -> Result<JsValue, JsValue> {
    let code = query_type.as_deref().unwrap_or("auto");
    let result = match fetch_with_referrals(code, query).await {
        Ok((data, referrals)) => {
            let tree_node = custom::build_tree(query, &data, &referrals);
            let tree = custom::render_tree(&tree_node);
            // Result-panel order: host/received banner → result tree →
            // response body → followed referrals (each with its own banner).
            // The body anchors match the tree's response anchors so the
            // tree's in-page links resolve to the rendered data.
            let mut html = custom::banner_with_formats(&data.http_data);
            html.push_str(&custom::tree_block(&tree));
            html.push_str(&custom::render_response_body(
                &data,
                &custom::response_anchor(0),
            ));
            for (i, outcome) in referrals.iter().enumerate() {
                html.push_str(&custom::referral_divider());
                match &outcome.result {
                    Ok(referral) => html.push_str(&custom::render_response_html(
                        referral,
                        &custom::response_anchor(i + 1),
                    )),
                    Err(e) => html.push_str(&custom::referral_error_note(&outcome.url, e)),
                }
            }
            let error = if data.http_data.status_code >= 400 {
                custom::http_error_message(&data)
            } else {
                String::new()
            };
            let rpsl = build_rpsl(&data, &referrals);
            let json = build_json(&data, &referrals).unwrap_or_default();
            LookupResult {
                html,
                tree,
                error,
                rpsl,
                json,
            }
        }
        Err(FetchError::NoInformation(http)) => {
            let status = http.status_code;
            let html = format!(
                "{}{}",
                custom::banner_from_http(&http),
                custom::no_information_html(status)
            );
            LookupResult {
                html,
                tree: String::new(),
                error: format!("No information returned (HTTP {status})"),
                rpsl: String::new(),
                json: String::new(),
            }
        }
        Err(FetchError::Transport(e)) => {
            return Err(JsValue::from_str(&custom::describe_error(&e)));
        }
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_url_normalization() {
        assert_eq!(
            normalize_base_url("https://bootstrap.rcode3.com/rdap"),
            "https://bootstrap.rcode3.com/rdap"
        );
        assert_eq!(
            normalize_base_url("https://bootstrap.rcode3.com/rdap/"),
            "https://bootstrap.rcode3.com/rdap"
        );
        assert_eq!(
            normalize_base_url("  https://example.com/rdap//  "),
            "https://example.com/rdap"
        );
    }

    #[test]
    fn default_bootstrap_url() {
        assert_eq!(current_bootstrap_url(), DEFAULT_BOOTSTRAP_URL);
    }

    #[test]
    fn exts_list_none_sentinel_is_empty() {
        assert!(parse_exts_list("__none").unwrap().is_empty());
    }

    #[test]
    fn exts_list_default_variants() {
        // Unset-equivalent (empty/whitespace) and explicit "default" both use the library default.
        for spec in ["", "   ", "default", "DEFAULT", "Default"] {
            assert_eq!(
                parse_exts_list(spec).unwrap(),
                default_exts_list(),
                "expected library default for {spec:?}"
            );
        }
    }

    #[test]
    fn exts_list_explicit_ids() {
        let comma = parse_exts_list("cidr0,jscontact").unwrap();
        assert_eq!(comma.len(), 2);
        assert!(comma.contains(&ExtensionId::Cidr0));
        assert!(comma.contains(&ExtensionId::JsContact));

        let spaced = parse_exts_list("cidr0 redacted  ttl0").unwrap();
        assert_eq!(spaced.len(), 3);
        assert!(spaced.contains(&ExtensionId::Redacted));
        assert!(spaced.contains(&ExtensionId::Ttl0));
    }

    #[test]
    fn exts_list_unknown_id_errors() {
        assert!(parse_exts_list("cidr0,notanextension").is_err());
    }

    #[tokio::test]
    async fn native_lookup_domain() {
        let data = lookup("example.com").await.expect("domain lookup");
        println!("native domain ok: {}", data.rdap_type);
        println!("{}", custom::render_response_html(&data, ""));
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
        let (data, referrals) = fetch_with_referrals("auto", "icann.org")
            .await
            .expect("lookup html");
        let html = render_result_html(&data, &referrals);
        assert!(
            html.contains("data_divider"),
            "expected a referral divider between results: {html}"
        );
    }

    #[tokio::test]
    async fn domain_summary_renders_table() {
        let data = lookup("example.com").await.expect("domain lookup");
        let html = custom::render_response_html(&data, "");
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
        let body = custom::render_response_body(&data, "");
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

    fn fmt_response(json: &str, rdap_type: &str, host: &str) -> ResponseData {
        let rdap: icann_rdap_common::prelude::RdapResponse = serde_json::from_str(json).unwrap();
        let http_data = HttpData::builder()
            .host(host.to_string())
            .status_code(200)
            .received(chrono::Utc::now())
            .build();
        ResponseData {
            rdap,
            rdap_type: rdap_type.to_string(),
            http_data,
        }
    }

    fn ok_outcome(json: &str, rdap_type: &str, host: &str) -> custom::ReferralOutcome {
        custom::ReferralOutcome {
            url: format!("https://{host}/rdap/domain/x"),
            result: Ok(fmt_response(json, rdap_type, host)),
        }
    }

    #[test]
    fn build_json_single_result_is_an_object() {
        // GIVEN a lookup with no followed referrals
        let data = fmt_response(
            r#"{"objectClassName":"domain","ldhName":"example.com"}"#,
            "domain",
            "rdap.example",
        );
        // WHEN the download JSON is built
        let json = build_json(&data, &[]).expect("json");
        // THEN it is a single RDAP object, not an array.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(v.is_object(), "{json}");
        assert_eq!(v["ldhName"], "example.com");
    }

    #[test]
    fn build_json_with_referral_is_an_array() {
        // GIVEN a main response plus one successfully-followed referral
        let data = fmt_response(
            r#"{"objectClassName":"domain","ldhName":"example.com"}"#,
            "domain",
            "rdap.example",
        );
        let referrals = vec![ok_outcome(
            r#"{"objectClassName":"domain","ldhName":"related.example"}"#,
            "domain",
            "other.example",
        )];
        // WHEN the download JSON is built
        let json = build_json(&data, &referrals).expect("json");
        // THEN it is an array of [main, referral] in order.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let arr = v.as_array().expect("expected a JSON array");
        assert_eq!(arr.len(), 2, "{json}");
        assert_eq!(arr[0]["ldhName"], "example.com");
        assert_eq!(arr[1]["ldhName"], "related.example");
    }

    #[test]
    fn build_json_skips_failed_referrals() {
        // GIVEN a referral that failed to load
        let data = fmt_response(
            r#"{"objectClassName":"domain","ldhName":"example.com"}"#,
            "domain",
            "rdap.example",
        );
        let referrals = vec![custom::ReferralOutcome {
            url: "https://broken.example/x".to_string(),
            result: Err(RdapClientError::InvalidQueryValue),
        }];
        // WHEN the download JSON is built
        let json = build_json(&data, &referrals).expect("json");
        // THEN the failed referral is excluded: still a single object.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(v.is_object(), "{json}");
    }

    #[test]
    fn build_rpsl_concatenates_main_and_referrals() {
        // GIVEN a main domain and one followed referral domain
        let data = fmt_response(
            r#"{"objectClassName":"domain","ldhName":"example.com"}"#,
            "domain",
            "rdap.example",
        );
        let referrals = vec![ok_outcome(
            r#"{"objectClassName":"domain","ldhName":"related.example"}"#,
            "domain",
            "other.example",
        )];
        // WHEN the RPSL text is built
        let rpsl = build_rpsl(&data, &referrals);
        // THEN both objects appear, each with its own `domain:` key.
        assert!(rpsl.contains("example.com"), "{rpsl}");
        assert!(rpsl.contains("related.example"), "{rpsl}");
        assert_eq!(rpsl.matches("domain:").count(), 2, "{rpsl}");
    }
}
