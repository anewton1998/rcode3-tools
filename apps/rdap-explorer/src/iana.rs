//! Runtime ingestion of the IANA RDAP object-tags registry.
//!
//! The set of registered RDAP service providers is published by IANA at
//! <https://data.iana.org/rdap/object-tags.json>. Rather than baking these
//! servers into the binary, the explorer fetches the document at runtime and
//! keeps it in a shared, refreshable cache so the base-URL dropdown can offer
//! an "IANA Registered" group with no compile-time dependency.
//!
//! Design notes:
//! - The cache is an `Arc<RwLock<Vec<IanaServer>>>`: page renders take a
//!   short read lock; the background refresher takes the write lock only when
//!   a fetch succeeds. A failed fetch leaves the last-good list in place, so
//!   the dropdown never empties after the first successful load.
//! - The refresher is spawned at startup and never blocks serving. If the
//!   very first fetch fails the list simply starts empty and the group is
//!   omitted (see `iana_display_options`) until a later refresh lands.
//! - The document is fetched as text and parsed with `serde_json` directly
//!   rather than `reqwest::Response::json`, because the workspace `reqwest`
//!   is built without the `json` feature.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::normalize_bootstrap;

/// The IANA object-tags registry document.
pub const IANA_OBJECT_TAGS_URL: &str = "https://data.iana.org/rdap/object-tags.json";

/// Default refresh interval (24h), matching the `max-age` IANA publishes.
const DEFAULT_REFRESH_SECS: u64 = 86_400;

/// Floor for the refresh interval, so a misconfigured env value can't make
/// the refresher hammer IANA (which publishes at most daily).
const MIN_REFRESH_SECS: u64 = 60;

/// Shorter delay used to retry after a failed fetch (startup or refresh), so
/// a transient IANA outage recovers well before the normal daily cadence.
const RETRY_SECS: u64 = 60;

/// Default budget for the startup (warm-up) fetch before the server starts
/// serving. Env-overridable via `IANA_STARTUP_TIMEOUT_SECS`.
const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 10;

/// Floor for the startup timeout, so a `0`/tiny value can't make the gate
/// useless (it would never let the fetch land before serving).
const MIN_STARTUP_TIMEOUT_SECS: u64 = 1;

/// A single registered RDAP service provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IanaServer {
    /// The object tag (human-readable name), e.g. `"ARIN"`.
    pub tag: String,
    /// The RDAP base URL, e.g. `https://rdap.arin.net/registry/`.
    pub url: String,
    /// The normalized URL (`normalize_bootstrap(url)`), precomputed at parse
    /// time so cross-group dedup during rendering is allocation-free.
    pub key: String,
}

/// Shared, refreshable cache of the IANA-registered servers.
pub type IanaCache = Arc<RwLock<Vec<IanaServer>>>;

/// Errors surfaced while fetching or decoding the IANA registry.
#[derive(Debug, thiserror::Error)]
pub enum IanaError {
    /// The request could not be completed.
    #[error("fetch failed: {0}")]
    Fetch(#[from] reqwest::Error),
    /// The server responded with a non-success status.
    #[error("unexpected status: {code}")]
    Status { code: u16 },
    /// The body was not valid JSON.
    #[error("invalid JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Parses the object-tags JSON into a deduped, display-ordered server list.
///
/// Each `services` entry is `[ [contacts], [tags], [urls] ]`. We take the
/// first tag as the display name and prefer an `https://` URL (falling back
/// to the first non-empty URL when no HTTPS variant is published). Entries
/// missing a tag or any URL are skipped, and duplicates — compared via
/// [`normalize_bootstrap`] — are collapsed so a provider publishing both
/// `http` and `https` appears once. The result is sorted by tag
/// (case-insensitively) for a stable display order.
pub fn parse_object_tags(json: &serde_json::Value) -> Vec<IanaServer> {
    let mut servers: Vec<IanaServer> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let Some(services) = json.get("services").and_then(|s| s.as_array()) else {
        return servers;
    };

    for entry in services {
        let Some(fields) = entry.as_array() else {
            continue;
        };
        let tag = fields
            .get(1)
            .and_then(|t| t.as_array())
            .and_then(|t| t.first())
            .and_then(|t| t.as_str())
            .map(str::trim)
            .filter(|t| !t.is_empty());
        let urls = fields.get(2).and_then(|u| u.as_array());
        let (Some(tag), Some(urls)) = (tag, urls) else {
            continue;
        };

        let url = urls
            .iter()
            .filter_map(|u| u.as_str())
            .find(|u| u.starts_with("https://"))
            .or_else(|| {
                urls.iter()
                    .filter_map(|u| u.as_str())
                    .find(|u| !u.trim().is_empty())
            })
            .map(str::trim)
            .filter(|u| !u.is_empty());
        let Some(url) = url else {
            continue;
        };

        let key = normalize_bootstrap(url);
        if seen.insert(key.clone()) {
            servers.push(IanaServer {
                tag: tag.to_string(),
                url: url.to_string(),
                key,
            });
        }
    }

    servers.sort_by_key(|s| s.tag.to_lowercase());
    servers
}

/// Fetches and parses the IANA object-tags registry using the supplied
/// client (a single client is reused across refreshes to keep its connection
/// pool and TLS config warm).
pub async fn fetch_iana(client: &reqwest::Client) -> Result<Vec<IanaServer>, IanaError> {
    let resp = client
        .get(IANA_OBJECT_TAGS_URL)
        .timeout(Duration::from_secs(15))
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        return Err(IanaError::Status {
            code: status.as_u16(),
        });
    }

    let body = resp.text().await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    Ok(parse_object_tags(&json))
}

/// Resolves the refresh interval from the raw `IANA_REFRESH_SECS` value,
/// falling back to [`DEFAULT_REFRESH_SECS`] when unset/unparseable and
/// clamping to at least [`MIN_REFRESH_SECS`].
fn compute_refresh_interval(raw: Option<&str>) -> Duration {
    let secs = raw
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REFRESH_SECS);
    Duration::from_secs(secs.max(MIN_REFRESH_SECS))
}

/// Resolves the startup (warm-up) timeout from the raw
/// `IANA_STARTUP_TIMEOUT_SECS` value, falling back to
/// [`DEFAULT_STARTUP_TIMEOUT_SECS`] when unset/unparseable and clamping to
/// at least [`MIN_STARTUP_TIMEOUT_SECS`].
fn compute_startup_timeout(raw: Option<&str>) -> Duration {
    let secs = raw
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_STARTUP_TIMEOUT_SECS);
    Duration::from_secs(secs.max(MIN_STARTUP_TIMEOUT_SECS))
}

/// The delay to wait before the *next* refresh: the normal `interval` after
/// a success, or the shorter `retry` after a failure (so an outage recovers
/// sooner than the daily cadence).
fn next_delay(ok: bool, interval: Duration, retry: Duration) -> Duration {
    if ok { interval } else { retry }
}

/// Best-effort initial population of the cache, performed *before* the
/// server starts answering requests.
///
/// Waits up to the startup budget for one fetch. On success the cache is
/// populated and `true` is returned; on error or timeout the cache is left
/// as-is (empty) and `false` is returned, so the caller can start serving
/// with the bootstrap-only dropdown while the background refresher retries.
pub async fn warm_up(cache: &IanaCache, client: &reqwest::Client) -> bool {
    let budget =
        compute_startup_timeout(std::env::var("IANA_STARTUP_TIMEOUT_SECS").ok().as_deref());
    match tokio::time::timeout(budget, fetch_iana(client)).await {
        Ok(Ok(servers)) => {
            tracing::info!(
                count = servers.len(),
                "loaded IANA RDAP object tags before serving"
            );
            *cache.write().await = servers;
            true
        }
        Ok(Err(err)) => {
            tracing::warn!("IANA unavailable at startup: {err}; serving with bootstrap only");
            false
        }
        Err(_) => {
            tracing::warn!(
                "IANA startup fetch timed out after {:?}; serving with bootstrap only",
                budget
            );
            false
        }
    }
}

/// Spawns a background task that keeps the cache fresh *during* serving.
///
/// Sleep-first: it waits before each fetch rather than fetching on spawn, so
/// it never duplicates the startup [`warm_up`]. The first wait is the short
/// [`RETRY_SECS`] when the cache is still empty (warm-up failed) and the
/// normal interval otherwise; thereafter each wait is chosen by
/// [`next_delay`] from the previous fetch's outcome. A successful fetch
/// replaces the cached list; a failed fetch keeps the last-good value and
/// logs a warning, so a transient IANA outage never empties the dropdown.
///
/// Must be called from within a Tokio runtime (the task is spawned with
/// [`tokio::spawn`]).
pub fn spawn_refresher(cache: IanaCache, client: reqwest::Client) {
    let interval = compute_refresh_interval(std::env::var("IANA_REFRESH_SECS").ok().as_deref());
    let retry = Duration::from_secs(RETRY_SECS);

    tokio::spawn(async move {
        // Recover quickly if the startup warm-up left the cache empty.
        let mut delay = if cache.read().await.is_empty() {
            retry
        } else {
            interval
        };
        loop {
            tokio::time::sleep(delay).await;
            match fetch_iana(&client).await {
                Ok(servers) => {
                    tracing::info!(count = servers.len(), "refreshed IANA RDAP object tags");
                    *cache.write().await = servers;
                    delay = next_delay(true, interval, retry);
                }
                Err(err) => {
                    tracing::warn!("failed to refresh IANA RDAP object tags: {err}");
                    delay = next_delay(false, interval, retry);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(raw: &str) -> serde_json::Value {
        serde_json::from_str(raw).expect("test fixture must be valid JSON")
    }

    #[test]
    fn parses_tag_and_prefers_https() {
        // GIVEN a registry with one provider offering both http and https
        let doc = json(
            r#"{
                "services": [
                    [["info@arin.net"], ["ARIN"], ["https://rdap.arin.net/registry/", "http://rdap.arin.net/registry/"]]
                ]
            }"#,
        );
        // WHEN parsed
        let servers = parse_object_tags(&doc);
        // THEN the tag is the label, the https URL wins, and the key is
        // the normalized (slash-stripped) URL
        assert_eq!(
            servers,
            vec![IanaServer {
                tag: "ARIN".to_string(),
                url: "https://rdap.arin.net/registry/".to_string(),
                key: "https://rdap.arin.net/registry".to_string(),
            }]
        );
    }

    #[test]
    fn falls_back_to_first_url_when_no_https() {
        // GIVEN a provider publishing only an http URL
        let doc =
            json(r#"{ "services": [[["x@e.net"], ["HTTPONLY"], ["http://rdap.example/"]]] }"#);
        // WHEN parsed
        let servers = parse_object_tags(&doc);
        // THEN the http URL is used
        assert_eq!(servers[0].url, "http://rdap.example/");
    }

    #[test]
    fn skips_malformed_entries() {
        // GIVEN a mix of well-formed and broken entries
        let doc = json(
            r#"{
                "services": [
                    [["x@e.net"], ["GOOD"], ["https://good.example/"]],
                    [["x@e.net"], [], ["https://notag.example/"]],
                    [["x@e.net"], ["NOURLS"], []],
                    "not-an-array",
                    [1, 2, 3]
                ]
            }"#,
        );
        // WHEN parsed
        let servers = parse_object_tags(&doc);
        // THEN only the well-formed entry survives
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].tag, "GOOD");
    }

    #[test]
    fn dedups_by_normalized_url() {
        // GIVEN two providers whose URLs differ only by a trailing slash
        let doc = json(
            r#"{
                "services": [
                    [["a@e.net"], ["A"], ["https://same.example/"]],
                    [["b@e.net"], ["B"], ["https://same.example"]],
                    [["c@e.net"], ["C"], ["https://other.example/"]]
                ]
            }"#,
        );
        // WHEN parsed
        let servers = parse_object_tags(&doc);
        // THEN the duplicate collapses to the first occurrence
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].tag, "A");
        assert_eq!(servers[1].tag, "C");
    }

    #[test]
    fn sorts_case_insensitively_by_tag() {
        // GIVEN tags in mixed case
        let doc = json(
            r#"{
                "services": [
                    [["z@e.net"], ["zeta"], ["https://z.example/"]],
                    [["a@e.net"], ["Alpha"], ["https://a.example/"]],
                    [["m@e.net"], ["mid"], ["https://m.example/"]]
                ]
            }"#,
        );
        // WHEN parsed
        let servers = parse_object_tags(&doc);
        // THEN they sort case-insensitively
        let tags: Vec<&str> = servers.iter().map(|s| s.tag.as_str()).collect();
        assert_eq!(tags, vec!["Alpha", "mid", "zeta"]);
    }

    #[test]
    fn missing_services_yields_empty() {
        // GIVEN a document with no services array
        let doc = json(r#"{ "version": "1.0" }"#);
        // WHEN parsed
        // THEN the result is empty rather than a panic
        assert!(parse_object_tags(&doc).is_empty());
    }

    #[test]
    fn refresh_interval_defaults_when_unset() {
        // GIVEN no configured interval
        // THEN the 24h default is used
        assert_eq!(
            compute_refresh_interval(None),
            Duration::from_secs(DEFAULT_REFRESH_SECS)
        );
    }

    #[test]
    fn refresh_interval_parses_valid_value() {
        // GIVEN a valid configured interval
        // THEN it is honored
        assert_eq!(
            compute_refresh_interval(Some("3600")),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn refresh_interval_clamps_to_floor() {
        // GIVEN values at or below the floor (0, 1, 30)
        // THEN they are raised to MIN_REFRESH_SECS
        for raw in ["0", "1", "30"] {
            assert_eq!(
                compute_refresh_interval(Some(raw)),
                Duration::from_secs(MIN_REFRESH_SECS),
                "raw {raw} should clamp to the floor"
            );
        }
    }

    #[test]
    fn refresh_interval_falls_back_on_unparseable() {
        // GIVEN a non-numeric configured value
        // THEN the default is used
        assert_eq!(
            compute_refresh_interval(Some("not-a-number")),
            Duration::from_secs(DEFAULT_REFRESH_SECS)
        );
    }

    #[test]
    fn next_delay_success_uses_interval_failure_uses_retry() {
        // GIVEN an interval and a shorter retry
        let interval = Duration::from_secs(3600);
        let retry = Duration::from_secs(60);
        // THEN a success waits the full interval, a failure retries sooner
        assert_eq!(next_delay(true, interval, retry), interval);
        assert_eq!(next_delay(false, interval, retry), retry);
    }

    #[test]
    fn startup_timeout_defaults_and_clamps() {
        // GIVEN unset / valid / below-floor values
        // THEN default, honored value, and floor respectively
        assert_eq!(
            compute_startup_timeout(None),
            Duration::from_secs(DEFAULT_STARTUP_TIMEOUT_SECS)
        );
        assert_eq!(compute_startup_timeout(Some("20")), Duration::from_secs(20));
        assert_eq!(
            compute_startup_timeout(Some("0")),
            Duration::from_secs(MIN_STARTUP_TIMEOUT_SECS)
        );
    }
}
