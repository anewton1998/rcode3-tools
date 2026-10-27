//! Generic wrapper for RDAP search-result responses.
//!
//! A search response is a level-0 `Common` plus an array of full objects
//! (`Vec<Domain>`, `Vec<Entity>`, …). This module renders that uniformly:
//! a heading carrying the search type and result count, then each contained
//! object rendered in full via a caller-supplied renderer and separated by
//! the same `data_divider` used between followed referrals, capped at
//! [`MAX_SEARCH_RESULTS`] with a trailing "…and N more" note, and finally
//! the level-0 notices/conformance rendered once.
//!
//! Design notes:
//! - The contained-object renderer is passed in as a closure so this module
//!   stays agnostic of the object class and reuses the existing per-object
//!   renderers (`domain_html`, `entity_html`, `rpki::roa_html`, …).
//! - The cap bounds DOM size and render time for large result sets while
//!   still telling the user how many were omitted.
//! - Notices and conformance live at the search wrapper level (level 0), not
//!   on each contained object, so they are emitted once here.

use icann_rdap_common::prelude::Common;

use super::anchor::search_item_anchor;
use super::common::append_level0_common;
use super::html::{render, title};

/// Maximum number of contained results rendered before truncating with a
/// "…and N more" note. Bounds DOM size for large RDAP search responses.
pub(crate) const MAX_SEARCH_RESULTS: usize = 50;

/// Renders a search-results wrapper around `results`.
///
/// `label` is the human search type (e.g. `Domain Search Results`); the
/// result count is appended to the heading. `render_one` renders a single
/// contained object to its full result HTML, receiving the item's in-page
/// anchor so the contained object's body carries it (the result tree links
/// to it). `anchor` is the search response's own anchor.
pub(crate) fn search_results_html<T>(
    label: &str,
    results: &[T],
    authority: &str,
    common: &Common,
    anchor: &str,
    render_one: impl Fn(&T, &str, &str) -> String,
) -> String {
    let heading = format!("{label} ({})", results.len());
    let mut parts = vec![title(&heading, None)];

    if results.is_empty() {
        parts.push("<span class=\"info_text\">No results found.</span>".to_string());
    } else {
        let rendered: Vec<String> = results
            .iter()
            .take(MAX_SEARCH_RESULTS)
            .enumerate()
            .map(|(i, r)| render_one(r, authority, &search_item_anchor(anchor, i)))
            .collect();
        parts.push(rendered.join(&super::referral_divider()));
        if results.len() > MAX_SEARCH_RESULTS {
            let more = results.len() - MAX_SEARCH_RESULTS;
            let plural = if more == 1 { "" } else { "s" };
            parts.push(format!(
                "<p class=\"info_text\">…and {more} more result{plural} not shown.</p>"
            ));
        }
    }

    append_level0_common(&mut parts, authority, common);
    render(parts, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use icann_rdap_common::prelude::Common;

    fn empty_common() -> Common {
        // The icann-rdap builders are crate-private; an empty level-0 Common
        // deserializes from an empty object (all fields are optional).
        serde_json::from_str("{}").expect("empty Common")
    }

    /// A trivial renderer so the wrapper can be tested without a real object.
    /// Echoes the item anchor as the `data_result` id so anchor threading is
    /// observable.
    fn render_marker(item: &String, _authority: &str, anchor: &str) -> String {
        if anchor.is_empty() {
            format!("<div class=\"data_result\">item-{item}</div>")
        } else {
            format!("<div class=\"data_result\" id=\"{anchor}\">item-{item}</div>")
        }
    }

    #[test]
    fn heading_shows_label_and_count() {
        // GIVEN three results
        let results = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        // WHEN wrapped
        let html = search_results_html(
            "Domain Search Results",
            &results,
            "rdap.example",
            &empty_common(),
            "rdap-r0",
            render_marker,
        );
        // THEN the heading carries the label and the count
        assert!(html.contains("Domain Search Results (3)"), "{html}");
    }

    #[test]
    fn empty_results_show_no_results_note() {
        // GIVEN an empty result set
        let results: Vec<String> = Vec::new();
        // WHEN wrapped
        let html = search_results_html(
            "Entity Search Results",
            &results,
            "rdap.example",
            &empty_common(),
            "rdap-r0",
            render_marker,
        );
        // THEN a "No results found." note is shown and no divider appears
        assert!(html.contains("No results found."), "{html}");
        assert!(!html.contains("data_divider"), "{html}");
    }

    #[test]
    fn results_are_joined_with_dividers() {
        // GIVEN two results
        let results = vec!["a".to_string(), "b".to_string()];
        // WHEN wrapped
        let html = search_results_html(
            "Nameserver Search Results",
            &results,
            "rdap.example",
            &empty_common(),
            "rdap-r0",
            render_marker,
        );
        // THEN exactly one divider sits between the two full results
        assert_eq!(html.matches("data_divider").count(), 1, "{html}");
        assert!(html.contains("item-a"), "{html}");
        assert!(html.contains("item-b"), "{html}");
    }

    #[test]
    fn results_are_capped_with_an_and_n_more_note() {
        // GIVEN more results than the cap
        let results: Vec<String> = (0..(MAX_SEARCH_RESULTS + 3))
            .map(|i| i.to_string())
            .collect();
        // WHEN wrapped
        let html = search_results_html(
            "Domain Search Results",
            &results,
            "rdap.example",
            &empty_common(),
            "rdap-r0",
            render_marker,
        );
        // THEN only MAX_SEARCH_RESULTS objects render, with a trailing note
        // (count the item markers, not `data_result`, since the wrapper is
        // itself a `data_result` div).
        assert_eq!(html.matches("item-").count(), MAX_SEARCH_RESULTS, "{html}");
        assert!(html.contains("…and 3 more results not shown."), "{html}");
        // the last omitted item must not be present
        assert!(!html.contains("item-53"), "{html}");
    }

    #[test]
    fn single_omitted_result_is_singular() {
        // GIVEN exactly one result beyond the cap
        let results: Vec<String> = (0..(MAX_SEARCH_RESULTS + 1))
            .map(|i| i.to_string())
            .collect();
        // WHEN wrapped
        let html = search_results_html(
            "Domain Search Results",
            &results,
            "rdap.example",
            &empty_common(),
            "rdap-r0",
            render_marker,
        );
        // THEN the note reads "1 more result" (singular)
        assert!(html.contains("…and 1 more result not shown."), "{html}");
        assert!(!html.contains("1 more results"), "{html}");
    }

    #[test]
    fn level_zero_common_rendered_once() {
        // GIVEN a search wrapper carrying a notice and conformance
        let json = r#"{
            "rdapConformance": ["rdap_level_0"],
            "notices": [{"title": "Terms", "description": ["Accept terms"]}]
        }"#;
        let common: Common = serde_json::from_str(json).unwrap();
        let results = vec!["a".to_string()];
        // WHEN wrapped
        let html = search_results_html(
            "Domain Search Results",
            &results,
            "rdap.example",
            &common,
            "rdap-r0",
            render_marker,
        );
        // THEN the level-0 notices and conformance appear once
        assert!(html.contains("Service Notices"), "{html}");
        assert!(html.contains("Terms"), "{html}");
        assert!(html.contains("rdap_level_0"), "{html}");
        assert_eq!(html.matches("Service Notices").count(), 1, "{html}");
    }
}
