//! In-page anchor ids shared by the result tree and the result body.
//!
//! The tree and the body are rendered from the same `ResponseData` in the
//! same order, so both sides can independently compute *identical* anchor
//! ids from an object's position in the source data. An id is built only
//! from fixed segments and integer indices — never from RDAP-provided text
//! — so ids are always HTML/URL-safe and need no escaping.
//!
//! Shape of the id space (`A` is the anchor of the containing object):
//! - response body root: `rdap-r{i}` (i = position among the tree root's
//!   children: 0 = main response, 1..n = followed referrals)
//! - entity block at index `i`: `A-ent-{i}` (nested: `A-ent-{i}-ent-{j}`)
//! - nameserver list item at index `i`: `A-ns-{i}`
//! - search-result block at index `i`: `A-res-{i}`
//!
//! An empty anchor (`""`) means "no anchors" (the non-tree render path);
//! renderers then emit no `id` attributes at all.

/// Anchor id for a rendered response body, where `idx` is the response's
/// position among the result tree's root children.
pub(crate) fn response_anchor(idx: usize) -> String {
    format!("rdap-r{idx}")
}

/// Anchor id for the entity block at index `i` within the entity group of
/// the object anchored at `anchor`. Empty when `anchor` is empty, so the
/// "no anchors" path propagates and never emits a stray id.
pub(crate) fn entity_anchor(anchor: &str, i: usize) -> String {
    if anchor.is_empty() {
        String::new()
    } else {
        format!("{anchor}-ent-{i}")
    }
}

/// Anchor id for the nameserver `<li>` at index `i` of the object
/// anchored at `anchor`. Empty when `anchor` is empty.
pub(crate) fn nameserver_anchor(anchor: &str, i: usize) -> String {
    if anchor.is_empty() {
        String::new()
    } else {
        format!("{anchor}-ns-{i}")
    }
}

/// Anchor id for the search-result block at index `i` within the search
/// response anchored at `anchor`. Empty when `anchor` is empty.
pub(crate) fn search_item_anchor(anchor: &str, i: usize) -> String {
    if anchor.is_empty() {
        String::new()
    } else {
        format!("{anchor}-res-{i}")
    }
}

/// A `id="…"` attribute for `anchor`, or empty when anchoring is off.
pub(crate) fn id_attr(anchor: &str) -> String {
    if anchor.is_empty() {
        String::new()
    } else {
        format!(" id=\"{anchor}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_anchor_is_index_prefixed() {
        // GIVEN response indices 0 and 2
        // WHEN the anchors are built
        // THEN they are distinct and carry the `rdap-r` prefix
        assert_eq!(response_anchor(0), "rdap-r0");
        assert_eq!(response_anchor(2), "rdap-r2");
    }

    #[test]
    fn nested_entity_anchors_extend_the_parent_path() {
        // GIVEN a domain response anchor and an entity path of [1, 0]
        let domain = response_anchor(0);
        // WHEN the nested entity anchors are built
        let l1 = entity_anchor(&domain, 1);
        let l2 = entity_anchor(&l1, 0);
        // THEN each level appends its index segment
        assert_eq!(l1, "rdap-r0-ent-1");
        assert_eq!(l2, "rdap-r0-ent-1-ent-0");
    }

    #[test]
    fn id_attr_is_empty_without_an_anchor() {
        // GIVEN anchoring is off
        // THEN no attribute is emitted
        assert_eq!(id_attr(""), "");
        assert_eq!(id_attr("rdap-r0"), " id=\"rdap-r0\"");
    }
}
