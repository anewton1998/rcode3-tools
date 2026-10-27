use icann_rdap_common::prelude::Entity;

use super::common::{append_common, contact_rows, entity_label};
use super::html::{escape, kv_table, mono, render, row, section, title, with_copy};

pub(crate) fn entity_html(entity: &Entity, authority: &str, anchor: &str) -> String {
    let label = entity_label(entity);
    let mut parts = vec![title("Entity", label.as_deref())];
    append_entity_body(&mut parts, entity, authority, anchor);
    render(parts, anchor)
}

/// Appends an entity's summary, contact details, and shared sections.
/// `anchor` is this entity's in-page anchor, passed down so nested entity
/// blocks receive child anchors.
pub(crate) fn append_entity_body(
    parts: &mut Vec<String>,
    entity: &Entity,
    authority: &str,
    anchor: &str,
) {
    let oc = &entity.object_common;
    let mut summary = Vec::new();
    let roles = entity.roles().join(", ");
    if !roles.is_empty() {
        summary.push(row("Roles", &escape(&roles)));
    }
    let public_ids: Vec<String> = entity
        .public_ids()
        .iter()
        .filter_map(|p| {
            let identifier = p.identifier.as_deref().unwrap_or_default();
            if identifier.is_empty() {
                return None;
            }
            let type_str = p.id_type.as_deref().unwrap_or("");
            let display = if type_str.is_empty() {
                mono(identifier)
            } else {
                mono(&format!("{type_str}={identifier}"))
            };
            Some(row("Public ID", &with_copy(display, identifier)))
        })
        .collect();
    summary.extend(public_ids);
    if let Some(handle) = oc.handle.as_deref() {
        summary.push(row("Handle", &with_copy(mono(handle), handle)));
    }
    parts.push(kv_table(&summary));

    if let Some(contact) = entity.contact() {
        parts.push(section("Contact", contact_rows(&contact)));
    }
    append_common(parts, authority, oc, &entity.common, anchor);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_renders_roles_and_handle() {
        let json = r#"{
            "objectClassName": "entity",
            "handle": "299",
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA ID", "identifier": "299"}]
        }"#;
        let entity: Entity = serde_json::from_str(json).unwrap();
        let html = entity_html(&entity, "rdap.example", "rdap-r0");
        assert!(html.contains("Roles"), "{html}");
        assert!(html.contains("registrar"), "{html}");
        assert!(html.contains("299"), "{html}");
        // the top-level entity body carries the response anchor
        assert!(html.contains("id=\"rdap-r0\""), "{html}");
    }

    #[test]
    fn entity_handle_has_copy_button() {
        // GIVEN an entity with a handle
        let json = r#"{
            "objectClassName": "entity",
            "handle": "299",
            "roles": ["registrar"]
        }"#;
        let entity: Entity = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = entity_html(&entity, "rdap.example", "");

        // THEN the Handle row carries a copy button for the handle
        assert!(html.contains("copyToClipboard('299')"), "{html}");
    }

    #[test]
    fn entity_public_ids_get_one_row_each_copying_identifier() {
        // GIVEN an entity with two public ids
        let json = r#"{
            "objectClassName": "entity",
            "handle": "299",
            "roles": ["registrar"],
            "publicIds": [
                {"type": "IANA ID", "identifier": "299"},
                {"type": "DUNS", "identifier": "123456789"}
            ]
        }"#;
        let entity: Entity = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = entity_html(&entity, "rdap.example", "");

        // THEN each public id is its own row copying the bare identifier
        assert_eq!(
            html.matches("<td class=\"data_key\">Public ID</td>")
                .count(),
            2,
            "{html}"
        );
        assert!(html.contains("copyToClipboard('299')"), "{html}");
        assert!(html.contains("copyToClipboard('123456789')"), "{html}");
        // the display keeps the type=identifier form
        assert!(html.contains("IANA ID=299"), "{html}");
        // the type prefix must not be part of the copied value
        assert!(!html.contains("copyToClipboard('IANA ID=299')"), "{html}");
    }

    #[test]
    fn entity_public_id_without_type_copies_identifier() {
        // GIVEN a public id with no type
        let json = r#"{
            "objectClassName": "entity",
            "handle": "299",
            "publicIds": [{"identifier": "abc"}]
        }"#;
        let entity: Entity = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = entity_html(&entity, "rdap.example", "");

        // THEN it still renders a row copying the identifier
        assert!(html.contains("copyToClipboard('abc')"), "{html}");
    }

    #[test]
    fn entity_without_anchor_emits_no_id() {
        // GIVEN the non-tree render path (empty anchor) and an entity whose
        // nested entity group would otherwise mint child ids
        let json = r#"{
            "objectClassName": "entity",
            "handle": "299",
            "roles": ["registrar"],
            "entities": [{"objectClassName": "entity", "handle": "7018", "roles": ["technical"]}]
        }"#;
        let entity: Entity = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = entity_html(&entity, "rdap.example", "");
        // THEN no id attribute is emitted anywhere (the empty anchor must
        // propagate so concatenated non-tree responses never collide)
        assert!(!html.contains("id="), "{html}");
    }
}
