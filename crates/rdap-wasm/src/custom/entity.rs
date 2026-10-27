use icann_rdap_common::prelude::Entity;

use super::common::{append_common, contact_rows, entity_label};
use super::html::{escape, kv_table, mono, render, row, section, str_opt, title};

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
        .map(|p| {
            format!(
                "{}={}",
                str_opt(p.id_type.as_ref()),
                str_opt(p.identifier.as_ref())
            )
        })
        .filter(|s| s != "=")
        .collect();
    if !public_ids.is_empty() {
        summary.push(row("Public IDs", &escape(&public_ids.join(", "))));
    }
    if let Some(handle) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(handle)));
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
