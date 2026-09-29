use icann_rdap_common::prelude::{Contact, Entity, Events, Links, Nameserver, ObjectCommon};

use super::entity::append_entity_body;
use super::html::{div, escape, kv_table, mono, row, section, str_opt, title};

/// Appends the shared object-common sections (status, events, links, redacted,
/// nested entities) to `parts`. Reused by every object-class renderer.
pub(crate) fn append_common(parts: &mut Vec<String>, oc: &ObjectCommon) {
    if let Some(status) = oc.status.as_ref() {
        let items = status
            .vec()
            .iter()
            .map(|s| escape(&s.to_string()))
            .collect::<Vec<_>>();
        if !items.is_empty() {
            parts.push(section(
                "Status",
                kv_table(&[row("Status", &items.join(", "))]),
            ));
        }
    }
    if let Some(events) = oc.events.as_ref() {
        parts.push(section("Events", events_table(events)));
    }
    if let Some(links) = oc.links.as_ref() {
        parts.push(section("Links", links_table(links)));
    }
    if let Some(redacted) = oc.redacted.as_ref() {
        let mut rows = Vec::new();
        for r in redacted.iter() {
            let name = r
                .name
                .description()
                .map(escape)
                .or_else(|| r.name.type_field().map(escape))
                .unwrap_or_default();
            let reason = r
                .reason
                .as_ref()
                .and_then(|reason| reason.description())
                .map(escape)
                .unwrap_or_default();
            if name.is_empty() && reason.is_empty() {
                continue;
            }
            rows.push(row(&name, &reason));
        }
        parts.push(section("Redacted", kv_table(&rows)));
    }
    if let Some(entities) = oc.entities.as_ref() {
        let mut blocks = Vec::new();
        for ent in entities.iter() {
            let label = entity_label(ent);
            let mut body = vec![title("Entity", label.as_deref())];
            append_entity_body(&mut body, ent);
            let block = div("rdap_entity", body);
            if !block.is_empty() {
                blocks.push(block);
            }
        }
        parts.push(section("Entities", blocks.join("")));
    }
}

/// A short label for an entity: its roles, else its handle.
pub(crate) fn entity_label(entity: &Entity) -> Option<String> {
    let roles = entity.roles();
    if !roles.is_empty() {
        return Some(roles.join(", "));
    }
    entity
        .object_common
        .handle
        .as_deref()
        .map(|h| h.to_string())
}

/// Renders the contact (vCard) details for an entity.
pub(crate) fn contact_rows(contact: &Contact) -> String {
    let mut rows = Vec::new();
    if let Some(name) = contact.full_name() {
        rows.push(row("Name", &escape(name)));
    }
    if let Some(org) = contact.organization_name() {
        rows.push(row("Organization", &escape(org)));
    }
    let emails: Vec<String> = contact.emails().iter().map(|e| e.email.clone()).collect();
    if !emails.is_empty() {
        rows.push(row("Email", &escape(&emails.join(", "))));
    }
    let phones: Vec<String> = contact.phones().iter().map(|p| p.phone.clone()).collect();
    if !phones.is_empty() {
        rows.push(row("Phone", &escape(&phones.join(", "))));
    }
    kv_table(&rows)
}

/// Renders a domain's nameservers as a simple list.
pub(crate) fn nameserver_list(nameservers: &[Nameserver]) -> String {
    let items = nameservers
        .iter()
        .filter_map(|ns| ns.ldh_name.as_deref())
        .map(|n| format!("<li>{}</li>", mono(n)))
        .collect::<Vec<_>>();
    if items.is_empty() {
        return String::new();
    }
    format!("<ul class=\"rdap_list\">{}</ul>", items.join(""))
}

fn events_table(events: &Events) -> String {
    let mut rows = Vec::new();
    for e in events.iter() {
        let action = str_opt(e.event_action.as_ref());
        let date = str_opt(e.event_date.as_ref());
        let actor = str_opt(e.event_actor.as_ref());
        if action.is_empty() && date.is_empty() && actor.is_empty() {
            continue;
        }
        rows.push(format!(
            "<tr><td>{action}</td><td>{date}</td><td>{actor}</td></tr>"
        ));
    }
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<table class=\"data_table\"><thead><tr><th>Action</th><th>Date</th><th>Actor</th></tr></thead><tbody>{}</tbody></table>",
        rows.join("")
    )
}

fn links_table(links: &Links) -> String {
    let mut rows = Vec::new();
    for l in links.iter() {
        let rel = str_opt(l.rel.as_ref());
        let media = str_opt(l.media_type.as_ref());
        let url = l
            .href
            .as_deref()
            .or(l.value.as_deref())
            .map(mono)
            .unwrap_or_default();
        if rel.is_empty() && media.is_empty() && url.is_empty() {
            continue;
        }
        rows.push(format!(
            "<tr><td>{rel}</td><td>{media}</td><td>{url}</td></tr>"
        ));
    }
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<table class=\"data_table\"><thead><tr><th>Relation</th><th>Type</th><th>URL</th></tr></thead><tbody>{}</tbody></table>",
        rows.join("")
    )
}
