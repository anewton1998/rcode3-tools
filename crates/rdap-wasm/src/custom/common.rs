use icann_rdap_common::prelude::{
    Common, Contact, Entity, Events, Links, Nameserver, Notice, ObjectCommon, Remarks,
};

use super::entity::append_entity_body;
use super::html::{div, escape, kv_table, mono, row, section, str_opt, title};

/// Appends the shared object-common sections (status, events, links, redacted,
/// nested entities, notices, conformance) to `parts`. Reused by every object-class renderer.
pub(crate) fn append_common(
    parts: &mut Vec<String>,
    authority: &str,
    oc: &ObjectCommon,
    common: &Common,
) {
    if let Some(status) = oc.status.as_ref() {
        let mut items: Vec<String> = status
            .vec()
            .iter()
            .map(|s| escape(&s.to_string()))
            .collect();
        items.sort();
        if !items.is_empty() {
            let bullets = items
                .iter()
                .map(|item| format!("<li>{}</li>", item))
                .collect::<Vec<_>>()
                .join("");
            parts.push(section(
                "Status",
                format!("<ul class=\"data_list\">{}</ul>", bullets),
            ));
        }
    }
    if let Some(remarks) = oc.remarks.as_ref() {
        parts.push(section("Remarks", remarks_list(remarks)));
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
            append_entity_body(&mut body, ent, authority);
            let block = div("indented_section", body);
            if !block.is_empty() {
                blocks.push(block);
            }
        }
        parts.push(section("Entities", blocks.join("")));
    }
    if let Some(notices) = common.notices.as_ref() {
        parts.push(section("Service Notices", notices_list(notices)));
    }
    if let Some(conformance) = common.rdap_conformance.as_ref() {
        parts.push(conformance_section(authority, conformance));
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
    format!("<ul class=\"data_list\">{}</ul>", items.join(""))
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

fn remarks_list(remarks: &Remarks) -> String {
    let mut html = String::new();
    for r in remarks.iter() {
        let title = r.title.as_deref().map(escape).unwrap_or_default();
        let r#type = r.nr_type.as_deref().map(escape);
        let desc = r
            .description
            .as_ref()
            .map(|d| {
                let items: Vec<String> = Vec::from(d);
                let filtered: Vec<String> = items
                    .iter()
                    .filter(|i| !i.trim().is_empty())
                    .cloned()
                    .collect();
                let mut groups: Vec<String> = Vec::new();
                let mut current_group = Vec::new();
                for item in &filtered {
                    let escaped = escape(item);
                    if !ends_with_punctuation(item) {
                        current_group.push(escaped);
                    } else {
                        current_group.push(escaped);
                        groups.push(current_group.join("<br>"));
                        current_group = Vec::new();
                    }
                }
                if !current_group.is_empty() {
                    groups.push(current_group.join("<br>"));
                }
                groups
                    .iter()
                    .map(|g| format!("<p class=\"data_unstructured_text\">{}</p>", g))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if title.is_empty() && r#type.is_none() && desc.is_empty() {
            continue;
        }
        let heading_text = if let Some(t) = &r#type {
            format!("{} ({})", title, mono(t))
        } else {
            title
        };
        let heading_class = if r#type.is_some() {
            "warning_text"
        } else {
            "info_text"
        };
        html.push_str(&format!(
            "<div class=\"indented_section\"><h2 class=\"{}\">{}</h2>{}</div>",
            heading_class, heading_text, desc
        ));
    }
    html
}

fn ends_with_punctuation(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed.ends_with('.')
        || trimmed.ends_with('!')
        || trimmed.ends_with('?')
        || trimmed.ends_with(';')
}

fn notices_list(notices: &[Notice]) -> String {
    let mut html = String::new();
    for notice in notices.iter() {
        let nr = &notice.0;
        let title = nr.title.as_deref().map(escape).unwrap_or_default();
        let r#type = nr.nr_type.as_deref().map(escape);
        let desc = nr
            .description
            .as_ref()
            .map(|d| {
                let items: Vec<String> = Vec::from(d);
                let filtered: Vec<String> = items
                    .iter()
                    .filter(|i| !i.trim().is_empty())
                    .cloned()
                    .collect();
                let mut groups: Vec<String> = Vec::new();
                let mut current_group = Vec::new();
                for item in &filtered {
                    let escaped = escape(item);
                    if !ends_with_punctuation(item) {
                        current_group.push(escaped);
                    } else {
                        current_group.push(escaped);
                        groups.push(current_group.join("<br>"));
                        current_group = Vec::new();
                    }
                }
                if !current_group.is_empty() {
                    groups.push(current_group.join("<br>"));
                }
                groups
                    .iter()
                    .map(|g| format!("<p class=\"data_unstructured_text\">{}</p>", g))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if title.is_empty() && r#type.is_none() && desc.is_empty() {
            continue;
        }
        let heading_text = if let Some(t) = &r#type {
            format!("{} ({})", title, mono(t))
        } else {
            title
        };
        let heading_class = if r#type.is_some() {
            "warning_text"
        } else {
            "info_text"
        };
        let links_html = if let Some(links) = &nr.links {
            links_table(links)
        } else {
            String::new()
        };
        html.push_str(&format!(
            "<div class=\"indented_section\"><h2 class=\"{}\">{}</h2>{}{}</div>",
            heading_class, heading_text, desc, links_html
        ));
    }
    html
}

fn conformance_section(
    authority: &str,
    conformance: &[icann_rdap_common::prelude::Extension],
) -> String {
    let items: Vec<String> = conformance
        .iter()
        .map(|e| format!("<li class=\"mono_text\">{}</li>", escape(&e.0)))
        .collect();
    section(
        &format!("Conformance Claims in Response from {}", escape(authority)),
        format!("<ul class=\"data_list\">{}</ul>", items.join("")),
    )
}

#[cfg(test)]
mod tests {
    use crate::custom::domain::domain_html;
    use icann_rdap_common::prelude::Domain;

    #[test]
    fn remarks_rendered_with_title() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "remarks": [{"title": "Note", "description": ["Hello world"]}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(html.contains("Remarks"), "{html}");
        assert!(html.contains("Note"), "{html}");
        assert!(html.contains("Hello world"), "{html}");
        assert!(html.contains("<h2"), "{html}");
        assert!(html.contains("info_text"), "{html}");
    }

    #[test]
    fn remark_falls_back_to_type() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "remarks": [{"type": "glossary", "description": ["See docs"]}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(html.contains("Remarks"), "{html}");
        assert!(html.contains("glossary"), "{html}");
        assert!(html.contains("See docs"), "{html}");
        assert!(html.contains("mono_text"), "{html}");
        assert!(html.contains("warning_text"), "{html}");
    }

    #[test]
    fn no_remarks_no_section() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(!html.contains("Remarks"), "{html}");
    }

    #[test]
    fn notices_rendered_with_title() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "notices": [{"title": "Terms", "description": ["Accept terms to use"]}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(html.contains("Service Notices"), "{html}");
        assert!(html.contains("Terms"), "{html}");
        assert!(html.contains("Accept terms to use"), "{html}");
        assert!(html.contains("<h2"), "{html}");
        assert!(html.contains("info_text"), "{html}");
    }

    #[test]
    fn notice_falls_back_to_type() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "notices": [{"type": "legal", "description": ["Legal notice"]}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(html.contains("Service Notices"), "{html}");
        assert!(html.contains("legal"), "{html}");
        assert!(html.contains("Legal notice"), "{html}");
        assert!(html.contains("mono_text"), "{html}");
        assert!(html.contains("warning_text"), "{html}");
    }

    #[test]
    fn no_notices_no_section() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(!html.contains("Service Notices"), "{html}");
    }

    #[test]
    fn notices_render_with_links() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "notices": [{
                "title": "Terms",
                "description": ["Accept terms"],
                "links": [{"rel": "terms", "href": "https://example.com/terms"}]
            }]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(html.contains("Service Notices"), "{html}");
        assert!(html.contains("https://example.com/terms"), "{html}");
    }

    #[test]
    fn conformance_section_rendered_with_claims() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "rdapConformance": ["rdap_profile-1.0"]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(
            html.contains("Conformance Claims in Response from rdap.example"),
            "{html}"
        );
        assert!(html.contains("rdap_profile-1.0"), "{html}");
    }

    #[test]
    fn no_conformance_no_section() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(!html.contains("Conformance Claims"), "{html}");
    }
}
