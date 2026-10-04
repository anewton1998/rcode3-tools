use chrono::DateTime;

use icann_rdap_common::prelude::{
    Common, Contact, Entity, Events, Links, Nameserver, Notice, ObjectCommon, Remarks,
};

use super::entity::append_entity_body;
use super::html::{
    div, escape, kv_table, lookup_action, mono, off_site_link, row, section, str_opt, title,
};

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
            .map(|s| {
                let escaped = escape(&s.to_string());
                let lower = s.to_string().to_lowercase();
                if lower == "pending delete" || lower == "pending transfer" {
                    format!("<li class=\"error_text\">{}</li>", escaped)
                } else if lower == "inactive" || lower == "client hold" || lower == "server hold" {
                    format!("<li class=\"warning_text\">{}</li>", escaped)
                } else {
                    format!("<li>{}</li>", escaped)
                }
            })
            .collect();
        items.sort();
        if !items.is_empty() {
            let bullets = items
                .iter()
                .map(|item| item.to_string())
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
    for p in contact.phones() {
        let type_str = p
            .contexts
            .as_ref()
            .or(p.features.as_ref())
            .and_then(|types| types.first())
            .map(|t| format!(" ({})", escape(t)))
            .unwrap_or_default();
        rows.push(row("Phone", &format!("{}{}", escape(&p.phone), type_str)));
    }
    kv_table(&rows)
}

/// Renders a domain's nameservers as a simple list.
pub(crate) fn nameserver_list(nameservers: &[Nameserver]) -> String {
    let items = nameservers
        .iter()
        .filter_map(|ns| ns.ldh_name.as_deref())
        .map(|n| format!("<li>{}</li>", lookup_action(n, "nameserver", &mono(n))))
        .collect::<Vec<_>>();
    if items.is_empty() {
        return String::new();
    }
    format!("<ul class=\"data_list\">{}</ul>", items.join(""))
}

fn events_table(events: &Events) -> String {
    let mut rows = Vec::new();
    let mut has_actor = false;
    for e in events.iter() {
        let action = str_opt(e.event_action.as_ref());
        let date = str_opt(e.event_date.as_ref());
        let actor = str_opt(e.event_actor.as_ref());
        let local = parse_event_date_to_local(e.event_date.as_ref());
        if action.is_empty() && date.is_empty() && actor.is_empty() && local.is_empty() {
            continue;
        }
        if !actor.is_empty() {
            has_actor = true;
        }
        let is_expiring_soon =
            is_event_expiring_soon(e.event_action.as_ref(), e.event_date.as_ref());
        rows.push((action, date, actor, local, is_expiring_soon));
    }
    if rows.is_empty() {
        return String::new();
    }
    if has_actor {
        format!(
            "<table class=\"data_table\"><thead><tr><th>Action</th><th>Local</th><th>Date</th><th>Actor</th></tr></thead><tbody>{}</tbody></table>",
            rows.iter().map(|(a, d, ac, l, exp)| {
                let row_class = if *exp { " class=\"warning_text\"" } else { "" };
                format!("<tr{}><td>{}</td><td>{}</td><td class=\"mono_text\">{}</td><td>{}</td></tr>", row_class, a, l, d, ac)
            }).collect::<Vec<_>>().join("")
        )
    } else {
        format!(
            "<table class=\"data_table\"><thead><tr><th>Action</th><th>Local</th><th>Date</th></tr></thead><tbody>{}</tbody></table>",
            rows.iter()
                .map(|(a, d, _, l, exp)| {
                    let row_class = if *exp { " class=\"warning_text\"" } else { "" };
                    format!(
                        "<tr{}><td>{}</td><td>{}</td><td class=\"mono_text\">{}</td></tr>",
                        row_class, a, l, d
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        )
    }
}

fn is_event_expiring_soon(action: Option<&String>, date: Option<&String>) -> bool {
    let action_lower = action
        .as_ref()
        .map(|a| a.to_lowercase())
        .unwrap_or_default();
    if !action_lower.contains("expiration") {
        return false;
    }
    let date_str = match date {
        Some(s) => s,
        None => return false,
    };
    let dt = match DateTime::parse_from_rfc3339(date_str) {
        Ok(dt) => dt.with_timezone(&chrono::Local),
        Err(_) => return false,
    };
    let now = chrono::Local::now();
    let diff = (dt - now).num_days();
    (0..30).contains(&diff)
}

fn parse_event_date_to_local(date: Option<&String>) -> String {
    let date_str = match date {
        Some(s) => s,
        None => return String::new(),
    };
    let dt = match DateTime::parse_from_rfc3339(date_str) {
        Ok(dt) => dt.with_timezone(&chrono::Local),
        Err(_) => return date_str.to_string(),
    };
    dt.format("%d %b %Y at %l:%M %P").to_string()
}

/// True when a link's media type is the RDAP JSON media type (ignoring any
/// trailing `;` parameters), case-insensitively.
fn is_rdap_json(media: Option<&str>) -> bool {
    has_base_media(media, "application/rdap+json")
}

/// True when a link's media type is `text/html` (ignoring any trailing `;`
/// parameters), case-insensitively.
fn is_html_media(media: Option<&str>) -> bool {
    has_base_media(media, "text/html")
}

/// Compares a media type's base (before any `;` parameters) against
/// `expected`, case-insensitively.
fn has_base_media(media: Option<&str>, expected: &str) -> bool {
    match media {
        Some(m) => {
            let base = m.split(';').next().unwrap_or("").trim();
            base.eq_ignore_ascii_case(expected)
        }
        None => false,
    }
}

fn links_table(links: &Links) -> String {
    let mut rows = Vec::new();
    for l in links.iter() {
        let rel = str_opt(l.rel.as_ref());
        let media = str_opt(l.media_type.as_ref());
        let url = match l.href.as_deref().or(l.value.as_deref()) {
            Some(u) if is_rdap_json(l.media_type.as_deref()) => lookup_action(u, "url", &mono(u)),
            Some(u) if is_html_media(l.media_type.as_deref()) => off_site_link(u),
            Some(u) => mono(u),
            None => String::new(),
        };
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
    fn nameserver_link_sets_query_and_query_type() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "nameservers": [{"objectClassName": "nameserver", "ldhName": "ns1.example.com"}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(
            html.contains("query = 'ns1.example.com'; queryType = 'nameserver'; lookup()"),
            "{html}"
        );
    }

    #[test]
    fn rdap_json_link_is_a_url_lookup_link() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "links": [
                {"rel": "self", "type": "application/rdap+json", "href": "https://rdap.example/domain/example.com"},
                {"rel": "related", "type": "text/html", "href": "https://example.com/whois"}
            ]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(
            html.contains(
                "query = 'https://rdap.example/domain/example.com'; queryType = 'url'; lookup()"
            ),
            "{html}"
        );
        // a non-rdap+json link stays plain text (no lookup action)
        assert!(html.contains("https://example.com/whois"), "{html}");
        assert!(
            !html.contains("query = 'https://example.com/whois'"),
            "non-rdap+json link should not be a lookup link: {html}"
        );
    }

    #[test]
    fn html_link_renders_as_off_site_anchor() {
        // GIVEN a link whose media type is text/html
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "links": [
                {"rel": "related", "type": "text/html", "href": "https://example.com/whois"}
            ]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN it is an anchor opening a new tab, not an in-page lookup
        assert!(
            html.contains(
                "<a class=\"off_site_link\" href=\"https://example.com/whois\" target=\"_blank\" rel=\"noopener noreferrer\">"
            ),
            "{html}"
        );
        assert!(
            !html.contains("query = 'https://example.com/whois'"),
            "{html}"
        );
    }

    #[test]
    fn html_media_type_with_parameters_is_still_off_site() {
        // GIVEN text/html with a trailing charset parameter
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "links": [
                {"rel": "related", "type": "text/html; charset=UTF-8", "href": "https://example.com/x"}
            ]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN it still renders as an off-site anchor
        assert!(html.contains("class=\"off_site_link\""), "{html}");
        assert!(html.contains("target=\"_blank\""), "{html}");
    }

    #[test]
    fn off_site_link_escapes_quotes_and_ampersands_in_href() {
        // GIVEN a hostile URL containing a double quote and an ampersand
        let html = super::off_site_link("https://example.com/a\"b&c");

        // WHEN/THEN the href attribute cannot be broken out of
        assert!(
            html.contains("href=\"https://example.com/a&quot;b&amp;c\""),
            "{html}"
        );
        assert!(
            !html.contains("href=\"https://example.com/a\""),
            "raw quote leaked into the href attribute: {html}"
        );
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

    #[test]
    fn events_table_without_actor() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(html.contains("Events"), "{html}");
        assert!(html.contains("registration"), "{html}");
        assert!(!html.contains("<th>Actor</th>"), "{html}");
    }

    #[test]
    fn events_table_with_actor() {
        let json = r#"{
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z", "eventActor": "Example Corp"}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain, "rdap.example");
        assert!(html.contains("Events"), "{html}");
        assert!(html.contains("registration"), "{html}");
        assert!(html.contains("<th>Actor</th>"), "{html}");
        assert!(html.contains("Example Corp"), "{html}");
    }

    #[test]
    fn is_event_expiring_soon_returns_true_for_near_future() {
        let future_date =
            (chrono::Local::now() + chrono::TimeDelta::try_days(10).unwrap()).to_rfc3339();
        assert!(super::is_event_expiring_soon(
            Some(&"expiration".to_string()),
            Some(&future_date)
        ));
    }

    #[test]
    fn is_event_expiring_soon_returns_false_for_past() {
        let past_date = "2020-01-01T00:00:00Z";
        assert!(!super::is_event_expiring_soon(
            Some(&"expiration".to_string()),
            Some(&past_date.to_string())
        ));
    }

    #[test]
    fn is_event_expiring_soon_returns_false_for_far_future() {
        let far_future_date =
            (chrono::Local::now() + chrono::TimeDelta::try_days(90).unwrap()).to_rfc3339();
        assert!(!super::is_event_expiring_soon(
            Some(&"expiration".to_string()),
            Some(&far_future_date)
        ));
    }

    #[test]
    fn is_event_expiring_soon_returns_false_for_non_expiration() {
        let future_date = "2026-10-01T00:00:00Z";
        assert!(!super::is_event_expiring_soon(
            Some(&"registration".to_string()),
            Some(&future_date.to_string())
        ));
    }

    #[test]
    fn is_event_expiring_soon_returns_false_for_no_date() {
        assert!(!super::is_event_expiring_soon(
            Some(&"expiration".to_string()),
            None
        ));
    }
}
