use icann_rdap_client::rdap::ResponseData;
use icann_rdap_client::RdapClientError;
use icann_rdap_common::prelude::{
    Autnum, Contact, Domain, Entity, Events, Links, Nameserver, Network, ObjectCommon, RdapResponse,
};

/// Renders the results-panel HTML for any supported RDAP response.
pub fn render_response_html(data: &ResponseData) -> String {
    match &data.rdap {
        RdapResponse::Domain(domain) => domain_html(domain),
        RdapResponse::Nameserver(nameserver) => nameserver_html(nameserver),
        RdapResponse::Network(network) => network_html(network),
        RdapResponse::Autnum(autnum) => autnum_html(autnum),
        RdapResponse::Entity(entity) => entity_html(entity),
        other => format!(
            "<span class=\"info_text\">{}</span>",
            escape(&other.to_string())
        ),
    }
}

// ---------------------------------------------------------------------------
// Per-object-class renderers
// ---------------------------------------------------------------------------

fn domain_html(domain: &Domain) -> String {
    let oc = &domain.object_common;
    let mut summary = Vec::new();
    if let Some(name) = domain.ldh_name.as_deref() {
        summary.push(row("Name", &mono(name)));
    }
    push_unicode(
        &mut summary,
        domain.unicode_name.as_deref(),
        domain.ldh_name.as_deref(),
    );
    if let Some(handle) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(handle)));
    }

    let mut parts = vec![
        title("Domain", domain.ldh_name.as_deref()),
        kv_table(&summary),
    ];
    if let Some(nameservers) = &domain.nameservers {
        parts.push(section("Nameservers", nameserver_list(nameservers)));
    }
    append_common(&mut parts, oc);
    render(parts)
}

fn nameserver_html(ns: &Nameserver) -> String {
    let oc = &ns.object_common;
    let mut summary = Vec::new();
    if let Some(name) = ns.ldh_name.as_deref() {
        summary.push(row("Name", &mono(name)));
    }
    push_unicode(
        &mut summary,
        ns.unicode_name.as_deref(),
        ns.ldh_name.as_deref(),
    );
    if let Some(ip) = &ns.ip_addresses {
        if let Some(v4) = &ip.v4 {
            let items = v4
                .vec()
                .iter()
                .map(|s| escape(&s.to_string()))
                .collect::<Vec<_>>();
            if !items.is_empty() {
                summary.push(row("IPv4", &mono(&items.join(", "))));
            }
        }
        if let Some(v6) = &ip.v6 {
            let items = v6
                .vec()
                .iter()
                .map(|s| escape(&s.to_string()))
                .collect::<Vec<_>>();
            if !items.is_empty() {
                summary.push(row("IPv6", &mono(&items.join(", "))));
            }
        }
    }
    if let Some(handle) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(handle)));
    }

    let mut parts = vec![
        title("Nameserver", ns.ldh_name.as_deref()),
        kv_table(&summary),
    ];
    append_common(&mut parts, oc);
    render(parts)
}

fn network_html(net: &Network) -> String {
    let oc = &net.object_common;
    let label = net.name.as_deref().or(net.start_address.as_deref());
    let mut summary = Vec::new();
    if let Some(s) = net.start_address.as_deref() {
        summary.push(row("Start Address", &mono(s)));
    }
    if let Some(e) = net.end_address.as_deref() {
        summary.push(row("End Address", &mono(e)));
    }
    if let Some(v) = net.ip_version.as_deref() {
        summary.push(row("IP Version", &escape(v)));
    }
    if let Some(t) = net.network_type.as_deref() {
        summary.push(row("Type", &escape(t)));
    }
    if let Some(p) = net.parent_handle.as_deref() {
        summary.push(row("Parent Handle", &mono(p)));
    }
    if let Some(h) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(h)));
    }

    let mut parts = vec![title("Network", label), kv_table(&summary)];
    append_common(&mut parts, oc);
    render(parts)
}

fn autnum_html(a: &Autnum) -> String {
    let oc = &a.object_common;
    let start = a.start_autnum.as_ref().and_then(|n| n.as_u32());
    let end = a.end_autnum.as_ref().and_then(|n| n.as_u32());
    let label = start.map(|s| format!("AS{s}"));

    let mut summary = Vec::new();
    if let Some(s) = start {
        summary.push(row("Start AS", &mono(&format!("AS{s}"))));
    }
    if let Some(e) = end.filter(|e| *e != start.unwrap_or(0)) {
        summary.push(row("End AS", &mono(&format!("AS{e}"))));
    }
    if let Some(n) = a.name.as_deref() {
        summary.push(row("Name", &escape(n)));
    }
    if let Some(t) = a.autnum_type.as_deref() {
        summary.push(row("Type", &escape(t)));
    }
    if let Some(c) = a.country.as_deref() {
        summary.push(row("Country", &escape(c)));
    }
    if let Some(h) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(h)));
    }

    let mut parts = vec![title("Autnum", label.as_deref()), kv_table(&summary)];
    append_common(&mut parts, oc);
    render(parts)
}

fn entity_html(entity: &Entity) -> String {
    let label = entity_label(entity);
    let mut parts = vec![title("Entity", label.as_deref())];
    append_entity_body(&mut parts, entity);
    render(parts)
}

fn append_entity_body(parts: &mut Vec<String>, entity: &Entity) {
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
    append_common(parts, oc);
}

// ---------------------------------------------------------------------------
// Shared (object-common) sections, reused across every object class
// ---------------------------------------------------------------------------

fn append_common(parts: &mut Vec<String>, oc: &ObjectCommon) {
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

fn contact_rows(contact: &Contact) -> String {
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

fn nameserver_list(nameservers: &[Nameserver]) -> String {
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

// ---------------------------------------------------------------------------
// Small HTML helpers
// ---------------------------------------------------------------------------

fn render(parts: Vec<String>) -> String {
    div("rdap_result", parts)
}

fn div(cls: &str, parts: Vec<String>) -> String {
    let inner = parts
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("");
    if inner.is_empty() {
        return String::new();
    }
    format!("<div class=\"{cls}\">{inner}</div>")
}

fn title(heading: &str, name: Option<&str>) -> String {
    match name {
        Some(n) => format!(
            "<h2 class=\"rdap_type_title\">{} {}</h2>",
            escape(heading),
            mono(n)
        ),
        None => format!("<h2 class=\"rdap_type_title\">{}</h2>", escape(heading)),
    }
}

fn section(title: &str, body: String) -> String {
    if body.is_empty() {
        return String::new();
    }
    format!(
        "<section class=\"rdap_section\"><h3>{}</h3>{}</section>",
        escape(title),
        body
    )
}

fn kv_table(rows: &[String]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<table class=\"data_table\"><tbody>{}</tbody></table>",
        rows.join("")
    )
}

fn row(label: &str, value: &str) -> String {
    format!("<tr><th scope=\"row\">{label}</th><td>{value}</td></tr>")
}

fn mono(s: &str) -> String {
    format!("<span class=\"mono_text\">{}</span>", escape(s))
}

fn entity_label(entity: &Entity) -> Option<String> {
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

fn push_unicode(rows: &mut Vec<String>, unicode: Option<&str>, ldh: Option<&str>) {
    if let Some(u) = unicode {
        if u.is_empty() || Some(u) == ldh {
            return;
        }
        rows.push(row("Unicode Name", &mono(u)));
    }
}

fn str_opt<T>(o: Option<&T>) -> String
where
    T: std::ops::Deref<Target = str>,
{
    o.map(|s| escape(s)).unwrap_or_default()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn http_error_message(data: &ResponseData) -> String {
    let code = data.http_data.status_code;
    if let RdapResponse::ErrorResponse(err) = &data.rdap {
        rdap_error_text(code, err.title.as_ref().map(|t| t.to_string()))
    } else {
        format!("HTTP {code}")
    }
}

pub fn describe_error(e: &RdapClientError) -> String {
    if let RdapClientError::ParsingError(info) = e {
        format!(
            "HTTP {} - no valid RDAP response",
            info.http_data.status_code
        )
    } else {
        e.to_string()
    }
}

fn rdap_error_text(status_code: u16, title: Option<String>) -> String {
    match title {
        Some(t) => format!("RDAP error {}: {}", status_code, t),
        None => format!("RDAP error {}", status_code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdap_error_text_includes_status_code() {
        assert_eq!(rdap_error_text(404, None), "RDAP error 404");
        assert_eq!(
            rdap_error_text(404, Some("Not Found".to_string())),
            "RDAP error 404: Not Found"
        );
    }

    #[test]
    fn domain_renders_summary_and_sections() {
        let json = r#"{
            "objectClassName": "domain",
            "handle": "EXAMPLE-COM",
            "ldhName": "example.com",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
            "nameservers": [{"objectClassName": "nameserver", "ldhName": "ns1.example.com"}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain);
        assert!(html.contains("rdap_type_title"), "{html}");
        assert!(html.contains("<th scope=\"row\">Name</th>"), "{html}");
        assert!(html.contains("example.com"), "{html}");
        assert!(html.contains(">Status<"), "{html}");
        assert!(html.contains("Nameservers"), "{html}");
    }

    #[test]
    fn nameserver_renders_ip_addresses() {
        let json = r#"{
            "objectClassName": "nameserver",
            "handle": "NS1-X",
            "ldhName": "ns1.example.com",
            "status": ["active"],
            "ipAddresses": {"v4": ["192.0.2.1"], "v6": ["2001:db8::1"]}
        }"#;
        let ns: Nameserver = serde_json::from_str(json).unwrap();
        let html = nameserver_html(&ns);
        assert!(html.contains("IPv4"), "{html}");
        assert!(html.contains("192.0.2.1"), "{html}");
        assert!(html.contains("IPv6"), "{html}");
    }

    #[test]
    fn network_renders_addresses() {
        let json = r#"{
            "objectClassName": "network",
            "handle": "NET-1",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "4",
            "name": "TEST-NET-1",
            "type": "allocation"
        }"#;
        let net: Network = serde_json::from_str(json).unwrap();
        let html = network_html(&net);
        assert!(html.contains("Start Address"), "{html}");
        assert!(html.contains("192.0.2.0"), "{html}");
        assert!(html.contains("TEST-NET-1"), "{html}");
    }

    #[test]
    fn autnum_renders_as_numbers() {
        let json = r#"{
            "objectClassName": "autnum",
            "handle": "AS15169",
            "startAutnum": 15169,
            "endAutnum": 15169,
            "name": "GOOGLE",
            "type": "allocation",
            "country": "US"
        }"#;
        let a: Autnum = serde_json::from_str(json).unwrap();
        let html = autnum_html(&a);
        assert!(html.contains("Start AS"), "{html}");
        assert!(html.contains("AS15169"), "{html}");
        assert!(html.contains("GOOGLE"), "{html}");
    }

    #[test]
    fn entity_renders_roles_and_handle() {
        let json = r#"{
            "objectClassName": "entity",
            "handle": "299",
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA ID", "identifier": "299"}]
        }"#;
        let entity: Entity = serde_json::from_str(json).unwrap();
        let html = entity_html(&entity);
        assert!(html.contains("Roles"), "{html}");
        assert!(html.contains("registrar"), "{html}");
        assert!(html.contains("299"), "{html}");
    }
}
