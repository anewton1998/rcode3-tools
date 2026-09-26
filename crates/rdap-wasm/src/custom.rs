use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::response::{Domain, RdapResponse};

pub fn domain_summary_html(data: &ResponseData) -> String {
    match &data.rdap {
        RdapResponse::Domain(domain) => domain_html(domain),
        other => format!("<span class=\"info_text\">{other}</span>"),
    }
}

fn domain_html(domain: &Domain) -> String {
    let name = domain.ldh_name.clone().unwrap_or_default();
    let mut parts: Vec<String> = vec![format!("<span class=\"mono_text\">{name}</span>")];

    if let Some(handle) = &domain.object_common.handle {
        parts.push(format!("<span class=\"info_text\">handle: {handle}</span>"));
    }

    if let Some(status) = &domain.object_common.status {
        for s in status.vec().iter() {
            parts.push(format!("<span>{s}</span>"));
        }
    }

    if let Some(events) = &domain.object_common.events {
        for event in events.iter() {
            if let (Some(action), Some(date)) = (&event.event_action, &event.event_date) {
                parts.push(format!("<span class=\"info_text\">{action}: {date}</span>"));
            }
        }
    }

    format!("<div>{}</div>", parts.join(" "))
}
