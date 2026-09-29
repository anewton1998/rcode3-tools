use icann_rdap_client::rdap::ResponseData;
use icann_rdap_client::RdapClientError;
use icann_rdap_common::response::{Domain, RdapResponse};

pub fn domain_summary_html(data: &ResponseData) -> String {
    match &data.rdap {
        RdapResponse::Domain(domain) => domain_table(domain),
        other => format!(
            "<span class=\"info_text\">{}</span>",
            escape(&other.to_string())
        ),
    }
}

fn domain_table(domain: &Domain) -> String {
    let mut rows: Vec<String> = Vec::new();

    if let Some(name) = &domain.ldh_name {
        rows.push(row(
            "Name",
            &format!("<span class=\"mono_text\">{}</span>", escape(name)),
        ));
    }

    if let Some(handle) = &domain.object_common.handle {
        rows.push(row("Handle", &escape(handle)));
    }

    if let Some(status) = &domain.object_common.status {
        let items: Vec<String> = status
            .vec()
            .iter()
            .map(|s| escape(&s.to_string()))
            .collect();
        if !items.is_empty() {
            rows.push(row("Status", &items.join(", ")));
        }
    }

    if let Some(events) = &domain.object_common.events {
        for event in events.iter() {
            if let (Some(action), Some(date)) = (&event.event_action, &event.event_date) {
                rows.push(row(
                    &escape(&action.to_string()),
                    &escape(&date.to_string()),
                ));
            }
        }
    }

    if rows.is_empty() {
        return "<p class=\"info_text\">No details available.</p>".to_string();
    }

    format!(
        "<table class=\"data_table\"><tbody>{}</tbody></table>",
        rows.join("")
    )
}

fn row(label: &str, value: &str) -> String {
    format!("<tr><th scope=\"row\">{label}</th><td>{value}</td></tr>")
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
}
