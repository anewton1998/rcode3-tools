use icann_rdap_client::rdap::ResponseData;
use icann_rdap_client::RdapClientError;
use icann_rdap_common::prelude::RdapResponse;

/// Human-readable message for an HTTP-level RDAP error response.
pub fn http_error_message(data: &ResponseData) -> String {
    let code = data.http_data.status_code;
    if let RdapResponse::ErrorResponse(err) = &data.rdap {
        rdap_error_text(code, err.title.as_ref().map(|t| t.to_string()))
    } else {
        format!("HTTP {code}")
    }
}

/// Human-readable message for a client lookup error.
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
