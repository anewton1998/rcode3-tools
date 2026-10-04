/// Wraps the rendered parts in a top-level results container.
pub(crate) fn render(parts: Vec<String>) -> String {
    div("data_result", parts)
}

/// Joins non-empty parts into a classed `<div>`; empty when nothing to show.
pub(crate) fn div(cls: &str, parts: Vec<String>) -> String {
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

/// Renders the object-class heading, optionally followed by a mono name.
pub(crate) fn title(heading: &str, name: Option<&str>) -> String {
    match name {
        Some(n) => format!(
            "<h2 class=\"data_title\">{} {}</h2>",
            escape(heading),
            mono(n)
        ),
        None => format!("<h2 class=\"data_title\">{}</h2>", escape(heading)),
    }
}

/// Renders a titled section; empty when the body is empty.
pub(crate) fn section(title: &str, body: String) -> String {
    if body.is_empty() {
        return String::new();
    }
    format!(
        "<section class=\"data_section\"><h2 class=\"info_text\">{}</h2>{}</section>",
        escape(title),
        body
    )
}

/// Renders a two-column key/value table; empty when there are no rows.
pub(crate) fn kv_table(rows: &[String]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<table class=\"data_table\"><tbody>{}</tbody></table>",
        rows.join("")
    )
}

/// A single key/value table row.
pub(crate) fn row(label: &str, value: &str) -> String {
    format!("<tr><td class=\"data_key\">{label}</td><td>{value}</td></tr>")
}

/// Wraps a value in monospace styling.
pub(crate) fn mono(s: &str) -> String {
    format!("<span class=\"mono_text\">{}</span>", escape(s))
}

/// A clickable in-page action that sets the query value and query type, then
/// triggers a lookup. `display` is pre-rendered inner HTML (trusted static
/// markup only). `value` and `query_type` come from untrusted RDAP responses
/// and are escaped for the single-quoted-JS-string-in-a-double-quoted-HTML-
/// attribute context of the `x-on:click` handler.
pub(crate) fn lookup_action(value: &str, query_type: &str, display: &str) -> String {
    format!(
        "<span class=\"in_page_action\" x-on:click=\"query = '{}'; queryType = '{}'; lookup()\">{}</span>",
        escape_js_attr(value),
        escape_js_attr(query_type),
        display
    )
}

/// Escapes a value for embedding in a single-quoted JS string inside a
/// double-quoted HTML attribute.
///
/// JS-significant characters (`\`, `'`, line breaks) are backslash-escaped,
/// and HTML-significant characters are entity-encoded — the browser decodes
/// the entities before Alpine evaluates the JS, so entity-encoding quotes
/// alone would not be sufficient.
fn escape_js_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\r' => out.push_str("\\r"),
            '\n' | '\u{2028}' | '\u{2029}' => out.push_str("\\n"),
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// The RDAP RIR-search scope icon (an inline SVG) for a given scope name.
///
/// Recognised scopes: `top`, `up`, `down`, `bottom`. Returns an empty string
/// for anything else.
pub(crate) fn rdap_scope_icon(scope: &str) -> &'static str {
    match scope {
        "top" => {
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="rdap-icon rdap-top"><path d="m18 15-6-6-6 6"/><path d="m18 21-6-6-6 6"/><path d="M6 3h12"/></svg>"#
        }
        "up" => {
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="rdap-icon rdap-up"><path d="m18 15-6-6-6 6"/></svg>"#
        }
        "down" => {
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="rdap-icon rdap-down"><path d="m6 9 6 6 6-6"/></svg>"#
        }
        "bottom" => {
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="rdap-icon rdap-bottom"><path d="m6 9 6 6 6-6"/><path d="m6 3 6 6 6-6"/><path d="M6 21h12"/></svg>"#
        }
        _ => "",
    }
}

/// The four RDAP RIR-search scope icon links (top/up/down/bottom) for a
/// value, built on a base query-type code such as `ip_v4_addr`,
/// `ip_v6_cidr`, or `as_number` (the concrete codes are
/// `{base_code}_top`, `{base_code}_up`, `{base_code}_down`,
/// `{base_code}_bottom`).
pub(crate) fn scope_links(value: &str, base_code: &str) -> String {
    ["top", "up", "down", "bottom"]
        .iter()
        .map(|scope| {
            lookup_action(
                value,
                &format!("{base_code}_{scope}"),
                rdap_scope_icon(scope),
            )
        })
        .collect::<String>()
}

/// Renders a value as its lookup link followed by the search glyph
/// `⌕` (U+2315) and the four scope icon links, wrapped in parentheses:
/// `{link} (⌕{icons})`. `display` is the link's pre-rendered inner
/// HTML. Empty values render as plain display text (a lookup on an empty
/// query is meaningless).
pub(crate) fn lookup_with_scopes(value: &str, base_code: &str, display: &str) -> String {
    if value.is_empty() {
        return display.to_string();
    }
    format!(
        "{} (\u{2315}{})",
        lookup_action(value, base_code, display),
        scope_links(value, base_code)
    )
}

/// Address/CIDR convenience wrapper around [`lookup_with_scopes`] where the
/// link simply displays the value itself.
pub(crate) fn addr_with_scopes(value: &str, base_code: &str) -> String {
    lookup_with_scopes(value, base_code, &mono(value))
}

/// Adds a "Unicode Name" row only when it differs from the LDH name.
pub(crate) fn push_unicode(rows: &mut Vec<String>, unicode: Option<&str>, ldh: Option<&str>) {
    if let Some(u) = unicode {
        if u.is_empty() || Some(u) == ldh {
            return;
        }
        rows.push(row("Unicode Name", &mono(u)));
    }
}

/// Escapes an optional deref-to-str value into a plain string.
pub(crate) fn str_opt<T>(o: Option<&T>) -> String
where
    T: std::ops::Deref<Target = str>,
{
    o.map(|s| escape(s)).unwrap_or_default()
}

/// Escapes HTML-significant characters.
pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_action_escapes_double_quotes_in_value() {
        // GIVEN a hostile value trying to break out of the click attribute
        let evil = r#"1.2.3.4" autofocus x-on:mouseover="alert(1)" x-foo="#;

        // WHEN rendered
        let html = lookup_action(evil, "ip_v4_addr", "x");

        // THEN no raw double quote survives and the injected directive is inert
        assert!(html.contains("&quot;"), "{html}");
        assert!(!html.contains("mouseover=\"alert"), "{html}");
    }

    #[test]
    fn lookup_action_escapes_single_quotes_in_value() {
        // GIVEN a value trying to break out of the single-quoted JS string
        let evil = "a'; alert(1); //";

        // WHEN rendered
        let html = lookup_action(evil, "ip_v4_addr", "x");

        // THEN the quote is JS-escaped so the string literal stays intact
        assert!(html.contains(r"query = 'a\'"), "{html}");
    }

    #[test]
    fn lookup_action_escapes_query_type_too() {
        // GIVEN a hostile query type (defense in depth; callers pass static codes)
        let html = lookup_action("1.2.3.4", "bad\"type", "x");

        // WHEN/THEN the quote cannot break the attribute
        assert!(!html.contains("bad\"type"), "{html}");
    }

    #[test]
    fn plain_values_pass_through_unchanged() {
        // GIVEN an ordinary address and code
        let html = lookup_action("192.0.2.1", "ip_v4_addr", "d");

        // WHEN/THEN the action string is exactly as expected
        assert!(
            html.contains("query = '192.0.2.1'; queryType = 'ip_v4_addr'; lookup()"),
            "{html}"
        );
    }

    #[test]
    fn empty_address_renders_plain_text_without_links() {
        // GIVEN an empty address value
        let html = addr_with_scopes("", "ip_v4_addr");

        // WHEN/THEN it renders as plain mono text with no lookup action
        assert_eq!(html, "<span class=\"mono_text\"></span>");
        assert!(!html.contains("lookup()"), "{html}");
    }
}
