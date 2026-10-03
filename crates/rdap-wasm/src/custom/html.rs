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
/// triggers a lookup. `display` is pre-rendered inner HTML.
pub(crate) fn lookup_action(value: &str, query_type: &str, display: &str) -> String {
    format!(
        "<span class=\"in_page_action\" x-on:click=\"query = '{}'; queryType = '{}'; lookup()\">{}</span>",
        escape(value),
        query_type,
        display
    )
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
