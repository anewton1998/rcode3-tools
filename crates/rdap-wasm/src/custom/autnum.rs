use icann_rdap_common::prelude::Autnum;

use super::common::append_common;
use super::html::{escape, kv_table, mono, render, row, title};

pub(crate) fn autnum_html(a: &Autnum) -> String {
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
    append_common(&mut parts, oc, &a.common);
    render(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
