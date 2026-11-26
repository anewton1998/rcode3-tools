use askama::Template;

/// A single option in a [`Select`].
pub struct SelectOption<'a> {
    pub value: &'a str,
    pub label: &'a str,
}

/// A labelled group of options, rendered as an HTML `<optgroup>`.
///
/// Used by the static mode of [`Select`] to present options under a heading
/// (e.g. "Bootstrap" / "IANA Registered"). Any options added via
/// [`Select::option`] render as bare `<option>`s *after* the groups, so a
/// trailing "Custom" entry can sit outside every group.
pub struct SelectGroup<'a> {
    pub label: &'a str,
    pub options: Vec<SelectOption<'a>>,
}

/// A dropdown (`<select>`) component.
///
/// Supports three modes:
/// - **Static flat**: options supplied at render time via [`Select::option`].
/// - **Static grouped**: when [`Select::group`]s are present, they render as
///   `<optgroup>`s, followed by any bare [`Select::option`]s (e.g. "Custom").
/// - **Dynamic grouped**: when [`Select::groups_expr`] is set, the options are
///   populated at runtime by Alpine from a JS expression yielding
///   `[{ label, options: [{ code, label }] }]` (rendered as `<optgroup>`s).
#[derive(Template)]
#[template(path = "select.html")]
pub struct Select<'a> {
    pub name: &'a str,
    pub options: Vec<SelectOption<'a>>,
    pub groups: Vec<SelectGroup<'a>>,
    pub selected: Option<&'a str>,
    pub x_model: Option<&'a str>,
    pub groups_expr: Option<&'a str>,
    /// A JS expression bound to `x-bind:disabled` (e.g. `"isUrlType"`).
    /// Must be a plain identifier/getter: askama HTML-escapes `& < > " '`,
    /// so operators and quotes in the expression would break it.
    pub x_bind_disabled: Option<&'a str>,
}

impl<'a> Select<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            options: Vec::new(),
            groups: Vec::new(),
            selected: None,
            x_model: None,
            groups_expr: None,
            x_bind_disabled: None,
        }
    }

    pub fn option(mut self, value: &'a str, label: &'a str) -> Self {
        self.options.push(SelectOption { value, label });
        self
    }

    /// Adds a labelled group of options (rendered as `<optgroup>`). Groups
    /// render before any bare [`Select::option`]s.
    pub fn group(mut self, label: &'a str, options: Vec<SelectOption<'a>>) -> Self {
        self.groups.push(SelectGroup { label, options });
        self
    }

    pub fn selected(mut self, value: &'a str) -> Self {
        self.selected = Some(value);
        self
    }

    pub fn x_model(mut self, expr: &'a str) -> Self {
        self.x_model = Some(expr);
        self
    }

    /// Enables dynamic grouped mode: a JS expression (evaluated by Alpine) that
    /// yields `[{ label, options: [{ code, label }] }]`.
    pub fn groups_expr(mut self, expr: &'a str) -> Self {
        self.groups_expr = Some(expr);
        self
    }

    /// Binds a JS expression to `x-bind:disabled` on the `<select>`.
    pub fn x_bind_disabled(mut self, expr: &'a str) -> Self {
        self.x_bind_disabled = Some(expr);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_options_render_with_selected() {
        let html = Select::new("kind")
            .option("a", "Alpha")
            .option("b", "Beta")
            .selected("b")
            .render()
            .unwrap();
        assert!(html.contains("<select"));
        assert!(html.contains("name=\"kind\""));
        assert!(html.contains("value=\"a\""));
        assert!(html.contains("value=\"b\" selected"));
        assert!(html.contains(">Alpha</option>"));
        assert!(html.contains(">Beta</option>"));
    }

    #[test]
    fn x_model_renders_attribute() {
        let html = Select::new("q").x_model("queryType").render().unwrap();
        assert!(html.contains("x-model=\"queryType\""));
    }

    #[test]
    fn x_bind_disabled_renders_attribute() {
        let html = Select::new("base_url")
            .x_bind_disabled("isUrlType")
            .render()
            .unwrap();
        assert!(html.contains("x-bind:disabled=\"isUrlType\""));
    }

    #[test]
    fn omits_x_bind_disabled_when_unset() {
        let html = Select::new("q").render().unwrap();
        assert!(!html.contains("x-bind:disabled"));
    }

    #[test]
    fn static_groups_render_as_optgroups_with_trailing_bare_option() {
        let html = Select::new("base_url")
            .group(
                "Bootstrap",
                vec![SelectOption {
                    value: "https://b.example",
                    label: "https://b.example",
                }],
            )
            .group(
                "IANA Registered",
                vec![SelectOption {
                    value: "https://a.example",
                    label: "ARIN",
                }],
            )
            .selected("https://a.example")
            .option("custom", "Custom")
            .render()
            .unwrap();
        assert!(html.contains("<optgroup label=\"Bootstrap\">"));
        assert!(html.contains("<optgroup label=\"IANA Registered\">"));
        // label is the tag, value is the URL
        assert!(html.contains("value=\"https://a.example\" selected>ARIN</option>"));
        // the bare Custom option renders after the groups
        assert!(html.contains(">Custom</option>"));
        assert!(html.rfind("IANA Registered").unwrap() < html.rfind(">Custom</option>").unwrap());
    }

    #[test]
    fn dynamic_groups_mode_renders_x_for_template() {
        let html = Select::new("query_type")
            .x_model("queryType")
            .groups_expr("queryTypeGroups")
            .render()
            .unwrap();
        assert!(html.contains("x-model=\"queryType\""));
        assert!(html.contains("x-for=\"g in queryTypeGroups\""));
        assert!(html.contains("x-for=\"o in g.options\""));
        assert!(html.contains(":value=\"o.code\""));
        assert!(html.contains("x-text=\"o.label\""));
        assert!(html.contains("<optgroup"));
        // no static options rendered in dynamic mode
        assert!(!html.contains(">Alpha</option>"));
    }
}
