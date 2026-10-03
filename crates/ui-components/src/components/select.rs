use askama::Template;

/// A single option in a [`Select`].
pub struct SelectOption<'a> {
    pub value: &'a str,
    pub label: &'a str,
}

/// A dropdown (`<select>`) component.
///
/// Supports two modes:
/// - **Static**: options supplied at render time via [`Select::option`].
/// - **Dynamic grouped**: when [`Select::groups_expr`] is set, the options are
///   populated at runtime by Alpine from a JS expression yielding
///   `[{ label, options: [{ code, label }] }]` (rendered as `<optgroup>`s).
#[derive(Template)]
#[template(path = "select.html")]
pub struct Select<'a> {
    pub name: &'a str,
    pub options: Vec<SelectOption<'a>>,
    pub selected: Option<&'a str>,
    pub x_model: Option<&'a str>,
    pub groups_expr: Option<&'a str>,
}

impl<'a> Select<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            options: Vec::new(),
            selected: None,
            x_model: None,
            groups_expr: None,
        }
    }

    pub fn option(mut self, value: &'a str, label: &'a str) -> Self {
        self.options.push(SelectOption { value, label });
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
