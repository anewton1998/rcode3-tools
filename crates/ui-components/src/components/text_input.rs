use askama::Template;

#[derive(Template)]
#[template(path = "text_input.html")]
pub struct TextInput<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
    pub placeholder: Option<&'a str>,
    pub enter_activates: Option<&'a str>,
    pub x_model: Option<&'a str>,
}

impl<'a> TextInput<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            value: None,
            placeholder: None,
            enter_activates: None,
            x_model: None,
        }
    }

    pub fn value(mut self, value: &'a str) -> Self {
        self.value = Some(value);
        self
    }

    pub fn placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = Some(placeholder);
        self
    }

    pub fn enter_activates(mut self, selector: &'a str) -> Self {
        self.enter_activates = Some(selector);
        self
    }

    pub fn x_model(mut self, expr: &'a str) -> Self {
        self.x_model = Some(expr);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_activates_renders_attribute_and_handler() {
        let html = TextInput::new("q")
            .enter_activates("#lookup-btn")
            .render()
            .unwrap();
        assert!(html.contains("data-enter-activates=\"#lookup-btn\""));
        assert!(html.contains("onkeydown="));
        assert!(html.contains("dataset.enterActivates"));
    }

    #[test]
    fn omits_handler_when_not_set() {
        let html = TextInput::new("q").render().unwrap();
        assert!(!html.contains("data-enter-activates"));
        assert!(!html.contains("onkeydown"));
    }
}
