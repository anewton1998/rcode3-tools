use askama::Template;

#[derive(Template)]
#[template(path = "text_input.html")]
pub struct TextInput<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
    pub placeholder: Option<&'a str>,
}

impl<'a> TextInput<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            value: None,
            placeholder: None,
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
}
