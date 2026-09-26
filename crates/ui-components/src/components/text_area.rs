use askama::Template;

#[derive(Template)]
#[template(path = "text_area.html")]
pub struct TextArea<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub rows: u32,
}

impl<'a> TextArea<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            value: "",
            rows: 4,
        }
    }

    pub fn value(mut self, value: &'a str) -> Self {
        self.value = value;
        self
    }

    pub fn rows(mut self, rows: u32) -> Self {
        self.rows = rows;
        self
    }
}
