use askama::Template;

#[derive(Template)]
#[template(path = "button.html")]
pub struct Button<'a> {
    pub label: &'a str,
    pub hx_post: Option<&'a str>,
    pub hx_target: Option<&'a str>,
}

impl<'a> Button<'a> {
    pub fn new(label: &'a str) -> Self {
        Self {
            label,
            hx_post: None,
            hx_target: None,
        }
    }

    pub fn hx_post(mut self, url: &'a str) -> Self {
        self.hx_post = Some(url);
        self
    }

    pub fn hx_target(mut self, target: &'a str) -> Self {
        self.hx_target = Some(target);
        self
    }
}
