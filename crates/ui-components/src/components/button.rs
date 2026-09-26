use askama::Template;

// turf compiles button.scss at compile-time relative to this file
turf::style_sheet!("src/scss/button.scss");

#[derive(Template)]
#[template(path = "button.html")]
pub struct Button<'a> {
    pub label: &'a str,
    pub hx_post: Option<&'a str>,
    pub hx_target: Option<&'a str>,
    pub class_name: &'a str,
    pub style_sheet: &'static str,
}

impl<'a> Button<'a> {
    pub fn new(label: &'a str) -> Self {
        Self {
            label,
            hx_post: None,
            hx_target: None,
            class_name: ClassName::BTN,
            style_sheet: STYLE_SHEET,
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
