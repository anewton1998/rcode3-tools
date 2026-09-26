use askama::Template;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StatusLevel {
    Info,
    Warning,
    Error,
}

impl StatusLevel {
    pub fn class_name(self) -> &'static str {
        match self {
            StatusLevel::Info => "info_text",
            StatusLevel::Warning => "warning_text",
            StatusLevel::Error => "error_text",
        }
    }
}

#[derive(Template)]
#[template(path = "status_text.html")]
pub struct StatusText<'a> {
    pub level: StatusLevel,
    pub text: &'a str,
    pub loading: bool,
}

impl<'a> StatusText<'a> {
    pub fn info(text: &'a str) -> Self {
        Self::new(StatusLevel::Info, text)
    }

    pub fn warning(text: &'a str) -> Self {
        Self::new(StatusLevel::Warning, text)
    }

    pub fn error(text: &'a str) -> Self {
        Self::new(StatusLevel::Error, text)
    }

    pub fn new(level: StatusLevel, text: &'a str) -> Self {
        Self {
            level,
            text,
            loading: false,
        }
    }

    pub fn loading(mut self) -> Self {
        self.loading = true;
        self
    }
}
