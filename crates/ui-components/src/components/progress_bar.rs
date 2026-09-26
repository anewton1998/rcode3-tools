use askama::Template;

#[derive(Template)]
#[template(path = "progress_bar.html")]
pub struct ProgressBar;
