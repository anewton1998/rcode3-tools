pub mod components {
    pub mod button;
    pub mod link_nav;
    pub mod progress_bar;
    pub mod status_text;
    pub mod text_area;
    pub mod text_input;
}

pub mod theme;

pub use components::button::Button;
pub use components::link_nav::{LinkNav, NavItem};
pub use components::progress_bar::ProgressBar;
pub use components::status_text::{StatusLevel, StatusText};
pub use components::text_area::TextArea;
pub use components::text_input::TextInput;
pub use theme::Theme;

pub fn global_css() -> &'static str {
    concat!(
        include_str!("../css/rcode3.css"),
        "\n",
        include_str!("../css/app.css")
    )
}
