pub mod components {
    pub mod button;
}

pub use components::button::Button;

// Optional: Provide a function to get global base CSS using grass
pub fn global_base_css() -> Result<String, grass::Error> {
    let scss = r#"
        body { margin: 0; font-family: system-ui, sans-serif; }
        * { box-sizing: border-box; }
    "#;
    grass::from_string(scss, &grass::Options::default())
}
