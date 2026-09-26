pub mod components {
    pub mod button;
}

pub use components::button::Button;

// Global base CSS. Compiled with plain grass (no class renaming), so it can
// style classes added at runtime by htmx/alpine that turf would otherwise scope.
pub fn global_base_css() -> Result<String, Box<grass::Error>> {
    let scss = r#"
        body { margin: 0; font-family: system-ui, sans-serif; }
        * { box-sizing: border-box; }

        .htmx-request {
            opacity: 0.6;
            pointer-events: none;
        }

        .status-message {
            color: #15803d;
            font-size: 0.875rem;
        }
    "#;
    grass::from_string(scss, &grass::Options::default())
}
