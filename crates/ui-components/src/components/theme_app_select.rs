use askama::Template;

use crate::theme::Theme;

/// Single source of truth for the app switcher.
///
/// Every app that renders [`ThemeAppSelect`] shows exactly this list, so adding a
/// new app is a one-line change here rather than a per-app edit. The URLs assume
/// the merged gateway topology (home at `/`, RDAP Explorer at `/rdap-explorer`).
pub const APP_LINKS: &[(&str, &str)] =
    &[("RDAP Explorer", "/rdap-explorer"), ("rcode3 tools", "/")];

/// A single app entry in the switcher.
pub struct AppLink<'a> {
    pub label: &'a str,
    pub url: &'a str,
}

/// A combined "theme + apps" control for the site banner.
///
/// Renders two synchronised views from the same data, toggled by a CSS media
/// query at 700px:
/// - **Wide screens**: a single `<select>` with a *Theme* group and an *Apps*
///   group. App options carry a `data-app` attribute so the shared JS can tell
///   a navigation apart from a theme change.
/// - **Narrow screens**: a hamburger button that opens a dropdown listing the
///   apps (plain links) and the themes (buttons carrying `data-theme`).
///
/// Theme application and navigation are handled by `assets/js/theme_app_select.js`;
/// this component only produces the markup.
#[derive(Template)]
#[template(path = "theme_app_select.html")]
pub struct ThemeAppSelect<'a> {
    pub themes: &'a [Theme],
    pub apps: Vec<AppLink<'a>>,
}

impl<'a> ThemeAppSelect<'a> {
    /// Builds the control with all themes and the [`APP_LINKS`] app list.
    pub fn new() -> Self {
        Self {
            themes: Theme::all(),
            apps: APP_LINKS
                .iter()
                .map(|(label, url)| AppLink { label, url })
                .collect(),
        }
    }
}

impl Default for ThemeAppSelect<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_theme_and_app_groups() {
        let html = ThemeAppSelect::new().render().unwrap();
        // Wide-screen select with both groups.
        assert!(html.contains("class=\"theme_app_select rcode3_select\""));
        assert!(html.contains("<optgroup label=\"Theme\">"));
        assert!(html.contains("<optgroup label=\"Apps\">"));
        // Every theme is offered as an option keyed by its class name.
        assert!(html.contains("value=\"theme_green_on_black\""));
        assert!(html.contains("value=\"theme_botho\""));
    }

    #[test]
    fn app_options_carry_data_app_for_navigation() {
        let html = ThemeAppSelect::new().render().unwrap();
        for (label, url) in APP_LINKS {
            assert!(
                html.contains(&format!("data-app=\"{url}\"")) && html.contains(label),
                "expected app option for {label} -> {url}"
            );
        }
    }

    #[test]
    fn renders_hamburger_and_menu() {
        let html = ThemeAppSelect::new().render().unwrap();
        assert!(html.contains("class=\"theme_app_burger\""));
        assert!(html.contains("id=\"theme_app_menu\""));
        // Narrow-screen menu exposes app links and theme buttons.
        assert!(html.contains("class=\"theme_app_menu_apps\""));
        assert!(html.contains("class=\"theme_app_menu_themes\""));
        assert!(html.contains("data-theme=\"theme_botho\""));
    }
}
