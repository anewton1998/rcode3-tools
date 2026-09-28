#[derive(Clone, Copy)]
pub enum Theme {
    GreenOnBlack,
    GreenOnBlackWithAmber,
    BlackOnLightGray,
    BlackOnWhite,
    BlackOnWhiteWithRed,
    BlackOnWhiteWithGreen,
    WhiteOnBlue,
    WhiteOnBlueWithGreen,
    AmberOnBlack,
    AmberOnBlackWithBlue,
    BlueOnWhite,
    BlueOnBlack,
    Tandy400,
    Botho,
}

impl Theme {
    pub const DEFAULT: Theme = Theme::GreenOnBlack;

    pub fn class_name(self) -> &'static str {
        match self {
            Theme::GreenOnBlack => "theme_green_on_black",
            Theme::GreenOnBlackWithAmber => "theme_green_on_black_with_amber",
            Theme::BlackOnLightGray => "theme_black_on_light_gray",
            Theme::BlackOnWhite => "theme_black_on_white",
            Theme::BlackOnWhiteWithRed => "theme_black_on_white_with_red",
            Theme::BlackOnWhiteWithGreen => "theme_black_on_white_with_green",
            Theme::WhiteOnBlue => "theme_white_on_blue",
            Theme::WhiteOnBlueWithGreen => "theme_white_on_blue_with_green",
            Theme::AmberOnBlack => "theme_amber_on_black",
            Theme::AmberOnBlackWithBlue => "theme_amber_on_black_with_blue",
            Theme::BlueOnWhite => "theme_blue_on_white",
            Theme::BlueOnBlack => "theme_blue_on_black",
            Theme::Tandy400 => "theme_tandy_400",
            Theme::Botho => "theme_botho",
        }
    }

    pub fn all() -> &'static [Theme] {
        &[
            Theme::GreenOnBlack,
            Theme::GreenOnBlackWithAmber,
            Theme::BlackOnLightGray,
            Theme::BlackOnWhite,
            Theme::BlackOnWhiteWithRed,
            Theme::BlackOnWhiteWithGreen,
            Theme::WhiteOnBlue,
            Theme::WhiteOnBlueWithGreen,
            Theme::AmberOnBlack,
            Theme::AmberOnBlackWithBlue,
            Theme::BlueOnWhite,
            Theme::BlueOnBlack,
            Theme::Tandy400,
            Theme::Botho,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            Theme::GreenOnBlack => "Green on black",
            Theme::GreenOnBlackWithAmber => "Green on black (amber)",
            Theme::BlackOnLightGray => "Black on light gray",
            Theme::BlackOnWhite => "Black on white",
            Theme::BlackOnWhiteWithRed => "Black on white (red)",
            Theme::BlackOnWhiteWithGreen => "Black on white (green)",
            Theme::WhiteOnBlue => "White on blue",
            Theme::WhiteOnBlueWithGreen => "White on blue (green)",
            Theme::AmberOnBlack => "Amber on black",
            Theme::AmberOnBlackWithBlue => "Amber on black (blue)",
            Theme::BlueOnWhite => "Blue on white",
            Theme::BlueOnBlack => "Blue on black",
            Theme::Tandy400 => "Tandy 400",
            Theme::Botho => "Botho",
        }
    }

    pub fn from_env() -> Self {
        std::env::var("THEME")
            .ok()
            .and_then(|value| Self::from_name(&value))
            .unwrap_or(Self::DEFAULT)
    }

    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.strip_prefix("theme_").unwrap_or(name);
        Some(match name {
            "green_on_black" => Theme::GreenOnBlack,
            "green_on_black_with_amber" => Theme::GreenOnBlackWithAmber,
            "black_on_light_gray" => Theme::BlackOnLightGray,
            "black_on_white" => Theme::BlackOnWhite,
            "black_on_white_with_red" => Theme::BlackOnWhiteWithRed,
            "black_on_white_with_green" => Theme::BlackOnWhiteWithGreen,
            "white_on_blue" => Theme::WhiteOnBlue,
            "white_on_blue_with_green" => Theme::WhiteOnBlueWithGreen,
            "amber_on_black" => Theme::AmberOnBlack,
            "amber_on_black_with_blue" => Theme::AmberOnBlackWithBlue,
            "blue_on_white" => Theme::BlueOnWhite,
            "blue_on_black" => Theme::BlueOnBlack,
            "tandy_400" => Theme::Tandy400,
            "botho" => Theme::Botho,
            _ => return None,
        })
    }
}
