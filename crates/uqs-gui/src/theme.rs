//! Design tokens and widget styles.
//!
//! One warm paper, one ink, one accent (deep green) — nothing else carries colour.
//! Every style below reads from these tokens; no widget inlines a colour of its own.

use iced::border::{self, Border};
use iced::theme::Palette;
use iced::widget::{button, container, progress_bar, svg, text_input};
use iced::{Background, Color, Shadow, Theme, Vector};

// --- tokens -------------------------------------------------------------------------

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 12.0;
pub const SPACE_LG: f32 = 20.0;
pub const SPACE_XL: f32 = 32.0;

pub const TEXT_DISPLAY: f32 = 26.0;
pub const TEXT_TITLE: f32 = 17.0;
pub const TEXT_BODY: f32 = 14.0;
pub const TEXT_CAPTION: f32 = 12.0;
pub const TEXT_PIN: f32 = 30.0;

pub const RADIUS_CARD: f32 = 12.0;
pub const RADIUS_CONTROL: f32 = 8.0;
pub const RADIUS_PILL: f32 = 999.0;

const LIGHT: Palette = Palette {
    background: Color::from_rgb8(0xF6, 0xF4, 0xEF), // warm paper
    text: Color::from_rgb8(0x1C, 0x1B, 0x19),       // ink
    primary: Color::from_rgb8(0x2F, 0x6F, 0x5E),    // the one accent
    success: Color::from_rgb8(0x2F, 0x6F, 0x5E),
    warning: Color::from_rgb8(0xB7, 0x79, 0x1F),
    danger: Color::from_rgb8(0xB4, 0x23, 0x18),
};

const DARK: Palette = Palette {
    background: Color::from_rgb8(0x17, 0x19, 0x1B),
    text: Color::from_rgb8(0xEC, 0xEA, 0xE4),
    primary: Color::from_rgb8(0x6F, 0xBF, 0xA3),
    success: Color::from_rgb8(0x6F, 0xBF, 0xA3),
    warning: Color::from_rgb8(0xE0, 0xA4, 0x3E),
    danger: Color::from_rgb8(0xE5, 0x6A, 0x5C),
};

pub fn light() -> Theme {
    Theme::custom("UQS Light", LIGHT)
}

pub fn dark() -> Theme {
    Theme::custom("UQS Dark", DARK)
}

/// Secondary ink: body text that should recede (captions, hints).
pub fn muted(theme: &Theme) -> Color {
    theme.extended_palette().background.base.text.scale_alpha(0.62)
}

/// Hairline for cards and inputs.
fn hairline(theme: &Theme) -> Color {
    theme.extended_palette().background.base.text.scale_alpha(0.14)
}

// --- containers ---------------------------------------------------------------------

/// Raised surface: panels and list rows.
pub fn card(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.background.weakest.color)),
        border: Border { color: hairline(theme), width: 1.0, radius: RADIUS_CARD.into() },
        ..Default::default()
    }
}

/// Accent-tinted surface for the one thing that needs attention (an incoming offer).
pub fn attention_card(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.primary.weak.color.scale_alpha(0.35))),
        border: Border { color: p.primary.base.color, width: 1.0, radius: RADIUS_CARD.into() },
        ..Default::default()
    }
}

/// The drop target: inset, slightly darker than paper.
pub fn drop_zone(theme: &Theme, hovering: bool) -> container::Style {
    let p = theme.extended_palette();
    let (bg, border_color, width) = if hovering {
        (p.primary.weak.color.scale_alpha(0.35), p.primary.base.color, 2.0)
    } else {
        (p.background.weak.color.scale_alpha(0.6), hairline(theme), 1.0)
    };
    container::Style {
        background: Some(Background::Color(bg)),
        border: Border { color: border_color, width, radius: RADIUS_CARD.into() },
        ..Default::default()
    }
}

/// Small status pill (visible / hidden / sending).
pub fn pill(theme: &Theme, on: bool) -> container::Style {
    let p = theme.extended_palette();
    let (bg, fg) = if on {
        (p.primary.weak.color.scale_alpha(0.45), p.primary.strong.color)
    } else {
        (p.background.weak.color, muted(theme))
    };
    container::Style {
        text_color: Some(fg),
        background: Some(Background::Color(bg)),
        border: border::rounded(RADIUS_PILL),
        ..Default::default()
    }
}

/// Selected device row.
pub fn selected_row(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.primary.weak.color.scale_alpha(0.35))),
        border: Border { color: p.primary.base.color, width: 1.0, radius: RADIUS_CONTROL.into() },
        ..Default::default()
    }
}

// --- buttons ------------------------------------------------------------------------

fn press_shadow(status: button::Status) -> (Shadow, Vector) {
    match status {
        button::Status::Pressed => (Shadow::default(), Vector::new(0.0, 1.0)),
        _ => (Shadow::default(), Vector::ZERO),
    }
}

/// The one filled button on screen: Send / Accept.
pub fn primary(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let (shadow, _) = press_shadow(status);
    let base = match status {
        button::Status::Active => p.primary.base,
        button::Status::Hovered => p.primary.strong,
        button::Status::Pressed => p.primary.strong,
        button::Status::Disabled => iced::theme::palette::Pair::new(
            p.primary.base.color.scale_alpha(0.35),
            p.primary.base.text.scale_alpha(0.7),
        ),
    };
    button::Style {
        background: Some(Background::Color(base.color)),
        text_color: base.text,
        border: border::rounded(RADIUS_CONTROL),
        shadow,
        snap: true,
    }
}

/// Outlined button: Add files, Paste, Browse, Decline-when-not-destructive.
pub fn ghost(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let bg = match status {
        button::Status::Hovered => Some(Background::Color(p.background.weak.color)),
        button::Status::Pressed => Some(Background::Color(p.background.strong.color)),
        _ => None,
    };
    let text_color = match status {
        button::Status::Disabled => muted(theme).scale_alpha(0.6),
        _ => p.background.base.text,
    };
    button::Style {
        background: bg,
        text_color,
        border: Border { color: hairline(theme), width: 1.0, radius: RADIUS_CONTROL.into() },
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Text-only button: list row actions, ×, "Settings".
pub fn quiet(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let bg = match status {
        button::Status::Hovered | button::Status::Pressed => Some(Background::Color(p.background.weak.color)),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: match status {
            button::Status::Disabled => muted(theme).scale_alpha(0.6),
            _ => p.background.base.text,
        },
        border: border::rounded(RADIUS_CONTROL),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Destructive outline: Decline.
pub fn danger(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let bg = match status {
        button::Status::Hovered | button::Status::Pressed => Some(Background::Color(p.danger.weak.color.scale_alpha(0.3))),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: p.danger.base.color,
        border: Border { color: p.danger.base.color.scale_alpha(0.6), width: 1.0, radius: RADIUS_CONTROL.into() },
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Whole-row button for the device list (transparent; selection is drawn by the container).
pub fn row_button(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    button::Style {
        background: match status {
            button::Status::Hovered => Some(Background::Color(p.background.weak.color.scale_alpha(0.7))),
            _ => None,
        },
        text_color: p.background.base.text,
        border: border::rounded(RADIUS_CONTROL),
        shadow: Shadow::default(),
        snap: true,
    }
}

// --- inputs & indicators ------------------------------------------------------------

pub fn input(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let p = theme.extended_palette();
    let border_color = match status {
        text_input::Status::Focused { .. } => p.primary.base.color,
        text_input::Status::Hovered => p.background.base.text.scale_alpha(0.3),
        _ => hairline(theme),
    };
    text_input::Style {
        background: Background::Color(p.background.weakest.color),
        border: Border { color: border_color, width: 1.0, radius: RADIUS_CONTROL.into() },
        icon: muted(theme),
        placeholder: muted(theme),
        value: p.background.base.text,
        selection: p.primary.weak.color,
    }
}

pub fn progress(theme: &Theme) -> progress_bar::Style {
    let p = theme.extended_palette();
    progress_bar::Style {
        background: Background::Color(p.background.weak.color),
        bar: Background::Color(p.primary.base.color),
        border: border::rounded(RADIUS_PILL),
    }
}

/// Symbolic icon tinted with the ink (or the accent when `accent`).
pub fn icon(theme: &Theme, accent: bool) -> svg::Style {
    let p = theme.extended_palette();
    svg::Style {
        color: Some(if accent { p.primary.base.color } else { p.background.base.text }),
    }
}
