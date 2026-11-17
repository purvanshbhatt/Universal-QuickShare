//! Inline symbolic icons (24×24, stroke = currentColor), tinted via `theme::icon`.

use iced::widget::svg::Handle;

macro_rules! icon {
    ($name:ident, $body:expr) => {
        pub fn $name() -> Handle {
            Handle::from_memory(concat!(
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">"#,
                $body,
                "</svg>"
            ).as_bytes())
        }
    };
}

icon!(phone, r#"<rect x="7" y="2.5" width="10" height="19" rx="2.2"/><line x1="11" y1="18" x2="13" y2="18"/>"#);
icon!(tablet, r#"<rect x="4" y="3" width="16" height="18" rx="2.2"/><line x1="11" y1="18" x2="13" y2="18"/>"#);
icon!(laptop, r#"<rect x="4" y="5" width="16" height="11" rx="1.8"/><line x1="2" y1="19" x2="22" y2="19"/>"#);
icon!(device, r#"<rect x="3" y="4" width="18" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/>"#);
icon!(file, r#"<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>"#);
icon!(link, r#"<path d="M10 13a5 5 0 0 0 7.07 0l2.12-2.12a5 5 0 0 0-7.07-7.07L11 5"/><path d="M14 11a5 5 0 0 0-7.07 0L4.8 13.12a5 5 0 0 0 7.07 7.07L13 19"/>"#);
icon!(text, r#"<line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="16" y2="12"/><line x1="4" y1="18" x2="12" y2="18"/>"#);
icon!(wifi, r#"<path d="M2 8.5a16 16 0 0 1 20 0"/><path d="M5.5 12a11 11 0 0 1 13 0"/><path d="M9 15.5a5.5 5.5 0 0 1 6 0"/><circle cx="12" cy="19" r="1" fill="black"/>"#);
icon!(inbox, r#"<path d="M4 13h4l2 3h4l2-3h4"/><path d="M5 5h14l2 8v6H3v-6z"/>"#);
icon!(send, r#"<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/>"#);
icon!(close, r#"<line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/>"#);
icon!(gear, r#"<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>"#);
icon!(back, r#"<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/>"#);
icon!(folder, r#"<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>"#);
icon!(check, r#"<path d="m5 12 5 5L20 7"/>"#);
icon!(mark, r#"<rect x="3" y="3" width="11" height="11" rx="3" fill="black" stroke="none"/><rect x="10" y="10" width="11" height="11" rx="3" fill="black" stroke="none" opacity="0.55"/>"#);
