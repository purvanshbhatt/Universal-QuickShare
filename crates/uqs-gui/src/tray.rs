//! StatusNotifierItem tray icon (XFCE panel "Status Tray" plugin, KDE, GNOME+ext).

use iced::futures::channel::mpsc::Sender;
use iced::futures::Stream;
use ksni::menu::{MenuItem, StandardItem};
use ksni::TrayMethods;

#[derive(Debug, Clone)]
pub enum TrayCommand {
    /// Tray spawned (or failed): tells the app whether closing the window may exit.
    Ready(bool),
    Show,
    SendClipboard,
    Quit,
}

struct UqsTray {
    tx: Sender<TrayCommand>,
}

impl UqsTray {
    fn emit(&mut self, cmd: TrayCommand) {
        let _ = self.tx.try_send(cmd);
    }
}

impl ksni::Tray for UqsTray {
    fn id(&self) -> String {
        "uqs-gui".into()
    }
    fn title(&self) -> String {
        "Quick Share".into()
    }
    fn icon_name(&self) -> String {
        "document-send".into()
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Universal Quick Share".into(),
            description: "Click to open · right-click for actions".into(),
            ..Default::default()
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        self.emit(TrayCommand::Show);
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Open Quick Share".into(),
                icon_name: "window-new".into(),
                activate: Box::new(|this: &mut Self| this.emit(TrayCommand::Show)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Send clipboard…".into(),
                icon_name: "edit-paste".into(),
                activate: Box::new(|this: &mut Self| this.emit(TrayCommand::SendClipboard)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|this: &mut Self| this.emit(TrayCommand::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub fn run() -> impl Stream<Item = TrayCommand> {
    iced::stream::channel(8, async move |mut out: Sender<TrayCommand>| {
        use iced::futures::SinkExt;
        let tray = UqsTray { tx: out.clone() };
        match tray.spawn().await {
            Ok(_handle) => {
                let _ = out.send(TrayCommand::Ready(true)).await;
                // `_handle` must outlive the service; park here for the app's lifetime.
                std::future::pending::<()>().await;
            }
            Err(e) => {
                tracing::warn!("tray unavailable ({e}); window close will quit the app");
                let _ = out.send(TrayCommand::Ready(false)).await;
                std::future::pending::<()>().await;
            }
        }
    })
}
