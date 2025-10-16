use iced::widget::{button, column, text};
use iced::{Alignment, Element, Sandbox, Settings};
use telemetry::init as telemetry_init;

pub fn main() -> iced::Result {
    telemetry_init();
    CerbereApp::run(Settings::default())
}

#[derive(Default)]
struct CerbereApp {
    status: String,
}

#[derive(Debug, Clone)]
enum Message {
    CheckStatus,
}

impl Sandbox for CerbereApp {
    type Message = Message;

    fn new() -> Self {
        Self { status: "Idle".into() }
    }

    fn title(&self) -> String {
        "Cerbère — SamHan".into()
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::CheckStatus => {
                self.status = "OK (skeleton)".into();
            }
        }
    }

    fn view(&self) -> Element<Message> {
        column![
            text("Cerbère (GUI skeleton)").size(28),
            text(format!("Status: {}", self.status)),
            button("Check status").on_press(Message::CheckStatus),
        ]
        .align_items(Alignment::Center)
        .spacing(16)
        .into()
    }
}
