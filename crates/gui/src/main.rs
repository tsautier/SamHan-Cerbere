use iced::widget::{button, column, text, row, text_input};
use iced::{Alignment, Element, Sandbox, Settings, Theme};

pub fn main() -> iced::Result { CerbereApp::run(Settings::default()) }

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
enum Tab { #[default] Status, Policies, Mfa }

#[derive(Default)]
struct CerbereApp { tab: Tab, status: String, policies_summary: String, mfa_user: String, enroll_output: String }

#[derive(Debug, Clone)]
enum Message {
    SwitchStatus, SwitchPolicies, SwitchMfa,
    ValidatePolicies, DryRunPolicy,
    MfaUserChanged(String), MfaEnroll, CheckStatus,
}

impl Sandbox for CerbereApp {
    type Message = Message;
    fn new() -> Self { Self { status: "Idle".into(), ..Default::default() } }
    fn title(&self) -> String { "Cerbère — SamHan".into() }
    fn theme(&self) -> Theme { Theme::Dark }
    fn update(&mut self, msg: Message) {
        match msg {
            Message::SwitchStatus => self.tab = Tab::Status,
            Message::SwitchPolicies => self.tab = Tab::Policies,
            Message::SwitchMfa => self.tab = Tab::Mfa,
            Message::ValidatePolicies => {
                let res = policy_engine::loader::load_policies("./config/policies")
                    .map(|r| format!("{} rule(s) loaded", r.len()))
                    .unwrap_or_else(|e| format!("error: {e}"));
                self.policies_summary = res;
            }
            Message::DryRunPolicy => { self.policies_summary.push_str("\n(dry-run stub: allow_mfa)"); }
            Message::MfaUserChanged(s) => self.mfa_user = s,
            Message::MfaEnroll => {
                let user = self.mfa_user.trim();
                if user.is_empty() { self.enroll_output = "please enter username".into(); }
                else {
                    let secret = mfa_broker::totp::random_secret(20);
                    let t = mfa_broker::totp::Totp::new(secret.clone(), 6, 30);
                    let uri = t.generate_uri(user, "SamHan-Cerbere");
                    let mut store = storage::mfa::TotpStore::load("./data/totp.json").unwrap_or_default();
                    let _ = store.set(storage::mfa::TotpSecret{ user: user.into(), secret, digits: 6, period: 30 });
                    self.enroll_output = uri;
                }
            }
            Message::CheckStatus => self.status = "OK".into(),
        }
    }
    fn view(&self) -> Element<Message> {
        let tabs = row![
            button("Status").on_press(Message::SwitchStatus),
            button("Policies").on_press(Message::SwitchPolicies),
            button("MFA").on_press(Message::SwitchMfa),
        ].spacing(10);

        let content: Element<_> = match self.tab {
            Tab::Status => column![
                text("Cerbère (GUI)").size(28),
                text(format!("Status: {}", self.status)),
                button("Check").on_press(Message::CheckStatus),
            ].align_items(Alignment::Start).spacing(12).into(),
            Tab::Policies => column![
                button("Validate").on_press(Message::ValidatePolicies),
                button("Dry-run").on_press(Message::DryRunPolicy),
                text(&self.policies_summary)
            ].spacing(8).into(),
            Tab::Mfa => column![
                text("Enroll TOTP for user:"),
                text_input("alice", &self.mfa_user, Message::MfaUserChanged),
                button("Enroll").on_press(Message::MfaEnroll),
                text(&self.enroll_output)
            ].spacing(8).into(),
        };
        column![tabs, content].spacing(16).into()
    }
}
