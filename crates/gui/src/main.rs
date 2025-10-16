use iced::widget::{button, column, text, row, text_input};
use iced::{Alignment, Element, Settings, Theme, Task};

pub fn main() -> iced::Result {
    iced::application("Cerbère — SamHan", CerbereApp::update, CerbereApp::view)
        .theme(|_| Theme::Dark)
        .settings(Settings::default())
        .run_with(CerbereApp::init)
}

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

impl CerbereApp {
    fn init() -> (Self, Task<Message>) {
        (
            Self { status: "Idle".into(), ..Self::default() },
            Task::none(),
        )
    }

    fn update(state: &mut Self, msg: Message) -> Task<Message> {
        match msg {
            Message::SwitchStatus => state.tab = Tab::Status,
            Message::SwitchPolicies => state.tab = Tab::Policies,
            Message::SwitchMfa => state.tab = Tab::Mfa,
            Message::ValidatePolicies => {
                let res = policy_engine::loader::load_policies("./config/policies")
                    .map(|r| format!("{} rule(s) loaded", r.len()))
                    .unwrap_or_else(|e| format!("error: {e}"));
                state.policies_summary = res;
            }
            Message::DryRunPolicy => { state.policies_summary.push_str("
(dry-run stub: allow_mfa)"); }
            Message::MfaUserChanged(s) => state.mfa_user = s,
            Message::MfaEnroll => {
                let user = state.mfa_user.trim();
                if user.is_empty() { state.enroll_output = "please enter username".into(); }
                else {
                    let secret = mfa_broker::totp::random_secret(20);
                    let t = mfa_broker::totp::Totp::new(secret.clone(), 6, 30);
                    let uri = t.generate_uri(user, "SamHan-Cerbere");
                    let mut store = storage::mfa::TotpStore::load("./data/totp.json").unwrap_or_default();
                    let _ = store.set(storage::mfa::TotpSecret{ user: user.into(), secret, digits: 6, period: 30 });
                    state.enroll_output = uri;
                }
            }
            Message::CheckStatus => state.status = "OK".into(),
        }
        Task::none()
    }

    fn view(state: &Self) -> Element<'_, Message> {
        let tabs = row![
            button("Status").on_press(Message::SwitchStatus),
            button("Policies").on_press(Message::SwitchPolicies),
            button("MFA").on_press(Message::SwitchMfa),
        ].spacing(10);

        let content: Element<_> = match state.tab {
            Tab::Status => column![
                text("Cerbère (GUI)").size(28),
                text(format!("Status: {}", state.status)),
                button("Check").on_press(Message::CheckStatus),
            ].align_x(Alignment::Start).spacing(12).into(),
            Tab::Policies => column![
                button("Validate").on_press(Message::ValidatePolicies),
                button("Dry-run").on_press(Message::DryRunPolicy),
                text(&state.policies_summary)
            ].spacing(8).into(),
            Tab::Mfa => column![
                text("Enroll TOTP for user:"),
                text_input("alice", &state.mfa_user).on_input(Message::MfaUserChanged),
                button("Enroll").on_press(Message::MfaEnroll),
                text(&state.enroll_output)
            ].spacing(8).into(),
        };
        column![tabs, content].spacing(16).into()
    }
}
