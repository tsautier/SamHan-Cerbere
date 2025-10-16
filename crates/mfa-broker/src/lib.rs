//! mfa-broker — skeleton

pub trait MfaProvider {
    fn name(&self) -> &str;
    fn begin(&self, user: &str) -> bool;
    fn verify(&self, user: &str, code: &str) -> bool;
}

pub struct TotpDummy;

impl MfaProvider for TotpDummy {
    fn name(&self) -> &str { "totp-dummy" }
    fn begin(&self, _user: &str) -> bool { true }
    fn verify(&self, _user: &str, _code: &str) -> bool { true }
}
