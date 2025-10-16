pub trait MfaProvider {
    fn name(&self) -> &str;
    fn begin(&self, _user: &str) -> bool { true }
    fn verify(&self, _user: &str, _code: &str) -> bool { true }
}
pub struct TotpDummy;
impl MfaProvider for TotpDummy { fn name(&self)->&str { "totp-dummy" } }
pub mod totp;
