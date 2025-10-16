use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Rule { pub when:String, pub action:String }

#[derive(Debug, Clone)]
pub enum Decision { AllowMfa, RequireStrongMfa, Reject }

impl Decision {
    pub fn from_str(s:&str)->Self{ match s{ "allow_mfa"=>Self::AllowMfa, "require_strong_mfa"=>Self::RequireStrongMfa, "reject"=>Self::Reject, _=>Self::AllowMfa } }
}
