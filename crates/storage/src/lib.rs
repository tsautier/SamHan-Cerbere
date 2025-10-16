pub fn version()->&'static str{ env!("CARGO_PKG_VERSION") }
pub mod config;
pub mod mfa;
pub mod audit;
pub mod rotation;
