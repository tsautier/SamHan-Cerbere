pub fn version()->&'static str{ env!("CARGO_PKG_VERSION") }
pub mod model;
pub mod loader;
pub mod eval;
