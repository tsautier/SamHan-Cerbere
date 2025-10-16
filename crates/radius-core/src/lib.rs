//! radius-core — library root
pub mod packet;
pub mod server;

pub use server::run_server;

pub fn version() -> &'static str { env!("CARGO_PKG_VERSION") }
