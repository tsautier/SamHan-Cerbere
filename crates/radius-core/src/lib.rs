pub mod packet;
pub mod server;
pub mod rate;
pub mod helpers;

pub use server::{run_server, run_server_with_params, ServerParams};

pub fn version()->&'static str{ env!("CARGO_PKG_VERSION") }
