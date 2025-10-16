//! telemetry — skeleton
use tracing_subscriber::{fmt, EnvFilter};

pub fn init() {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}
