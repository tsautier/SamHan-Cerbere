//! radius-core — skeleton
use tracing::info;

pub async fn run_dummy_server() -> anyhow::Result<()> {
    // Placeholder for UDP 1812 listener
    info!("radius-core: dummy server started (not actually binding UDP)");
    Ok(())
}

pub fn version() -> &'static str { env!("CARGO_PKG_VERSION") }
