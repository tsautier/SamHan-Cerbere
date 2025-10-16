use clap::{Parser, Subcommand};
use telemetry::init as telemetry_init;
use tracing::info;

#[derive(Parser)]
#[command(name = "cerbere", version, about = "SamHan RADIUS + MFA (skeleton)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a default config (placeholder)
    Init { #[arg(long, default_value_t = String::from("standalone"))] mode: String },
    /// Run a dummy RADIUS server (placeholder)
    Run,
    /// Show status (placeholder)
    Status { #[arg(long)] json: bool },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry_init();
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Init { mode } => {
            info!("Initialized in mode: {}", mode);
        }
        Commands::Run => {
            info!("Launching dummy RADIUS server…");
            radius_core::run_dummy_server().await?;
        }
        Commands::Status { json } => {
            if json {
                println!(r#"{{"status":"ok","components":["cli"]}}"#);
            } else {
                println!("Status: OK");
            }
        }
    }
    Ok(())
}
