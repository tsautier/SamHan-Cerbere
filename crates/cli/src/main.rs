use clap::{Parser, Subcommand};
use telemetry::init as telemetry_init;
use tracing::info;
use tokio::time::{timeout, Duration};

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
    /// Run a minimal RADIUS server (UDP/1812)
    Run {
        /// Bind address (default: 0.0.0.0:1812)
        #[arg(long, default_value = "0.0.0.0:1812")]
        bind: String
    },
    /// Show status (placeholder)
    Status { #[arg(long)] json: bool },
    /// Send a simple Access-Request to a server and wait for Access-Accept
    Radius {
        #[command(subcommand)]
        op: RadiusOp
    }
}

#[derive(Subcommand)]
enum RadiusOp {
    /// Self test to 127.0.0.1:1812 (or custom host:port)
    Test {
        /// Destination host:port
        #[arg(long, default_value = "127.0.0.1:1812")]
        dest: String,
        /// Identifier to use (0-255)
        #[arg(long, default_value_t = 1)]
        id: u8,
        /// Timeout in ms to wait for response
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u64,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry_init();
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Init { mode } => {
            info!("Initialized in mode: {}", mode);
        }
        Commands::Run { bind } => {
            info!("Launching RADIUS server on {bind}");
            radius_core::run_server(&bind).await?;
        }
        Commands::Status { json } => {
            if json {
                println!(r#"{{"status":"ok","components":["cli","radius-core"]}}"#);
            } else {
                println!("Status: OK");
            }
        }
        Commands::Radius { op } => {
            match op {
                RadiusOp::Test { dest, id, timeout_ms } => {
                    self_test(&dest, id, timeout_ms).await?;
                }
            }
        }
    }
    Ok(())
}

async fn self_test(dest: &str, id: u8, timeout_ms: u64) -> anyhow::Result<()> {
    use tokio::net::UdpSocket;
    use radius_core::packet::{Header, Code};

    // Build a minimal Access-Request with empty attributes.
    let hdr = Header {
        code: Code::AccessRequest,
        identifier: id,
        length: Header::LEN as u16,
        authenticator: [0u8; 16],
    };
    let mut out = Vec::with_capacity(Header::LEN);
    hdr.encode(&mut out);

    // Bind ephemeral local udp
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(dest).await?;
    sock.send(&out).await?;

    let mut buf = [0u8; 2048];
    let fut = sock.recv(&mut buf);

    let n = timeout(Duration::from_millis(timeout_ms), fut).await??;
    if n < Header::LEN {
        anyhow::bail!("response too short");
    }

    let (resp_hdr, _rest) = Header::parse(&buf[..n])?;
    if resp_hdr.code != Code::AccessAccept || resp_hdr.identifier != id {
        anyhow::bail!("unexpected response: {:?}", resp_hdr.code as u8);
    }

    println!("Self-test OK: received Access-Accept (id={}) from {}", id, dest);
    Ok(())
}
