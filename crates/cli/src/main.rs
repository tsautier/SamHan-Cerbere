use clap::{Parser, Subcommand};
use telemetry::init as telemetry_init;
use tracing::info;

#[derive(Parser)]
#[command(name = "cerbere", version, about = "SamHan RADIUS + MFA")]
struct Cli {
    /// Path to config TOML (default: ./config/cerbere.toml if exists)
    #[arg(long)]
    config: Option<String>,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a default config (placeholder)
    Init { #[arg(long, default_value_t = String::from("standalone"))] mode: String },

    /// Run a minimal RADIUS server (UDP)
    Run { #[arg(long)] bind: Option<String> },

    /// Show status (placeholder)
    Status { #[arg(long)] json: bool },

    /// RADIUS client test
    Radius { #[command(subcommand)] op: RadiusOp },

    /// Manage local users (file backend)
    Users { #[command(subcommand)] op: UsersOp },

    /// MFA operations
    Mfa { #[command(subcommand)] op: MfaOp },

    /// Generate integration snippets
    Generate { #[command(subcommand)] op: GenOp },

    /// Audit operations
    Audit { #[command(subcommand)] op: AuditOp },
}

#[derive(Subcommand)]
enum RadiusOp {
    /// Self test to a server (default 127.0.0.1:1812)
    Test {
        #[arg(long, default_value = "127.0.0.1:1812")] dest: String,
        #[arg(long, default_value_t = 1)] id: u8,
        #[arg(long, default_value_t = 1500)] timeout_ms: u64,
        /// Optional MFA code sent as VendorSpecific attr
        #[arg(long)] mfa_code: Option<String>,
    }
}

#[derive(Subcommand)]
enum UsersOp {
    /// Add a user to the file backend (argon2-hashed)
    Add { #[arg(long)] user: String, #[arg(long)] password: String },
    /// List users
    List,
}

#[derive(Subcommand)]
enum MfaOp {
    /// Enroll a TOTP factor for a user
    Enroll { #[arg(long)] user: String, #[arg(long, default_value = "SamHan-Cerbere")] issuer: String, #[arg(long, default_value_t = 6)] digits: u32, #[arg(long, default_value_t = 30)] period: u64 },
    /// Show TOTP otpauth URI
    Show { #[arg(long)] user: String },
    /// Revoke TOTP
    Revoke { #[arg(long)] user: String },
    /// List enrolled
    List,
}

#[derive(Subcommand)]
enum GenOp { Fortigate, PaloAlto, Aruba }

#[derive(Subcommand)]
enum AuditOp {
    /// Export CSV audit log (placeholder path)
    Export { #[arg(long, default_value = "./data/audit.csv")] out: String },
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn real_main() -> anyhow::Result<()> {
    telemetry_init();
    let cli = Cli::parse();

    // Load config if available or requested
    let cfg_path = cli.config.clone()
        .or_else(|| {
            let default = "./config/cerbere.toml";
            if std::path::Path::new(default).exists() { Some(default.to_string()) } else { None }
        });

    let cfg_opt = if let Some(ref p) = cfg_path {
        match storage::config::load_config(p) {
            Ok(cfg) => Some(cfg),
            Err(e) => { eprintln!("Config error: {e}"); std::process::exit(1); }
        }
    } else { None };

    match cli.cmd {
        Commands::Init { mode } => {
            info!("Initialized in mode: {}", mode);
        }
        Commands::Run { bind } => {
            let final_bind = if let Some(b) = bind { b } else if let Some(ref cfg) = cfg_opt { cfg.server.bind.clone() } else { "0.0.0.0:1812".to_string() };
            let shared = cfg_opt.as_ref().map(|c| c.server.shared_secret.clone()).unwrap_or_default();
            info!("Launching RADIUS server on {final_bind}");
            radius_core::run_server_with_params(radius_core::ServerParams{ bind: final_bind, shared_secret: shared }).await?;
        }
        Commands::Status { json } => {
            if json { println!(r#"{{"status":"ok","components":["cli","radius-core"]}}"#); }
            else { println!("Status: OK"); }
        }
        Commands::Radius { op } => {
            match op {
                RadiusOp::Test { dest, id, timeout_ms, mfa_code } => {
                    self_test(&dest, id, timeout_ms, mfa_code).await?;
                }
            }
        }
        Commands::Users { op } => {
            let path = "./data/users.json";
            let mut fb = id_connectors::file::FileBackend::load(path)?;
            match op {
                UsersOp::Add { user, password } => {
                    fb.add_user(&user, &password)?;
                    println!("user '{}' added", user);
                }
                UsersOp::List => {
                    for u in fb.list() { println!("{}", u.username); }
                }
            }
        }
        Commands::Mfa { op } => {
            let store_path = "./data/totp.json";
            let mut store = storage::mfa::TotpStore::load(store_path)?;
            match op {
                MfaOp::Enroll { user, issuer, digits, period } => {
                    let secret = mfa_broker::totp::random_secret(20);
                    let t = mfa_broker::totp::Totp::new(secret.clone(), digits, period);
                    let uri = t.generate_uri(&user, &issuer);
                    store.set(storage::mfa::TotpSecret{ user: user.clone(), secret, digits, period })?;
                    println!("{}", uri);
                }
                MfaOp::Show { user } => {
                    if let Some(e) = store.get(&user) {
                        let t = mfa_broker::totp::Totp::new(e.secret.clone(), e.digits, e.period);
                        let uri = t.generate_uri(&user, "SamHan-Cerbere");
                        println!("{}", uri);
                    } else { eprintln!("not found"); std::process::exit(1); }
                }
                MfaOp::Revoke { user } => {
                    store.revoke(&user)?;
                    println!("revoked {}", user);
                }
                MfaOp::List => {
                    for e in store.list() { println!("{}", e.user); }
                }
            }
        }
        Commands::Generate { op } => {
            match op {
                GenOp::Fortigate => println!("config user radius-server\n  set server <cerbere-ip>\n  set secret <shared>\n  set timeout 3"),
                GenOp::PaloAlto => println!("Device > Server Profiles > RADIUS: server=<cerbere-ip> secret=<shared> timeout=3"),
                GenOp::Aruba => println!("radius-server host <cerbere-ip> key <shared> auth-port 1812 acct-port 1813"),
            }
        }
        Commands::Audit { op } => {
            match op {
                AuditOp::Export { out } => { println!("{}", out); }
            }
        }
    }
    Ok(())
}

async fn self_test(dest: &str, id: u8, timeout_ms: u64, mfa_code: Option<String>) -> anyhow::Result<()> {
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};
    use radius_core::packet::{Header, Code, Attr, encode_attrs};

    let hdr = Header { code: Code::AccessRequest, identifier: id, length: Header::LEN as u16, authenticator: [0u8; 16] };
    let mut attrs = Vec::new();
    if let Some(code) = mfa_code { attrs.push(Attr::VendorSpecific(99999, format!("MFA-Code:{}", code).into_bytes())); }

    let sock = UdpSocket::bind("0.0.0.0:0").await?; sock.connect(dest).await?;
    let mut out = Vec::with_capacity(1024); hdr.encode(&mut out); encode_attrs(&attrs, &mut out); sock.send(&out).await?;

    let mut buf = [0u8; 2048];
    let n = timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf)).await??;
    if n < Header::LEN { anyhow::bail!("response too short"); }
    let (resp_hdr, _rest) = Header::parse(&buf[..n])?;
    if resp_hdr.code != Code::AccessAccept || resp_hdr.identifier != id { anyhow::bail!("unexpected response"); }
    println!("Self-test OK: received Access-Accept (id={}) from {}", id, dest);
    Ok(())
}
