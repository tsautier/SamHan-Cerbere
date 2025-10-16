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
        /// Shared secret used to encrypt PAP and verify responses
        #[arg(long, default_value = "changeme")] shared_secret: String,
        #[arg(long, default_value = "alice")] user: String,
        #[arg(long, default_value = "secret")] password: String,
        /// MFA code to send on challenge
        #[arg(long)] mfa_code: Option<String>,
    }
}

#[derive(Subcommand)]
enum UsersOp {
    /// Add a user with plaintext password (TEST ONLY for CHAP)
    AddPlain { #[arg(long)] user: String, #[arg(long)] password: String },
    /// Add a user storing NT hash for EAP-MSCHAPv2
    AddNthash { #[arg(long)] user: String, #[arg(long)] password: String },

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
    let _telemetry = telemetry_init();
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
                RadiusOp::Test { dest, id, timeout_ms, shared_secret, user, password, mfa_code } => {
                    self_test(&dest, id, timeout_ms, shared_secret, user, password, mfa_code).await?;
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
                UsersOp::AddPlain { user, password } => {
                    let mut fb = id_connectors::file::FileBackend::load(path)?;
                    fb.set_plain(&user, &password)?;
                    println!("user '{}' set with plaintext (TEST ONLY)", user);
                }
                UsersOp::AddNthash { user, password } => {
                    let nthash = compute_nthash_hex(&password);
                    let mut fb = id_connectors::file::FileBackend::load(path)?;
                    fb.set_nthash_hex(&user, &nthash)?;
                    println!("user '{}' set with nthash {}", user, nthash);
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

async fn self_test(dest: &str, id: u8, timeout_ms: u64, shared_secret:String, user:String, password:String, mfa_code: Option<String>) -> anyhow::Result<()> {
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};
    use radius_core::packet::{Header, Code, Attr, encode_attrs};
    use md5::Context;
    use rand::RngCore;

    // Random Request Authenticator
    let mut req_auth = [0u8;16];
    rand::thread_rng().fill_bytes(&mut req_auth);

    // Encrypt User-Password per RFC2865
    fn encrypt_user_password(pw:&[u8], shared:&str, req_auth:&[u8;16]) -> Vec<u8> {
        let mut p = pw.to_vec();
        // pad to multiple of 16 with zeros
        let pad = (16 - (p.len() % 16)) % 16;
        p.extend(std::iter::repeat(0u8).take(pad));
        let mut out = Vec::new();
        let mut prev = req_auth.to_vec();
        for chunk in p.chunks(16) {
            let mut hasher = Context::new();
            hasher.consume(shared.as_bytes());
            hasher.consume(&prev);
            let b = hasher.compute();
            let mut c = [0u8;16];
            for i in 0..16 { c[i] = chunk[i] ^ b[i]; }
            out.extend_from_slice(&c);
            prev = c.to_vec();
        }
        out
    }

    let hdr = Header { code: Code::AccessRequest, identifier: id, length: Header::LEN as u16, authenticator: req_auth };
    let mut attrs = Vec::new();
    attrs.push(Attr::UserName(user.clone()));
    let enc = encrypt_user_password(password.as_bytes(), &shared_secret, &req_auth);
    attrs.push(Attr::UserPassword(enc));

    let sock = UdpSocket::bind("0.0.0.0:0").await?; sock.connect(dest).await?;
    let mut out = Vec::with_capacity(1024); hdr.encode(&mut out); encode_attrs(&attrs, &mut out); sock.send(&out).await?;

    let mut buf = [0u8; 4096];
    let n = timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf)).await??;
    if n < Header::LEN { anyhow::bail!("response too short"); }
    // Verify response authenticator
    let mut hasher = Context::new();
    hasher.consume(&buf[0..4]);
    hasher.consume(&req_auth);
    if n > Header::LEN { hasher.consume(&buf[Header::LEN..n]); }
    hasher.consume(shared_secret.as_bytes());
    let digest = hasher.compute();
    let resp_auth = &buf[4..20];
    if &digest[..16] != resp_auth { anyhow::bail!("bad response authenticator"); }

    let (resp_hdr, rest) = radius_core::packet::Header::parse(&buf[..n])?;
    match resp_hdr.code {
        Code::AccessAccept => { println!("Primary OK (no MFA required)."); return Ok(()); }
        Code::AccessReject => { println!("Rejected."); anyhow::bail!("reject"); }
        Code::AccessChallenge => { /* Continue below with State */ }
        _ => { println!("Unexpected code {:?}", resp_hdr.code); }
    }

    // Parse attrs for State
    let attrs2 = radius_core::packet::parse_attrs(rest)?;
    let mut state=None;
    for a in attrs2 { if let Attr::State(v) = a { state=Some(v); } }
    let st = state.ok_or_else(||anyhow::anyhow!("no State in challenge"))?;

    // Follow-up Access-Request with State + MFA-Code
    let mut req_auth2 = [0u8;16];
    rand::thread_rng().fill_bytes(&mut req_auth2);
    let hdr2 = Header { code: Code::AccessRequest, identifier: id.wrapping_add(1), length: Header::LEN as u16, authenticator: req_auth2 };
    let mut attrs = Vec::new();
    attrs.push(Attr::UserName(user));
    attrs.push(Attr::State(st));
    let mf = mfa_code.unwrap_or_else(||"000000".into());
    attrs.push(Attr::VendorSpecific(99999, format!("MFA-Code:{}", mf).into_bytes()));

    let mut out2 = Vec::with_capacity(1024); hdr2.encode(&mut out2); encode_attrs(&attrs, &mut out2);
    sock.send(&out2).await?;
    let n2 = timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf)).await??;
    if n2 < Header::LEN { anyhow::bail!("response too short #2"); }
    // verify response authenticator #2
    let mut hasher2 = Context::new();
    hasher2.consume(&buf[0..4]);
    hasher2.consume(&req_auth2);
    if n2 > Header::LEN { hasher2.consume(&buf[Header::LEN..n2]); }
    hasher2.consume(shared_secret.as_bytes());
    let digest2 = hasher2.compute();
    if &digest2[..16] != &buf[4..20] { anyhow::bail!("bad response authenticator #2"); }

    let (hdr3, _rest3) = radius_core::packet::Header::parse(&buf[..n2])?;
    if hdr3.code == Code::AccessAccept { println!("MFA OK: Access-Accept"); Ok(()) } else { anyhow::bail!("MFA rejected") }
}

fn compute_nthash_hex(password: &str) -> String {
    use md4::{Digest, Md4};
    let mut le = Vec::with_capacity(password.len()*2);
    for ch in password.encode_utf16() {
        le.extend_from_slice(&ch.to_le_bytes());
    }
    let mut md4 = Md4::new();
    md4.update(&le);
    let out = md4.finalize();
    hex::encode(out)
}
