//! radius-core::server — UDP server with PAP/CHAP, Access-Challenge for MFA, and response authenticator
use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{error, info, debug};
use std::collections::HashMap;
use std::time::{Instant, Duration};

use crate::packet::{Header, Code, parse_attrs, Attr};
use crate::rate::RateLimit;
use crate::pap::decrypt_user_password;
use crate::chap::verify_chap;

#[derive(Clone)]
pub struct ServerParams {
    pub bind: String,
    pub shared_secret: String,
}

struct Session {
    user: String,
    created: Instant,
}

pub async fn run_server(bind_addr: &str) -> Result<()> {
    run_server_with_params(ServerParams {
        bind: bind_addr.to_string(),
        shared_secret: String::new(),
    }).await
}

pub async fn run_server_with_params(params: ServerParams) -> Result<()> {
    let sock = UdpSocket::bind(&params.bind).await?;
    info!("radius-core: listening on {}", &params.bind);

    let mut rl = RateLimit::default();
    let mut sessions: HashMap<Vec<u8>, Session> = HashMap::new();
    let mut buf = vec![0u8; 4096];

    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if n < Header::LEN { continue; }
                let pkt = &buf[..n];
                match Header::parse(pkt) {
                    Ok((hdr, attrs_buf)) => {
                        let attrs = parse_attrs(attrs_buf).unwrap_or_default();
                        let client_ip = match peer {
                            std::net::SocketAddr::V4(a) => a.ip().to_string(),
                            std::net::SocketAddr::V6(a) => a.ip().to_string(),
                        };

                        // extract attrs
                        let mut username: Option<String> = None;
                        let mut enc_pwd: Option<Vec<u8>> = None;
                        let mut state: Option<Vec<u8>> = None;
                        let mut mfa_code: Option<String> = None;
                        // CHAP
                        let mut chap_id: Option<u8> = None;
                        let mut chap_value: Option<[u8;16]> = None;
                        let mut chap_challenge: Option<Vec<u8>> = None;

                        for a in &attrs {
                            match a {
                                Attr::UserName(s) => username = Some(s.clone()),
                                Attr::UserPassword(v) => enc_pwd = Some(v.clone()),
                                Attr::State(v) => state = Some(v.clone()),
                                Attr::VendorSpecific(_, v) => {
                                    if let Ok(s) = std::str::from_utf8(v) {
                                        if let Some(rest) = s.strip_prefix("MFA-Code:") {
                                            mfa_code = Some(rest.trim().to_string());
                                        }
                                    }
                                }
                                Attr::ChapPassword { id, hash } => { chap_id = Some(*id); chap_value = Some(*hash); }
                                Attr::ChapChallenge(v) => { chap_challenge = Some(v.clone()); }
                                _ => {}
                            }
                        }

                        let uname = username.clone().unwrap_or_else(|| "-".into());
                        if !rl.allowed(&uname, &client_ip) { continue; }

                        // Primary auth
                        let mut primary_ok = false;
                        // a) CHAP (needs password_plain in file backend)
                        if let (Some(cid), Some(val), Some(chal)) = (chap_id, chap_value, chap_challenge.clone()) {
                            if let Ok(fb) = id_connectors::file::FileBackend::load("./data/users.json") {
                                if let Some(u) = fb.find(&uname) {
                                    if let Some(ref plain) = u.password_plain {
                                        primary_ok = verify_chap(cid, plain, &chal, &val);
                                    }
                                }
                            }
                        }

                        // b) PAP decrypt + file/ldap
                        if !primary_ok && state.is_none() {
                            if let Some(ref enc) = enc_pwd {
                                if let Some(pass) = decrypt_user_password(enc, &params.shared_secret, &hdr.authenticator) {
                                    let pass_str = std::str::from_utf8(&pass).unwrap_or("");
                                    primary_ok = auth::authenticate(&uname, pass_str);
                                }
                            }
                        } else if state.is_some() {
                            // follow-up MFA step
                            primary_ok = true;
                        }

                        // Policy
                        let rules = policy_engine::loader::load_policies("./config/policies").unwrap_or_default();
                        let ctx = policy_engine::eval::Context{ client_ip: &client_ip, user: username.as_deref() };
                        let decision = policy_engine::eval::evaluate(&rules, &ctx);
                        debug!("decision={:?} primary_ok={} state={}", decision, primary_ok, state.is_some());

                        if hdr.code == Code::AccessRequest {
                            // MFA required: issue Access-Challenge + State
                            if state.is_none() && primary_ok && matches!(decision, policy_engine::model::Decision::RequireStrongMfa) {
                                let token = uuid::Uuid::new_v4().as_bytes().to_vec();
                                sessions.insert(token.clone(), Session{ user: uname.clone(), created: Instant::now() });
                                let reply = build_reply(&hdr, Code::AccessChallenge, vec![Attr::State(token)], &params.shared_secret);
                                let _ = sock.send_to(&reply, peer).await;
                                continue;
                            }
                            // MFA response: verify TOTP
                            if let Some(st) = state.clone() {
                                if let Some(sess) = sessions.get(&st) {
                                    if sess.created.elapsed() < Duration::from_secs(120) {
                                        let user_for_mfa = username.clone().unwrap_or_else(|| sess.user.clone());
                                        let ok = verify_totp(&user_for_mfa, mfa_code.as_deref().unwrap_or(""));
                                        let code = if ok { Code::AccessAccept } else { Code::AccessReject };
                                        let reply = build_reply(&hdr, code, vec![], &params.shared_secret);
                                        let _ = sock.send_to(&reply, peer).await;
                                        continue;
                                    }
                                }
                                let reply = build_reply(&hdr, Code::AccessReject, vec![], &params.shared_secret);
                                let _ = sock.send_to(&reply, peer).await;
                                continue;
                            }
                            // Accept when allowed and primary auth OK
                            if primary_ok && matches!(decision, policy_engine::model::Decision::AllowMfa) {
                                let reply = build_reply(&hdr, Code::AccessAccept, vec![], &params.shared_secret);
                                let _ = sock.send_to(&reply, peer).await;
                                continue;
                            }
                            // Default reject
                            let reply = build_reply(&hdr, Code::AccessReject, vec![], &params.shared_secret);
                            let _ = sock.send_to(&reply, peer).await;
                        }
                    }
                    Err(e) => { error!("failed to parse RADIUS header: {e}"); }
                }
            }
            Err(e) => { error!("recv_from error: {e}"); }
        }
    }
}

/// Build RADIUS reply and compute Response Authenticator per RFC2865
fn build_reply(req:&Header, code: Code, attrs: Vec<Attr>, shared_secret: &str) -> Vec<u8> {
    use md5::Context;
    let mut out = Vec::with_capacity(1024);
    // placeholder header
    let mut hdr = [0u8; Header::LEN];
    hdr[0] = code as u8;
    hdr[1] = req.identifier;
    // hdr[2..4] length later
    // temp authenticator = request one; replaced by response authenticator
    hdr[4..20].copy_from_slice(&req.authenticator);
    out.extend_from_slice(&hdr);
    crate::packet::encode_attrs(&attrs, &mut out);
    let length = out.len() as u16;
    out[2..4].copy_from_slice(&length.to_be_bytes());

    // Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attrs+Secret)
    let mut hasher = Context::new();
    hasher.consume(&out[0..4]);
    hasher.consume(&req.authenticator);
    if out.len() > Header::LEN { hasher.consume(&out[Header::LEN..]); }
    hasher.consume(shared_secret.as_bytes());
    let digest = hasher.compute();
    out[4..20].copy_from_slice(&digest[..16]);
    out
}

fn verify_totp(user: &str, code: &str) -> bool {
    if let Ok(store) = storage::mfa::TotpStore::load("./data/totp.json") {
        if let Some(e) = store.get(user) {
            let t = mfa_broker::totp::Totp::new(e.secret.clone(), e.digits, e.period);
            return t.verify(code, 1);
        }
    }
    false
}

mod auth {
    pub fn authenticate(user:&str, pass:&str) -> bool {
        // file backend
        if let Ok(fb) = id_connectors::file::FileBackend::load("./data/users.json") {
            if fb.authenticate(user, pass) { return true; }
        }
        // ldap backend
        if let Ok(cfg) = storage::config::load_config("./config/cerbere.toml") {
            if cfg.backend.primary.r#type == "ldap" {
                if let (Some(url), Some(bind_dn), Some(bind_password), Some(base)) = (
                    cfg.backend.primary.url.clone(),
                    cfg.backend.primary.bind_dn.clone(),
                    cfg.backend.primary.bind_password.clone(),
                    cfg.backend.primary.user_base_dn.clone()
                ) {
                    return id_connectors::ldap::auth_simple(&url, &bind_dn, &bind_password, &base, user, pass).unwrap_or(false);
                }
            }
        }
        false
    }
}
