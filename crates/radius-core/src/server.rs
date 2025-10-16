use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{error, info, debug};
use std::collections::HashMap;
use std::time::{Instant, Duration};

use crate::packet::{Header, Code, parse_attrs, Attr};
use crate::rate::RateLimit;
use crate::pap::decrypt_user_password;
use crate::chap::verify_chap;
use crate::mschapv2;

#[derive(Clone)]
pub struct ServerParams { pub bind:String, pub shared_secret:String }

struct Session { user: String, created: Instant }

pub async fn run_server(bind_addr:&str)->Result<()>{ run_server_with_params(ServerParams{ bind:bind_addr.to_string(), shared_secret:String::new() }).await }

pub async fn run_server_with_params(params: ServerParams)->Result<()>{
    let sock=UdpSocket::bind(&params.bind).await?;
    info!("radius-core: listening on {}", &params.bind);
    let mut rl=RateLimit::default();
    let mut sessions: HashMap<Vec<u8>, Session> = HashMap::new();
    let mut buf=vec![0u8;4096];
    loop{
        match sock.recv_from(&mut buf).await{
            Ok((n,peer))=>{
                if n<Header::LEN { continue; }
                let pkt=&buf[..n];
                match Header::parse(pkt){
                    Ok((hdr, attrs_buf))=>{
                        let attrs=parse_attrs(attrs_buf).unwrap_or_default();
                        let client_ip=match peer{ std::net::SocketAddr::V4(a)=>a.ip().to_string(), std::net::SocketAddr::V6(a)=>a.ip().to_string() };

                        // Extract username, user-password (encrypted), state, mfa-code (VSA 99999)
                        let mut username: Option<String> = None;
                        let mut enc_pwd: Option<Vec<u8>> = None;
                        let mut state: Option<Vec<u8>> = None;
                        let mut mfa_code: Option<String> = None;
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
                                _=>{}
                            }
                        }
                        let uname = username.clone().unwrap_or_else(||"-".into());
                        // CHAP verification (if present)
                        let mut chap_ok = None;
                        let mut chap_id: Option<u8> = None;
                        let mut chap_value: Option<[u8;16]> = None;
                        let mut chap_challenge: Option<Vec<u8>> = None;
                        for a in &attrs {
                            match a {
                                Attr::ChapPassword { id, hash } => { chap_id = Some(*id); chap_value = Some(*hash); }
                                Attr::ChapChallenge(v) => { chap_challenge = Some(v.clone()); }
                                _ => {}
                            }
                        }
                        if let (Some(cid), Some(val), Some(chal)) = (chap_id, chap_value, chap_challenge.clone()) {
                            if let Ok(fb) = id_connectors::file::FileBackend::load("./data/users.json") {
                                if let Some(u) = fb.find(&uname) {
                                    if let Some(ref plain) = u.password_plain {
                                        chap_ok = Some( verify_chap(cid, plain, &chal, &val) );
                                    }
                                }
                            }
                        }

                        if !rl.allowed(&uname, &client_ip){ continue; }

                        // Primary auth (file/ldap) only on initial request (no state)
                        let mut primary_ok = false;
                        if state.is_none() {
                            if let Some(ref enc) = enc_pwd {
                                if let Some(pass) = decrypt_user_password(enc, &params.shared_secret, &hdr.authenticator) {
                                    primary_ok = crate::auth::authenticate(&uname, std::str::from_utf8(&pass).unwrap_or(""));
                                }
                            }
                        } else {
                            primary_ok = true; // continue flow for MFA verify
                        }

                        // Load policies and evaluate (basic context)
                        let rules=policy_engine::loader::load_policies("./config/policies").unwrap_or_default();
                        let ctx=policy_engine::eval::Context{ client_ip:&client_ip, user: username.as_deref() };
                        let decision=policy_engine::eval::evaluate(&rules, &ctx);
                        debug!("policy decision: {:?} primary_ok={} state={:?}", decision, primary_ok, state.is_some());

                        if hdr.code==Code::AccessRequest {
                            // Case 1: Need MFA (no state => issue challenge + state token)
                            if state.is_none() && primary_ok && matches!(decision, policy_engine::model::Decision::RequireStrongMfa) {
                                let token = uuid::Uuid::new_v4().as_bytes().to_vec();
                                sessions.insert(token.clone(), Session{ user: uname.clone(), created: Instant::now() });
                                let reply = build_reply(&hdr, Code::AccessChallenge, vec![Attr::State(token)], &params.shared_secret);
                            }
                            // Case 2: MFA response (has state): verify TOTP
                            if let Some(st) = state.clone() {
                                if let Some(sess) = sessions.get(&st) {
                                    if sess.created.elapsed() < Duration::from_secs(120) {
                                        if let Some(user) = username.clone() {
                                            let ok = verify_totp(&user, mfa_code.as_deref().unwrap_or(""));
                                            let code = if ok { Code::AccessAccept } else { Code::AccessReject };
                                            let reply = build_reply(&hdr, code, vec![], &params.shared_secret);
                                            let _ = sock.send_to(&reply, peer).await;
                                            continue;
                                        }
                                    }
                                }
                                let reply = build_reply(&hdr, Code::AccessReject, vec![], &params.shared_secret);
                                let _ = sock.send_to(&reply, peer).await;
                                continue;
                            }
                            // Case 3: Simple accept (no MFA required) or CHAP verified
                            if (primary_ok || chap_ok == Some(true)) && matches!(decision, policy_engine::model::Decision::AllowMfa) {
                                let reply = build_reply(&hdr, Code::AccessAccept, vec![], &params.shared_secret);
                                let _ = sock.send_to(&reply, peer).await;
                                continue;
                            }
                            // Default reject
                            let reply = build_reply(&hdr, Code::AccessReject, vec![], &params.shared_secret);
                            let _ = sock.send_to(&reply, peer).await;
                        }
                    }
                    Err(e)=>{ error!("failed to parse RADIUS header: {e}"); }
                }
            }
            Err(e)=>{ error!("recv_from error: {e}"); }
        }
    }
}


fn build_reply(req:&Header, code: Code, attrs: Vec<Attr>, shared_secret: &str) -> Vec<u8> {
    use md5::{Md5, Digest};
    let mut out = Vec::with_capacity(1024);
    // Placeholder length; will set after attrs
    let mut hdr_bytes = vec![0u8; Header::LEN];
    hdr_bytes[0] = code as u8;
    hdr_bytes[1] = req.identifier;
    // length bytes set later
    hdr_bytes[4..20].copy_from_slice(&req.authenticator); // temp; will be replaced by response authenticator later
    out.extend_from_slice(&hdr_bytes);
    crate::packet::encode_attrs(&attrs, &mut out);
    let length = out.len() as u16;
    out[2..4].copy_from_slice(&length.to_be_bytes());

    // Compute response authenticator: MD5(Code+ID+Length+RequestAuth+Attrs+Secret)
    let mut hasher = Md5::new();
    hasher.update(&out[0..4]);              // Code, ID, Length
    hasher.update(&req.authenticator);      // Request Authenticator
    if out.len() > Header::LEN {
        hasher.update(&out[Header::LEN..]); // Attributes
    }
    hasher.update(shared_secret.as_bytes());
    let digest = hasher.finalize();
    out[4..20].copy_from_slice(&digest[..16]);
    out
}
}

// helper: TOTP verification from storage
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
        // ldap backend (optional): use config
        if let Ok(cfg) = storage::config::load_config("./config/cerbere.toml") {
            if cfg.backend.primary.r#type == "ldap" {
                if let (Some(url), Some(bind_dn), Some(bind_password), Some(base)) = (cfg.backend.primary.url.clone(), cfg.backend.primary.bind_dn.clone(), cfg.backend.primary.bind_password.clone(), cfg.backend.primary.user_base_dn.clone()) {
                    return id_connectors::ldap::auth_simple(&url, &bind_dn, &bind_password, &base, user, pass).unwrap_or(false);
                }
            }
        }
        false
    }
}
