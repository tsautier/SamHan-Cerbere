use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{error, info, debug};

use crate::packet::{Header, Code, parse_attrs, Attr};
use crate::rate::RateLimit;

#[derive(Clone)]
pub struct ServerParams { pub bind:String, pub shared_secret:String }

pub async fn run_server(bind_addr:&str)->Result<()>{
    run_server_with_params(ServerParams{ bind:bind_addr.to_string(), shared_secret:String::new() }).await
}

pub async fn run_server_with_params(params: ServerParams)->Result<()>{
    let sock=UdpSocket::bind(&params.bind).await?;
    info!("radius-core: listening on {}", &params.bind);
    let mut rl=RateLimit::default();
    let mut buf=vec![0u8;4096];
    loop{
        match sock.recv_from(&mut buf).await{
            Ok((n,peer))=>{
                debug!("received {} bytes from {}", n, peer);
                if n>=Header::LEN{
                    let pkt=&buf[..n];
                    match Header::parse(pkt){
                        Ok((hdr,attrs_buf))=>{
                            let attrs=parse_attrs(attrs_buf).unwrap_or_default();
                            let username=attrs.iter().find_map(|a| if let Attr::UserName(s)=a { Some(s.clone()) } else { None });
                            let client_ip=match peer{ std::net::SocketAddr::V4(a)=>a.ip().to_string(), std::net::SocketAddr::V6(a)=>a.ip().to_string() };
                            let uname=username.clone().unwrap_or_else(||"-".into());

                            if !rl.allowed(&uname, &client_ip){ continue; }

                            let rules=policy_engine::loader::load_policies("./config/policies").unwrap_or_default();
                            let ctx=policy_engine::eval::Context{ client_ip:&client_ip, user: username.as_deref() };
                            let decision=policy_engine::eval::evaluate(&rules, &ctx);
                            debug!("policy decision: {:?}", decision);

                            if hdr.code==Code::AccessRequest{
                                let resp_hdr=Header{ code:Code::AccessAccept, identifier:hdr.identifier, length:Header::LEN as u16, authenticator:hdr.authenticator };
                                let mut out=Vec::with_capacity(Header::LEN);
                                resp_hdr.encode(&mut out);
                                if let Err(e)=sock.send_to(&out, peer).await{ error!("send_to error: {e}"); } else { debug!("sent Access-Accept to {}", peer); }
                            }
                        }
                        Err(e)=>{ error!("failed to parse RADIUS header: {e}"); }
                    }
                }
            }
            Err(e)=>{ error!("recv_from error: {e}"); }
        }
    }
}
