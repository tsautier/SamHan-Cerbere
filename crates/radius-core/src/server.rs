//! radius-core::server — UDP server skeleton with minimal packet handling
use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{error, info, debug};

use crate::packet::{Header, Code};

/// Run a minimal RADIUS UDP server that answers Access-Accept to any Access-Request.
pub async fn run_server(bind_addr: &str) -> Result<()> {
    let sock = UdpSocket::bind(bind_addr).await?;
    info!("radius-core: listening on {}", bind_addr);

    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer)) => {
                        debug!("received {} bytes from {}", n, peer);
                        if n >= Header::LEN {
                            let pkt = &buf[..n];
                            match Header::parse(pkt) {
                                Ok((hdr, _attrs)) => {
                                    debug!("packet: code={:?} id={} len={}", hdr.code, hdr.identifier, hdr.length);
                                    if hdr.code == Code::AccessRequest {
                                        // Build a minimal Access-Accept echo (copy authenticator back, set length to header size)
                                        let resp_hdr = Header {
                                            code: Code::AccessAccept,
                                            identifier: hdr.identifier,
                                            length: Header::LEN as u16,
                                            authenticator: hdr.authenticator,
                                        };
                                        let mut out = Vec::with_capacity(Header::LEN);
                                        resp_hdr.encode(&mut out);
                                        if let Err(e) = sock.send_to(&out, peer).await {
                                            error!("send_to error: {e}");
                                        } else {
                                            debug!("sent Access-Accept to {}", peer);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("failed to parse RADIUS header: {e}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("recv_from error: {e}");
                    }
                }
            }
        }
    }
}
