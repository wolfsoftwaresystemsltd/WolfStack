// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! PVE Console — WebSocket proxy for Proxmox VE terminal sessions
//! Bridges browser xterm.js ↔ PVE termproxy WebSocket using PVE's packet protocol.

use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::Message;
use futures::StreamExt;
use tokio_tungstenite::tungstenite;
use tracing::{info, error, debug};

use super::AppState;

/// Certificate verifier that accepts all certs (for self-signed PVE TLS)
#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// WebSocket endpoint: /ws/pve-console/{node_id}/{vmid}
/// Connects to a Proxmox VE terminal through the termproxy API.
/// vmid=0 means "node shell" (PVE host terminal), vmid>0 means guest console.
pub async fn pve_console_ws(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let (node_id, vmid_str) = path.into_inner();

    let vmid: u64 = match vmid_str.parse() {
        Ok(v) => v,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid VMID" }))),
    };

    // Look up the PVE node
    let node = match state.cluster.get_node(&node_id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" }))),
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))),
    };

    let token = node.pve_token.clone().unwrap_or_default();
    let pve_name = node.pve_node_name.clone().unwrap_or_default();
    let fp = node.pve_fingerprint.clone();
    let address = node.address.clone();
    let port = node.port;

    let client = crate::proxmox::PveClient::new(&address, port, &token, fp.as_deref(), &pve_name);

    // Get termproxy ticket — node shell (vmid=0) or guest terminal (vmid>0)
    let (term_port, ticket, guest_type) = if vmid == 0 {
        // Node shell
        let (tp, tk, _user) = match client.node_termproxy().await {
            Ok(t) => t,
            Err(e) => {
                error!("PVE node termproxy failed: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })));
            }
        };
        info!("PVE node console on {}:{} -> termproxy port {}", address, port, tp);
        (tp, tk, "node".to_string())
    } else {
        // Guest terminal — determine type
        let guests = client.list_all_guests().await.unwrap_or_default();
        let gt = guests.iter()
            .find(|g| g.vmid == vmid)
            .map(|g| g.guest_type.clone())
            .unwrap_or_else(|| "lxc".to_string());

        let (tp, tk, _user) = match client.termproxy(vmid, &gt).await {
            Ok(t) => t,
            Err(e) => {
                error!("PVE termproxy failed for VMID {}: {}", vmid, e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })));
            }
        };
        info!("PVE console: {} VMID {} on {}:{} -> termproxy port {}", gt, vmid, address, port, tp);
        (tp, tk, gt)
    };

    // Upgrade to WebSocket on the browser side
    let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;

    // Spawn the bridge task
    actix_rt::spawn(pve_bridge(session, msg_stream, address, port, pve_name, term_port, ticket, token, fp, vmid, guest_type));

    Ok(res)
}

/// Bridge browser WS ↔ PVE termproxy WS
async fn pve_bridge(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    pve_host: String,
    pve_port: u16,
    pve_node: String,
    term_port: u16,
    ticket: String,
    token: String,
    _fingerprint: Option<String>,
    vmid: u64,
    guest_type: String,
) {
    // Build PVE WebSocket URL — percent-encode the ticket
    let vncticket: String = ticket.bytes().map(|b| {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            format!("{}", b as char)
        } else {
            format!("%{:02X}", b)
        }
    }).collect();
    // Node shell vs guest terminal have different WebSocket URLs
    let pve_ws_url = if guest_type == "node" {
        format!(
            "wss://{}:{}/api2/json/nodes/{}/vncwebsocket?port={}&vncticket={}",
            pve_host, pve_port, pve_node, term_port, vncticket
        )
    } else {
        format!(
            "wss://{}:{}/api2/json/nodes/{}/{}/{}/vncwebsocket?port={}&vncticket={}",
            pve_host, pve_port, pve_node, guest_type, vmid, term_port, vncticket
        )
    };
    debug!("Connecting to PVE WebSocket: {}", pve_ws_url);

    // Build TLS connector that accepts self-signed certs (PVE default)
    let tls_connector = {
        let mut builder = native_tls::TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        match builder.build() {
            Ok(c) => Some(tokio_tungstenite::Connector::NativeTls(c)),
            Err(e) => {
                error!("TLS connector error: {}", e);
                let _ = session.text(format!("\r\n\x1b[31mTLS error: {}\x1b[0m\r\n", e)).await;
                let _ = session.close(None).await;
                return;
            }
        }
    };

    // Connect to PVE WebSocket
    let ws_request = match tungstenite::client::IntoClientRequest::into_client_request(pve_ws_url.as_str()) {
        Ok(mut req) => {
            // Add PVE API auth header
            let auth = if token.starts_with("PVEAPIToken=") {
                token.clone()
            } else {
                format!("PVEAPIToken={}", token)
            };
            req.headers_mut().insert("Authorization", auth.parse().unwrap());
            req
        }
        Err(e) => {
            error!("Failed to build PVE WS request: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mConnection error: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };

    let pve_stream = match tokio_tungstenite::connect_async_tls_with_config(
        ws_request,
        None,
        false,
        tls_connector,
    ).await {
        Ok((stream, _response)) => stream,
        Err(e) => {
            error!("Failed to connect to PVE WebSocket: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mPVE WebSocket connection failed: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };

    let (mut pve_sink, mut pve_stream_rx) = pve_stream.split();

    // Send the ticket as the first message to authenticate with PVE termproxy
    // PVE expects the auth wrapped in termproxy protocol: 0:len:username:ticket\n
    let auth_payload = format!("{}:{}\n", _user_from_token(&token), ticket);
    let auth_msg = format!("0:{}:{}", auth_payload.len(), auth_payload);
    if let Err(e) = futures::SinkExt::send(&mut pve_sink, tungstenite::Message::Text(auth_msg)).await {
        error!("Failed to send PVE auth ticket: {}", e);
        let _ = session.close(None).await;
        return;
    }

    info!("PVE console bridge established for VMID {}", vmid);

    // Bridge loop
    loop {
        tokio::select! {
            // PVE → Browser: PVE sends terminal output wrapped in protocol (channel:length:data)
            // We need to strip the protocol prefix and forward only the data payload
            msg = pve_stream_rx.next() => {
                match msg {
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        // Parse PVE termproxy protocol: "channel:length:data"
                        // Channel 0 = terminal data, channel 1 = resize
                        let payload = if text.starts_with("0:") || text.starts_with("1:") {
                            // Find the second colon (after channel:length)
                            if let Some(first_colon) = text.find(':') {
                                if let Some(second_colon) = text[first_colon + 1..].find(':') {
                                    let data_start = first_colon + 1 + second_colon + 1;
                                    &text[data_start..]
                                } else {
                                    &text
                                }
                            } else {
                                &text
                            }
                        } else {
                            &text
                        };
                        if !payload.is_empty() {
                            if session.text(payload.to_string()).await.is_err() { break; }
                        }
                    }
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        if session.binary(data.to_vec()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Ping(data))) => {
                        let _ = futures::SinkExt::send(&mut pve_sink,
                            tungstenite::Message::Pong(data)).await;
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            // Browser → PVE: wrap in PVE termproxy protocol (0:len:msg)
            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let pve_msg = format!("0:{}:{}", text.len(), text);
                        if futures::SinkExt::send(&mut pve_sink,
                            tungstenite::Message::Text(pve_msg)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        let text = String::from_utf8_lossy(&data);
                        let pve_msg = format!("0:{}:{}", text.len(), text);
                        if futures::SinkExt::send(&mut pve_sink,
                            tungstenite::Message::Text(pve_msg)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        let _ = session.pong(&bytes).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    let _ = futures::SinkExt::close(&mut pve_sink).await;
    let _ = session.close(None).await;
    info!("PVE console session ended for VMID {}", vmid);
}

/// Extract username from PVE API token
/// Token format: "user@realm!tokenid=secret-uuid" or "PVEAPIToken=user@realm!tokenid=secret-uuid"
fn _user_from_token(token: &str) -> String {
    let t = token.strip_prefix("PVEAPIToken=").unwrap_or(token);
    // user@realm!tokenid=secret → user@realm
    if let Some(pos) = t.find('!') {
        t[..pos].to_string()
    } else {
        "root@pam".to_string()
    }
}
