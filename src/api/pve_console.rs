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

/// WebSocket endpoint: /ws/pve-console/{node_id}/{vmid}
/// Connects to a Proxmox VE guest terminal through the termproxy API.
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

    // Determine guest type
    let client = crate::proxmox::PveClient::new(&address, port, &token, fp.as_deref(), &pve_name);
    let guests = client.list_all_guests().await.unwrap_or_default();
    let guest_type = guests.iter()
        .find(|g| g.vmid == vmid)
        .map(|g| g.guest_type.clone())
        .unwrap_or_else(|| "lxc".to_string());

    // Get termproxy ticket
    let (term_port, ticket, _user) = match client.termproxy(vmid, &guest_type).await {
        Ok(t) => t,
        Err(e) => {
            error!("PVE termproxy failed for VMID {}: {}", vmid, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })));
        }
    };

    info!("PVE console: {} VMID {} on {}:{} -> termproxy port {}",
        guest_type, vmid, address, port, term_port);

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
    let pve_ws_url = format!(
        "wss://{}:{}/api2/json/nodes/{}/{}/{}/vncwebsocket?port={}&vncticket={}",
        pve_host, pve_port, pve_node, guest_type, vmid, term_port, vncticket
    );
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
    // PVE expects: username:ticket\n
    let auth_msg = format!("{}:{}\n", _user_from_token(&token), ticket);
    if let Err(e) = futures::SinkExt::send(&mut pve_sink, tungstenite::Message::Text(auth_msg)).await {
        error!("Failed to send PVE auth ticket: {}", e);
        let _ = session.close(None).await;
        return;
    }

    info!("PVE console bridge established for VMID {}", vmid);

    // Bridge loop
    loop {
        tokio::select! {
            // PVE → Browser: PVE sends raw terminal output
            msg = pve_stream_rx.next() => {
                match msg {
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        if session.text(text).await.is_err() { break; }
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
