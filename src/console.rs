// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WebSocket console handler — provides interactive terminal sessions
//! for Docker and LXC containers via docker exec / lxc-attach.

use actix_web::{web, HttpRequest, HttpResponse};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::sync::Arc;
use futures::StreamExt;
use tokio_tungstenite::tungstenite;
use tracing::{info, error};

/// WebSocket console endpoint: /ws/console/{type}/{name}
pub async fn console_ws(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    body: web::Payload,
) -> Result<HttpResponse, actix_web::Error> {
    let (container_type, container_name) = path.into_inner();
    info!("Console WebSocket request: {} {}", container_type, container_name);

    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;

    // Use actix_rt::spawn (not tokio::spawn) so we can use non-Send types
    actix_rt::spawn(console_session(session, msg_stream, container_type, container_name));

    Ok(response)
}

async fn console_session(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    ctype: String,
    name: String,
) {
    // Create PTY
    let pty_system = native_pty_system();
    let pty_pair = match pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    }) {
        Ok(pair) => pair,
        Err(e) => {
            error!("Failed to open PTY: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mFailed to open PTY: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };

    // Build command based on container type
    let mut cmd = CommandBuilder::new("sh");
    cmd.arg("-c");
    match ctype.as_str() {
        "docker" => {
            cmd.arg(format!("docker exec -it {} /bin/bash 2>/dev/null || docker exec -it {} /bin/sh", name, name));
        }
        "lxc" => {
            cmd.arg(format!("lxc-attach -n {} -- /bin/bash 2>/dev/null || lxc-attach -n {} -- /bin/sh", name, name));
        }
        "vm" => {
            // Connect to QEMU serial console via socat
            let serial_sock = format!("/var/lib/wolfstack/vms/{}.serial.sock", name);
            cmd.arg(format!("socat -,raw,echo=0 UNIX-CONNECT:{}", serial_sock));
        }
        "host" => {
            // Host shell — open an interactive bash/sh session on this machine
            cmd.arg("bash 2>/dev/null || sh");
        }
        "upgrade" => {
            // WolfStack upgrade — re-run the setup script
            cmd.arg("curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/main/setup.sh | bash");
        }
        _ => {
            let _ = session.text("\r\n\x1b[31mUnknown container type\x1b[0m\r\n").await;
            let _ = session.close(None).await;
            return;
        }
    }

    let mut child = match pty_pair.slave.spawn_command(cmd) {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to spawn command: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mFailed to start shell: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };
    drop(pty_pair.slave);

    // Get reader and writer from master
    let reader = match pty_pair.master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to clone PTY reader: {}", e);
            let _ = session.close(None).await;
            return;
        }
    };

    let writer = match pty_pair.master.take_writer() {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to get PTY writer: {}", e);
            let _ = session.close(None).await;
            return;
        }
    };

    let _master = pty_pair.master;
    let writer = Arc::new(std::sync::Mutex::new(writer));

    // Channel to forward PTY output to the async context
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Blocking task: Read from PTY → send to channel
    let read_handle = tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Main loop: multiplex between PTY output and WebSocket input
    loop {
        tokio::select! {
            // PTY output → WebSocket
            Some(data) = rx.recv() => {
                let text = String::from_utf8_lossy(&data).to_string();
                if session.text(text).await.is_err() {
                    break;
                }
            }
            // WebSocket input → PTY
            Some(Ok(msg)) = msg_stream.recv() => {
                use actix_ws::Message;
                match msg {
                    Message::Text(text) => {
                        if let Ok(mut w) = writer.lock() {
                            let _ = w.write_all(text.as_bytes());
                        }
                    }
                    Message::Binary(data) => {
                        if let Ok(mut w) = writer.lock() {
                            let _ = w.write_all(&data);
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(data) => {
                        let _ = session.pong(&data).await;
                    }
                    _ => {}
                }
            }
            else => break,
        }
    }

    // Cleanup
    let _ = child.kill();
    read_handle.abort();
    let _ = session.close(None).await;
    info!("Console session ended for {} {}", ctype, name);
}

/// WebSocket proxy endpoint: /ws/remote-console/{node_id}/{type}/{name}
/// Bridges browser WS ↔ remote node's /ws/console/{type}/{name}
pub async fn remote_console_ws(
    req: HttpRequest,
    path: web::Path<(String, String, String)>,
    body: web::Payload,
    state: web::Data<crate::api::AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let (node_id, ctype, name) = path.into_inner();
    info!("Remote console proxy: node={} type={} name={}", node_id, ctype, name);

    // Look up the node
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))),
    };

    if node.is_self {
        // Self node — use local console directly
        return console_ws(req, web::Path::from((ctype, name)), body).await;
    }

    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;
    actix_rt::spawn(remote_console_bridge(session, msg_stream, node.address, node.port, ctype, name));
    Ok(response)
}

/// Bridge browser WS ↔ remote node's console WS
async fn remote_console_bridge(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    remote_host: String,
    remote_port: u16,
    ctype: String,
    name: String,
) {
    // Simple percent-encode for URL path
    let encoded_name: String = name.bytes().map(|b| {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            format!("{}", b as char)
        } else {
            format!("%{:02X}", b)
        }
    }).collect();
    let ws_path = format!("/ws/console/{}/{}", ctype, encoded_name);
    let internal_port = remote_port + 1;

    // URLs to try in order: wss main, ws internal, ws main
    let urls = vec![
        format!("wss://{}:{}{}", remote_host, remote_port, ws_path),
        format!("ws://{}:{}{}", remote_host, internal_port, ws_path),
        format!("ws://{}:{}{}", remote_host, remote_port, ws_path),
    ];

    // Build TLS connector that accepts self-signed certs
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

    let mut remote_stream = None;

    for url in &urls {
        let ws_request = match tungstenite::client::IntoClientRequest::into_client_request(url.as_str()) {
            Ok(req) => req,
            Err(_) => continue,
        };

        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio_tungstenite::connect_async_tls_with_config(
                ws_request,
                None,
                false,
                tls_connector.clone(),
            ),
        ).await {
            Ok(Ok((stream, _))) => {
                info!("Remote console connected via {}", url);
                remote_stream = Some(stream);
                break;
            }
            Ok(Err(e)) => {
                info!("Remote console {} failed: {}", url, e);
            }
            Err(_) => {
                info!("Remote console {} timed out", url);
            }
        }
    }

    let remote_ws = match remote_stream {
        Some(s) => s,
        None => {
            let _ = session.text(format!(
                "\r\n\x1b[31mCould not connect to remote console on {}:{}\x1b[0m\r\n",
                remote_host, remote_port
            )).await;
            let _ = session.close(None).await;
            return;
        }
    };

    let (mut remote_sink, mut remote_rx) = remote_ws.split();

    // Bridge loop
    loop {
        tokio::select! {
            // Remote → Browser
            msg = remote_rx.next() => {
                match msg {
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        if session.text(text.to_string()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        if session.binary(data.to_vec()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Ping(data))) => {
                        let _ = futures::SinkExt::send(&mut remote_sink,
                            tungstenite::Message::Pong(data)).await;
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            // Browser → Remote
            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(actix_ws::Message::Text(text))) => {
                        if futures::SinkExt::send(&mut remote_sink,
                            tungstenite::Message::Text(text.to_string())).await.is_err() { break; }
                    }
                    Some(Ok(actix_ws::Message::Binary(data))) => {
                        if futures::SinkExt::send(&mut remote_sink,
                            tungstenite::Message::Binary(data.to_vec())).await.is_err() { break; }
                    }
                    Some(Ok(actix_ws::Message::Ping(bytes))) => {
                        let _ = session.pong(&bytes).await;
                    }
                    Some(Ok(actix_ws::Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    let _ = futures::SinkExt::close(&mut remote_sink).await;
    let _ = session.close(None).await;
    info!("Remote console session ended for {} {} on {}", ctype, name, remote_host);
}
