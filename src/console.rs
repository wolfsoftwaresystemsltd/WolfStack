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

/// Certificate verifier that accepts all certs (for self-signed inter-node TLS)
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
    cmd.env("TERM", "xterm-256color");
    match ctype.as_str() {
        "docker" => {
            cmd.arg(format!(
                "docker exec -e TERM=xterm-256color -it {} /bin/sh -c \
                 'if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi'",
                name
            ));
        }
        "lxc" => {
            cmd.arg(format!(
                "lxc-attach -n {} --set-var TERM=xterm-256color -- /bin/sh -c \
                 'if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi'",
                name
            ));
        }
        "vm" => {
            // Connect to QEMU serial console via socat
            let serial_sock = format!("/var/lib/wolfstack/vms/{}.serial.sock", name);
            cmd.arg(format!("socat -,raw,echo=0 UNIX-CONNECT:{}", serial_sock));
        }
        "host" => {
            // Host shell — open an interactive login bash/sh session on this machine
            cmd.arg("if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi");
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
/// Opens a local PTY that SSH's into the remote node for the requested console.
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

    let remote_host = node.address.clone();
    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;

    // Build SSH command based on console type
    let ssh_cmd = match ctype.as_str() {
        "host" => format!(
            "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -t root@{} \
             'export TERM=xterm-256color; if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi'",
            remote_host
        ),
        "docker" => format!(
            "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -t root@{} \
             'docker exec -e TERM=xterm-256color -it {} /bin/sh -c \"if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi\"'",
            remote_host, name
        ),
        "lxc" => format!(
            "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -t root@{} \
             'lxc-attach -n {} --set-var TERM=xterm-256color -- /bin/sh -c \"if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi\"'",
            remote_host, name
        ),
        "upgrade" => format!(
            "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -t root@{} \
             'curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/main/setup.sh | bash'",
            remote_host
        ),
        _ => {
            let mut session = session;
            let _ = session.text("\r\n\x1b[31mUnknown container type\x1b[0m\r\n").await;
            let _ = session.close(None).await;
            return Ok(response);
        }
    };

    actix_rt::spawn(remote_ssh_session(session, msg_stream, ssh_cmd, ctype, name, remote_host));
    Ok(response)
}

/// Run a remote console via SSH through a local PTY
async fn remote_ssh_session(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    ssh_cmd: String,
    ctype: String,
    name: String,
    remote_host: String,
) {
    use portable_pty::{CommandBuilder, native_pty_system, PtySize};

    let pty_system = native_pty_system();
    let pty_pair = match pty_system.openpty(PtySize {
        rows: 30, cols: 120, pixel_width: 0, pixel_height: 0,
    }) {
        Ok(pair) => pair,
        Err(e) => {
            error!("Failed to open PTY for remote SSH: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mFailed to open PTY: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };

    let mut cmd = CommandBuilder::new("sh");
    cmd.arg("-c");
    cmd.arg(&ssh_cmd);
    cmd.env("TERM", "xterm-256color");

    let mut child = match pty_pair.slave.spawn_command(cmd) {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to spawn SSH: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mFailed to start SSH: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };
    drop(pty_pair.slave);

    let reader = pty_pair.master.try_clone_reader().unwrap();
    let writer = std::sync::Arc::new(std::sync::Mutex::new(pty_pair.master.take_writer().unwrap()));

    // Read PTY output in a blocking task
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    let read_handle = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut reader = reader;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });

    // Bridge: PTY ↔ browser WebSocket
    loop {
        tokio::select! {
            Some(bytes) = rx.recv() => {
                if session.binary(bytes).await.is_err() { break; }
            }
            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(actix_ws::Message::Text(text))) => {
                        let w = writer.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            use std::io::Write;
                            if let Ok(mut w) = w.lock() {
                                let _ = w.write_all(text.as_bytes());
                                let _ = w.flush();
                            }
                        }).await;
                    }
                    Some(Ok(actix_ws::Message::Binary(data))) => {
                        let w = writer.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            use std::io::Write;
                            if let Ok(mut w) = w.lock() {
                                let _ = w.write_all(&data);
                                let _ = w.flush();
                            }
                        }).await;
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

    let _ = child.kill();
    read_handle.abort();
    let _ = session.close(None).await;
    info!("Remote SSH session ended for {} {} on {}", ctype, name, remote_host);
}
