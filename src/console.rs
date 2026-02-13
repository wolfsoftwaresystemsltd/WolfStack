// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WebSocket console handler — provides interactive terminal sessions
//! for Docker and LXC containers via docker exec / lxc-attach.

use actix_web::{web, HttpRequest, HttpResponse};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::sync::Arc;
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
