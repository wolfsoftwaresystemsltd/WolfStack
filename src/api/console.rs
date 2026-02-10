use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::Message;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write};
use tokio::sync::mpsc;
use futures::StreamExt;
use tracing::{info, error};

pub async fn console_ws(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<(String, String)>, // type, name
) -> Result<HttpResponse, Error> {
    let (container_type, name) = path.into_inner();
    let (res, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    info!("Starting console for {} container: {}", container_type, name);

    // Channel for PTY output -> WS
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    
    // Channel for WS input -> PTY
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1024);
    // Channel for resize events (optional future use)
    let (resize_tx, _resize_rx) = mpsc::channel::<(u16, u16)>(10);

    // Spawn PTY thread (blocking)
    std::thread::spawn(move || {
        let pty_system = NativePtySystem::default();
        // Default size, maybe configurable later
        let pair = pty_system.openpty(PtySize {
            rows: 24, cols: 80, pixel_width: 0, pixel_height: 0,
        });

        match pair {
            Ok(pair) => {
                let mut cmd = if container_type == "lxc" {
                    let mut c = CommandBuilder::new("lxc-attach");
                    c.args(&["-n", &name, "--", "/bin/bash"]);
                    c.env("TERM", "xterm-256color");
                    c
                } else {
                    let mut c = CommandBuilder::new("docker");
                    c.args(&["exec", "-it", &name, "/bin/bash"]);
                    c.env("TERM", "xterm-256color");
                    c
                };

                match pair.slave.spawn_command(cmd) {
                    Ok(mut child) => {
                        let mut reader = pair.master.try_clone_reader().unwrap();
                        let mut writer = pair.master.take_writer().unwrap();

                        // PTY Reader Thread
                        let tx_clone = tx.clone();
                        std::thread::spawn(move || {
                            let mut buf = [0u8; 4096];
                            loop {
                                match reader.read(&mut buf) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if tx_clone.blocking_send(buf[0..n].to_vec()).is_err() { break; }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });

                        // PTY Writer Loop
                        while let Some(data) = input_rx.blocking_recv() {
                            if writer.write_all(&data).is_err() { break; }
                            let _ = writer.flush();
                        }
                        
                        let _ = child.kill(); 
                    },
                    Err(e) => {
                        error!("Failed to spawn command: {}", e);
                        let _ = tx.blocking_send(format!("Error: {}\r\n", e).into_bytes());
                    }
                }
            },
            Err(e) => {
                error!("Failed to open PTY: {}", e);
                let _ = tx.blocking_send(format!("Error: PTY failed {}\r\n", e).into_bytes());
            }
        }
    });

    // Main Async Loop
    actix_rt::spawn(async move {
        loop {
            tokio::select! {
                // PTY -> WebSocket
                Some(bytes) = rx.recv() => {
                    if session.binary(bytes).await.is_err() { break; }
                }

                // WebSocket -> PTY
                Some(Ok(msg)) = msg_stream.next() => {
                    match msg {
                        Message::Text(text) => {
                            let _ = input_tx.send(text.as_bytes().to_vec()).await;
                        }
                        Message::Binary(bin) => {
                            let _ = input_tx.send(bin.to_vec()).await;
                        }
                        Message::Close(_) => break,
                        Message::Ping(bytes) => {
                            if session.pong(&bytes).await.is_err() { break; }
                        }
                        _ => {}
                    }
                }
                
                else => break,
            }
        }
        let _ = session.close(None).await;
    });

    Ok(res)
}
