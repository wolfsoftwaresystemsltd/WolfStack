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
    let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;

    info!("Starting console for {} container: {}", container_type, name);

    // Channel for PTY output -> WS
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    
    // Channel for WS input -> PTY
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Spawn PTY thread (blocking)
    let ctype = container_type.clone();
    let cname = name.clone();
    std::thread::spawn(move || {
        let pty_system = NativePtySystem::default();
        let pair = match pty_system.openpty(PtySize {
            rows: 30, cols: 120, pixel_width: 0, pixel_height: 0,
        }) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to open PTY: {}", e);
                let _ = tx.blocking_send(format!("\r\nError: Failed to open PTY: {}\r\n", e).into_bytes());
                return;
            }
        };

        let cmd = if ctype == "lxc" {
            let mut c = CommandBuilder::new("lxc-attach");
            c.args(&["-n", &cname, "--", "/bin/sh", "-c", 
                "if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi"]);
            c.env("TERM", "xterm-256color");
            c
        } else if ctype == "host" {
            // Direct host shell — no container exec
            let mut c = CommandBuilder::new("/bin/bash");
            c.args(&["--login"]);
            c.env("TERM", "xterm-256color");
            c
        } else if ctype == "upgrade" {
            // Run the WolfStack upgrade script with live output
            let mut c = CommandBuilder::new("/bin/bash");
            c.args(&["-c",
                "echo '⚡ Starting WolfStack upgrade...'; echo ''; \
                 curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash; \
                 EXIT_CODE=$?; echo ''; \
                 if [ $EXIT_CODE -eq 0 ]; then \
                   echo '✅ Upgrade completed successfully.'; \
                 else \
                   echo \"❌ Upgrade failed with exit code $EXIT_CODE\"; \
                 fi; \
                 echo ''; echo 'You may close this window.'"]);
            c.env("TERM", "xterm-256color");
            c
        } else {
            let mut c = CommandBuilder::new("docker");
            // Use -it: -i keeps stdin open, -t allocates a TTY inside the container
            // (portable-pty provides the host-side PTY, but docker needs -t to know it's interactive)
            c.args(&["exec", "-it", &cname, "/bin/sh", "-c",
                "if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi"]);
            c.env("TERM", "xterm-256color");
            c
        };

        let child = match pair.slave.spawn_command(cmd) {
            Ok(child) => child,
            Err(e) => {
                error!("Failed to spawn command in container {}: {}", cname, e);
                let _ = tx.blocking_send(format!("\r\nError: Failed to spawn shell: {}\r\n", e).into_bytes());
                return;
            }
        };

        // IMPORTANT: Drop the slave handle so reads on master don't block forever
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().unwrap();
        let writer = pair.master.take_writer().unwrap();

        // PTY Reader Thread -> sends output to WS channel
        let tx_clone = tx.clone();
        let reader_thread = std::thread::spawn(move || {
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

        // PTY Writer Loop <- receives input from WS channel
        let mut writer = writer;
        while let Some(data) = input_rx.blocking_recv() {
            if writer.write_all(&data).is_err() { break; }
            let _ = writer.flush();
        }

        // Cleanup
        drop(writer);
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader_thread.join();
    });

    // Main Async Loop: bridge WS <-> PTY channels
    let mut session = session;
    let mut msg_stream = msg_stream;
    actix_rt::spawn(async move {
        loop {
            tokio::select! {
                // PTY -> WebSocket
                Some(bytes) = rx.recv() => {
                    if session.binary(bytes).await.is_err() { break; }
                }

                // WebSocket -> PTY
                msg = msg_stream.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            let _ = input_tx.send(text.as_bytes().to_vec()).await;
                        }
                        Some(Ok(Message::Binary(bin))) => {
                            let _ = input_tx.send(bin.to_vec()).await;
                        }
                        Some(Ok(Message::Ping(bytes))) => {
                            if session.pong(&bytes).await.is_err() { break; }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => {}
                    }
                }
            }
        }
        let _ = session.close(None).await;
    });

    Ok(res)
}
