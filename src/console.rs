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
use tracing::error;


/// WebSocket console endpoint: /ws/console/{type}/{name}
pub async fn console_ws(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    body: web::Payload,
    state: web::Data<crate::api::AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    // Require session authentication for WebSocket console access
    if let Err(resp) = crate::api::require_auth(&req, &state) {
        return Ok(resp);
    }

    let (container_type, container_name) = path.into_inner();

    // Validate container name to prevent command injection (except for compound install names)
    // k8s names use "cluster_id/pod/namespace[/container]" format — validate each part
    if container_type == "k8s" {
        for part in container_name.split('/') {
            if !part.is_empty() && !crate::auth::is_safe_name(part) {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid pod name"
                })));
            }
        }
    } else if container_type != "install" && container_type != "appstore-install" && container_type != "k8s-provision"
        && !crate::auth::is_safe_name(&container_name)
    {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid container name"
        })));
    }

    // Look up this node's custom update script (if any)
    let update_script = if container_type == "upgrade" {
        state.cluster.get_all_nodes().iter()
            .find(|n| n.is_self)
            .and_then(|n| n.update_script.clone())
    } else {
        None
    };

    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;

    // Use actix_rt::spawn (not tokio::spawn) so we can use non-Send types
    actix_rt::spawn(console_session(session, msg_stream, container_type, container_name, update_script));

    Ok(response)
}

async fn console_session(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    ctype: String,
    name: String,
    update_script: Option<String>,
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
                "docker exec -e TERM=xterm-256color -it {} /bin/bash --login 2>/dev/null || \
                 docker exec -e TERM=xterm-256color -it {} /bin/sh -l 2>/dev/null || \
                 docker exec -e TERM=xterm-256color -it {} /bin/ash 2>/dev/null || \
                 echo 'No shell available in this container'",
                name, name, name, 
            ));
        }
        "lxc" => {
            let base = crate::containers::lxc_base_dir(&name);
            let p_flag = if base != crate::containers::LXC_DEFAULT_PATH {
                format!("-P {} ", base)
            } else {
                String::new()
            };
            cmd.arg(format!(
                "lxc-attach {}-n {} --set-var TERM=xterm-256color -- /bin/sh -c \
                 'if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi'",
                p_flag, name
            ));
        }
        "vm" => {
            // Connect to QEMU serial console via socat
            let serial_sock = format!("/var/lib/wolfstack/vms/{}.serial.sock", name);
            cmd.arg(format!("socat -,raw,echo=0 UNIX-CONNECT:{}", serial_sock));
        }
        "pve-vm" => {
            // Deprecated — PVE VM consoles now use VNC via /ws/pve-vnc/{vmid}
            let _ = session.text("\r\n\x1b[33mPlease use the VNC console for Proxmox VMs.\x1b[0m\r\n").await;
            let _ = session.close(None).await;
            return;
        }
        "host" => {
            // Host shell — open an interactive login bash/sh session on this machine
            cmd.arg("if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi");
        }
        "k8s" => {
            // Kubernetes pod exec — name format: "cluster_id/pod_name/namespace[/container]"
            let parts: Vec<&str> = name.splitn(4, '/').collect();
            if parts.len() < 3 {
                let _ = session.text("\r\n\x1b[31mInvalid k8s console target (expected cluster/pod/namespace)\x1b[0m\r\n").await;
                let _ = session.close(None).await;
                return;
            }
            let cluster_id = parts[0];
            let pod_name = parts[1];
            let namespace = parts[2];
            let container_arg = if parts.len() >= 4 && !parts[3].is_empty() {
                format!("-c {} ", parts[3])
            } else {
                String::new()
            };
            let kubeconfig = match crate::kubernetes::get_cluster(cluster_id) {
                Some(c) => c.kubeconfig_path.clone(),
                None => {
                    let _ = session.text("\r\n\x1b[31mCluster not found\x1b[0m\r\n").await;
                    let _ = session.close(None).await;
                    return;
                }
            };
            let (binary, prefix_args) = crate::kubernetes::find_kubectl_pub();
            let kubectl_cmd = if prefix_args.is_empty() {
                binary.to_string()
            } else {
                format!("{} {}", binary, prefix_args.join(" "))
            };
            cmd.arg(format!(
                "{} --kubeconfig {} exec -it {} -n {} {}-e TERM=xterm-256color -- \
                 /bin/bash --login 2>/dev/null || \
                 {} --kubeconfig {} exec -it {} -n {} {}-e TERM=xterm-256color -- \
                 /bin/sh -l 2>/dev/null || \
                 echo 'No shell available in this pod'",
                kubectl_cmd, kubeconfig, pod_name, namespace, container_arg,
                kubectl_cmd, kubeconfig, pod_name, namespace, container_arg,
            ));
        }
        "upgrade" => {
            // WolfStack upgrade — use custom update script if configured, otherwise default
            let script = update_script.as_deref().unwrap_or(
                "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | sudo bash"
            );
            cmd.arg(script);
        }
        "install" => {
            // Component install — name format: "component" (host) or "component@docker:container" / "component@lxc:container"
            let (component, target) = if let Some(idx) = name.find('@') {
                (&name[..idx], Some(&name[idx+1..]))
            } else {
                (name.as_str(), None)
            };

            let install_script = match component {
                "wolfnet" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/wolfnet/setup.sh",
                "wolfproxy" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/master/wolfproxy/install.sh",
                "wolfserve" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/master/wolfserve/install.sh",
                "wolfdisk" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/wolfdisk/setup.sh",
                "wolfscale" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup_lb.sh",
                "mariadb" => "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/main/mariadb_setup.sh",
                "certbot" => "__inline_certbot__",
                _ => {
                    let _ = session.text(format!("\r\n\x1b[31mUnknown component: {}\x1b[0m\r\n", component)).await;
                    let _ = session.close(None).await;
                    return;
                }
            };

            // Certbot installs via package manager directly; other components use a remote script
            let certbot_inline = "if command -v apt-get >/dev/null 2>&1; then \
                apt-get update -qq && apt-get install -y certbot; \
                elif command -v dnf >/dev/null 2>&1; then \
                dnf install -y certbot; \
                elif command -v zypper >/dev/null 2>&1; then \
                zypper install -y certbot; \
                else echo 'Unsupported package manager' && exit 1; fi";
            let is_inline = install_script == "__inline_certbot__";

            match target {
                None | Some("host") => {
                    // Install on host
                    if is_inline {
                        cmd.arg(format!(
                            "echo '\\x1b[1;36mInstalling {} on this host...\\x1b[0m' && \
                             export DEBIAN_FRONTEND=noninteractive && \
                             {}; \
                             echo '' && echo '\\x1b[1;32mInstallation complete. You can close this terminal.\\x1b[0m'",
                            component, certbot_inline
                        ));
                    } else {
                        cmd.arg(format!(
                            "echo '\\x1b[1;36mInstalling {} on this host...\\x1b[0m' && \
                             export DEBIAN_FRONTEND=noninteractive && \
                             curl -fsSL '{}' | bash; \
                             echo '' && echo '\\x1b[1;32mInstallation complete. You can close this terminal.\\x1b[0m'",
                            component, install_script
                        ));
                    }
                }
                Some(target_str) => {
                    // target_str is "docker:name" or "lxc:name"
                    if let Some(idx) = target_str.find(':') {
                        let runtime = &target_str[..idx];
                        let container = &target_str[idx+1..];
                        match runtime {
                            "docker" => {
                                if is_inline {
                                    cmd.arg(format!(
                                        "echo '\\x1b[1;36mInstalling {} in Docker container {}...\\x1b[0m' && \
                                         docker exec -e DEBIAN_FRONTEND=noninteractive -e TERM=xterm-256color -it {} sh -c \
                                         '{}'; \
                                         echo '' && echo '\\x1b[1;32mInstallation complete. You can close this terminal.\\x1b[0m'",
                                        component, container, container, certbot_inline
                                    ));
                                } else {
                                    cmd.arg(format!(
                                        "echo '\\x1b[1;36mInstalling {} in Docker container {}...\\x1b[0m' && \
                                         docker exec -e DEBIAN_FRONTEND=noninteractive -e TERM=xterm-256color -it {} sh -c \
                                         'apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || \
                                          yum install -y -q curl 2>/dev/null || \
                                          apk add --quiet curl 2>/dev/null || true && \
                                          curl -fsSL \"{}\" | bash'; \
                                         echo '' && echo '\\x1b[1;32mInstallation complete. You can close this terminal.\\x1b[0m'",
                                        component, container, container, install_script
                                    ));
                                }
                            }
                            "lxc" => {
                                let lxc_base = crate::containers::lxc_base_dir(container);
                                let lxc_p = if lxc_base != crate::containers::LXC_DEFAULT_PATH {
                                    format!("-P {} ", lxc_base)
                                } else {
                                    String::new()
                                };
                                if is_inline {
                                    cmd.arg(format!(
                                        "echo '\\x1b[1;36mInstalling {} in LXC container {}...\\x1b[0m' && \
                                         lxc-attach {}-n {} --set-var TERM=xterm-256color --set-var DEBIAN_FRONTEND=noninteractive -- sh -c \
                                         '{}'; \
                                         echo '' && echo '\\x1b[1;32mInstallation complete. You can close this terminal.\\x1b[0m'",
                                        component, container, lxc_p, container, certbot_inline
                                    ));
                                } else {
                                    cmd.arg(format!(
                                        "echo '\\x1b[1;36mInstalling {} in LXC container {}...\\x1b[0m' && \
                                         lxc-attach {}-n {} --set-var TERM=xterm-256color --set-var DEBIAN_FRONTEND=noninteractive -- sh -c \
                                         'apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || \
                                          yum install -y -q curl 2>/dev/null || \
                                          apk add --quiet curl 2>/dev/null || true && \
                                          curl -fsSL \"{}\" | bash'; \
                                         echo '' && echo '\\x1b[1;32mInstallation complete. You can close this terminal.\\x1b[0m'",
                                        component, container, lxc_p, container, install_script
                                    ));
                                }
                            }
                            _ => {
                                let _ = session.text(format!("\r\n\x1b[31mUnsupported runtime: {}\x1b[0m\r\n", runtime)).await;
                                let _ = session.close(None).await;
                                return;
                            }
                        }
                    } else {
                        let _ = session.text("\r\n\x1b[31mInvalid target format. Use: component@runtime:container\x1b[0m\r\n").await;
                        let _ = session.close(None).await;
                        return;
                    }
                }
            }
        }
        "appstore-install" | "k8s-provision" => {
            // Script-based install — name is the session ID from prepare-install/prepare-provision API
            let prefix = if ctype == "k8s-provision" { "wolfstack-k8s-provision" } else { "wolfstack-appinstall" };
            let script_path = format!("/tmp/{}-{}.sh", prefix, name);
            if !std::path::Path::new(&script_path).exists() {
                let _ = session.text(format!(
                    "\r\n\x1b[31mInstall script not found: {}\r\nDid you call prepare-install first?\x1b[0m\r\n",
                    script_path
                )).await;
                let _ = session.close(None).await;
                return;
            }
            // Use script(1) to create a clean PTY session that closes properly
            // even if background processes (e.g. k3s systemd service) inherit fds.
            // The exec at the end ensures the shell exits when the script finishes.
            cmd.arg(format!(
                "exec bash -c 'bash {} 2>&1; EXIT_CODE=$?; rm -f {}; \
                 if [ $EXIT_CODE -ne 0 ]; then \
                   echo; printf \"\\033[1;31m━━━ Installation failed (exit code %s) ━━━\\033[0m\\n\" $EXIT_CODE; \
                   printf \"\\033[0;90mScroll up to see the error details.\\033[0m\\n\"; \
                 fi; \
                 echo; printf \"\\033[0;90mDone.\\033[0m\\n\"; \
                 exit $EXIT_CODE'",
                script_path, script_path
            ));
        }
        _ => {
            let _ = session.text("\r\n\x1b[31mUnknown container type\x1b[0m\r\n").await;
            let _ = session.close(None).await;
            return;
        }
    }

    let child = match pty_pair.slave.spawn_command(cmd) {
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

    let master = pty_pair.master;
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

    // For script-based sessions (installs, provisioning), monitor when the child
    // process exits. Background processes (e.g. k3s systemd services) can inherit
    // PTY file descriptors, which prevents the PTY reader from getting EOF even
    // after the main script finishes. By watching the child directly, we can close
    // the session promptly when the script completes.
    let is_script_session = ctype == "install" || ctype == "appstore-install" || ctype == "k8s-provision";
    let (child_exit_tx, mut child_exit_rx) = tokio::sync::oneshot::channel::<()>();
    let mut child_opt = Some(child);
    let child_exit_handle = if is_script_session {
        let mut child = child_opt.take().unwrap();
        Some(tokio::task::spawn_blocking(move || {
            let _ = child.wait();
            let _ = child_exit_tx.send(());
        }))
    } else {
        None
    };

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
            // Child process exited — drain remaining output, then close
            Ok(()) = &mut child_exit_rx => {
                // Give PTY reader a moment to flush remaining output
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                while let Ok(data) = rx.try_recv() {
                    let text = String::from_utf8_lossy(&data).to_string();
                    if session.text(text).await.is_err() { break; }
                }
                break;
            }
            // WebSocket input → PTY
            Some(Ok(msg)) = msg_stream.recv() => {
                use actix_ws::Message;
                match msg {
                    Message::Text(text) => {
                        // Check for resize command: {"type":"resize","cols":N,"rows":N}
                        if text.starts_with('{') {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                                if v.get("type").and_then(|t| t.as_str()) == Some("resize") {
                                    if let (Some(cols), Some(rows)) = (
                                        v.get("cols").and_then(|c| c.as_u64()),
                                        v.get("rows").and_then(|r| r.as_u64()),
                                    ) {
                                        let _ = master.resize(PtySize {
                                            rows: rows as u16,
                                            cols: cols as u16,
                                            pixel_width: 0,
                                            pixel_height: 0,
                                        });
                                    }
                                    continue;
                                }
                            }
                        }
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
    if let Some(mut child) = child_opt {
        // Non-script sessions: child is still owned here
        let _ = child.kill();
    }
    if let Some(h) = child_exit_handle { h.abort(); }
    read_handle.abort();
    let _ = session.close(None).await;

}

/// WebSocket proxy endpoint: /ws/remote-console/{node_id}/{type}/{name}
/// Bridges browser WS ↔ remote node's /ws/console/{type}/{name}
pub async fn remote_console_ws(
    req: HttpRequest,
    path: web::Path<(String, String, String)>,
    body: web::Payload,
    state: web::Data<crate::api::AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    // Require session authentication
    if let Err(resp) = crate::api::require_auth(&req, &state) {
        return Ok(resp);
    }

    let (node_id, ctype, name) = path.into_inner();

    // Validate name to prevent command injection
    if ctype != "install" && ctype != "appstore-install" && ctype != "k8s-provision" && ctype != "pve-vnc"
        && !crate::auth::is_safe_name(&name)
    {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid container name"
        })));
    }

    // Look up the node
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))),
    };

    if node.is_self {
        return console_ws(req, web::Path::from((ctype, name)), body, state).await;
    }

    let secret = state.cluster_secret.clone();
    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;
    actix_rt::spawn(remote_console_bridge(session, msg_stream, node.address, node.port, ctype, name, secret));
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
    cluster_secret: String,
) {
    // Simple percent-encode for URL path
    let encoded_name: String = name.bytes().map(|b| {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            format!("{}", b as char)
        } else {
            format!("%{:02X}", b)
        }
    }).collect();

    // PVE VNC uses a dedicated endpoint, not the generic console handler
    let ws_path = if ctype == "pve-vnc" {
        format!("/ws/pve-vnc/{}", encoded_name)
    } else {
        format!("/ws/console/{}/{}", ctype, encoded_name)
    };
    let internal_port = remote_port + 1;

    // URLs to try in order: wss main, ws internal, ws main
    let urls = vec![
        format!("wss://{}:{}{}", remote_host, remote_port, ws_path),
        format!("ws://{}:{}{}", remote_host, internal_port, ws_path),
        format!("ws://{}:{}{}", remote_host, remote_port, ws_path),
    ];

    // Build TLS connector that accepts self-signed certs (native-tls)
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
        let mut ws_request = match tungstenite::client::IntoClientRequest::into_client_request(url.as_str()) {
            Ok(req) => req,
            Err(_) => continue,
        };
        // Authenticate with remote node via cluster secret
        if let Ok(val) = tungstenite::http::HeaderValue::from_str(&cluster_secret) {
            ws_request.headers_mut().insert("X-WolfStack-Secret", val);
        }

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
                remote_stream = Some(stream);
                break;
            }
            Ok(Err(e)) => {
                error!("Remote console WS error for {}: {}", url, e);
            }
            Err(_) => {
                error!("Remote console WS timeout for {}", url);
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

}

