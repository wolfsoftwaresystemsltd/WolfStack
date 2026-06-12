// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Cluster Browser reverse proxy — tunnels every browser-session
//! HTTP request and WebSocket upgrade through WolfStack's own port
//! (8553) instead of exposing per-session ports (33000-33999) directly.
//!
//! Why: browsers/CDNs/reverse proxies in real deployments routinely
//! restrict ws(s) traffic to 80/443/8080. A selkies stream on
//! ws://host:33001 works on a LAN but falls over behind Cloudflare,
//! corporate HTTP proxies, or any setup that only allows well-known
//! ports through. Routing everything over the same port WolfStack
//! already listens on means the cluster browser works wherever
//! WolfStack does. Same pattern used by /ws/console and /ws/pve-vnc.
//!
//! Route: /api/cluster-browser/session/{id}/{tail:.*}
//!   - auth-gated (cookie session)
//!   - strips the /api/cluster-browser/session/{id}/ prefix
//!   - WebSocket upgrades bridged via tokio-tungstenite
//!   - plain HTTP proxied via reqwest with streaming bodies

use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::Message;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;
use tracing::{error, warn};

use super::AppState;

/// Shared HTTP client for proxying cluster-browser session traffic.
/// Previously a fresh Client was built per request — one pool leak
/// per proxied browser request. redirect::none() is preserved
/// because selkies sessions rely on exact-status pass-through (no
/// transparent redirect following).
static BROWSER_PROXY_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Headers that must NOT be copied end-to-end (hop-by-hop per RFC 7230).
/// Also strip `host` since reqwest sets it from the target URL.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// Look up a session's upstream target (host + port) and node_id. The
/// host is "127.0.0.1" for docker-backed sessions and the Service
/// ClusterIP for kubernetes-backed sessions — kube-proxy programs DNAT
/// rules into the host's iptables, so the daemon (in the host's net
/// namespace) can dial the ClusterIP directly. Returns None if no
/// matching session exists on this node — the caller turns that into
/// a 404 or queries other nodes.
fn session_target(id: &str) -> Option<(String, u16, String)> {
    crate::cluster_browser::list_sessions()
        .into_iter()
        .find(|s| s.id == id)
        .map(|s| (s.target_host, s.web_port, s.node_id))
}

/// Proxy a cluster browser request to a remote node. Makes a direct HTTP request to
/// the remote node's cluster browser proxy endpoint, preserving the original request
/// method, headers, and body.
async fn node_proxy_request(
    req: &HttpRequest,
    state: web::Data<AppState>,
    node_id: &str,
    session_id: &str,
    tail: String,
    mut payload: web::Payload,
) -> Result<HttpResponse, Error> {
    use futures::StreamExt as _;

    // Look up the node
    let node = match state.cluster.get_node(node_id) {
        Some(n) => n,
        None => {
            return Ok(HttpResponse::NotFound()
                .json(serde_json::json!({"error": "Remote session node not found"})));
        }
    };

    // Buffer the full request body
    let method = req.method().clone();
    let mut body_bytes = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(actix_web::error::ErrorBadRequest)?;
        body_bytes.extend_from_slice(&chunk);
    }

    // Build target URL on remote node (same endpoint this handler provides)
    let query_string = req.query_string();
    let scheme = if node.tls { "https" } else { "http" };
    let node_host = crate::netaddr::bracket_host(&node.address);
    let target = if query_string.is_empty() {
        format!("{}://{}:{}/api/cluster-browser/session/{}/{}", scheme, node_host, node.port, session_id, tail)
    } else {
        format!("{}://{}:{}/api/cluster-browser/session/{}{}?{}", scheme, node_host, node.port, session_id, tail, query_string)
    };

    // Build the request using the shared browser proxy client
    let mut builder = match method {
        actix_web::http::Method::GET => BROWSER_PROXY_CLIENT.get(&target),
        actix_web::http::Method::POST => BROWSER_PROXY_CLIENT.post(&target),
        actix_web::http::Method::PUT => BROWSER_PROXY_CLIENT.put(&target),
        _ => BROWSER_PROXY_CLIENT.get(&target),
    };

    // Copy headers (skip hop-by-hop)
    for (name, val) in req.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let Ok(v) = val.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    // Add inter-node auth
    builder = builder.header("X-WolfStack-Secret", state.cluster_secret.clone());

    // Add body if present
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.freeze());
    }

    // Execute the request
    match builder.send().await {
        Ok(upstream) => {
            let status = upstream.status().as_u16();
            let resp_ct = upstream
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            match upstream.bytes().await {
                Ok(bytes) => {
                    Ok(HttpResponse::build(
                        actix_web::http::StatusCode::from_u16(status)
                            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
                    )
                    .content_type(resp_ct)
                    .body(bytes.to_vec()))
                }
                Err(e) => {
                    warn!("Failed to read remote proxy response: {}", e);
                    Ok(HttpResponse::BadGateway().body(format!("Failed to read response: {}", e)))
                }
            }
        }
        Err(e) => {
            warn!("cluster_browser remote proxy error to {}: {}", target, e);
            Ok(HttpResponse::BadGateway().body(format!("Remote proxy error: {}", e)))
        }
    }
}

/// Unified entry point: same URL serves HTTP assets, SPA JS, and the
/// selkies /websocket upgrade — actix routes both through here. We
/// peek at the `Upgrade` header to pick the bridge vs the HTTP path.
pub async fn cluster_browser_proxy(
    req: HttpRequest,
    state: web::Data<AppState>,
    payload: web::Payload,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) {
        return Ok(resp);
    }

    let (id, tail) = path.into_inner();
    let (host, port, session_node_id) = match session_target(&id) {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::NotFound()
                .json(serde_json::json!({ "error": "Session not found on this node" })));
        }
    };

    // Check if session is on a remote node. If so, proxy through that node's
    // cluster browser endpoint directly.
    let self_node_id = crate::agent::self_node_id();
    if session_node_id != self_node_id {
        // Session is on a remote node — proxy the request directly to that node
        return node_proxy_request(&req, state, &session_node_id, &id, tail, payload).await;
    }

    let upgrade_is_ws = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if upgrade_is_ws {
        proxy_websocket(req, payload, &host, port, tail).await
    } else {
        proxy_http(req, payload, &host, port, tail).await
    }
}

/// HTTP proxy leg — reissues the client's request against
/// http://{host}:{port}/{tail}?{query}. `host` is "127.0.0.1" for
/// docker-backed sessions or the Service ClusterIP for kubernetes-
/// backed sessions; in both cases it's reachable from the WolfStack
/// daemon's namespace so we don't punch out of the host. Selkies asset
/// bundles are chunked/streaming, so we pipe the body rather than
/// buffering.
async fn proxy_http(
    req: HttpRequest,
    mut payload: web::Payload,
    host: &str,
    port: u16,
    tail: String,
) -> Result<HttpResponse, Error> {
    let query = req.query_string();
    let host = crate::netaddr::bracket_host(host);
    let target = if query.is_empty() {
        format!("http://{}:{}/{}", host, port, tail)
    } else {
        format!("http://{}:{}/{}?{}", host, port, tail, query)
    };

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("bad method: {}", e)))?;

    // Read the full client body. Selkies POSTs are tiny config/input
    // blobs; streaming the request body through reqwest would need a
    // channel bridge. For now buffer — responses stream fine.
    let mut body_bytes = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(actix_web::error::ErrorBadRequest)?;
        body_bytes.extend_from_slice(&chunk);
    }

    let mut builder = BROWSER_PROXY_CLIENT.request(method, &target).body(body_bytes.freeze());
    for (name, val) in req.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let Ok(v) = val.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("cluster_browser proxy upstream error: {}", e);
            return Ok(HttpResponse::BadGateway().body(format!("upstream error: {}", e)));
        }
    };

    let status = actix_web::http::StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = HttpResponse::build(status);
    for (name, val) in upstream.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        resp.insert_header((name.as_str(), val.to_str().unwrap_or("")));
    }
    let stream = upstream
        .bytes_stream()
        .map(|r| r.map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string())));
    Ok(resp.streaming(stream))
}

/// WebSocket bridge — accept the browser upgrade, open a ws:// client
/// to the container's /websocket (or whatever path selkies put there),
/// pump frames in both directions until either side closes.
async fn proxy_websocket(
    req: HttpRequest,
    payload: web::Payload,
    host: &str,
    port: u16,
    tail: String,
) -> Result<HttpResponse, Error> {
    let query = req.query_string();
    let host = crate::netaddr::bracket_host(host);
    let upstream_url = if query.is_empty() {
        format!("ws://{}:{}/{}", host, port, tail)
    } else {
        format!("ws://{}:{}/{}?{}", host, port, tail, query)
    };

    let (upstream, _resp) = match tokio_tungstenite::connect_async(&upstream_url).await {
        Ok(pair) => pair,
        Err(e) => {
            error!("cluster_browser proxy ws connect failed {}: {}", upstream_url, e);
            return Ok(HttpResponse::BadGateway()
                .json(serde_json::json!({ "error": format!("ws connect failed: {}", e) })));
        }
    };

    // actix-ws defaults to a 64 KB max frame size — selkies streams
    // H264 video frames well over that (hundreds of KB, sometimes MB
    // for keyframes). Without bumping this, big frames get rejected
    // and the data WS closes without a clean close frame, which is
    // exactly the "client connected, then dropped" symptom in the
    // container's pcmflux/data_websocket logs.
    let (res, session, msg_stream) = actix_ws::handle(&req, payload)?;
    let msg_stream = msg_stream.max_frame_size(16 * 1024 * 1024);
    actix_rt::spawn(ws_bridge(session, msg_stream, upstream));
    Ok(res)
}

/// Ferry messages between the browser's actix_ws session and the
/// container's tungstenite client. Binary/Text/Ping/Close each map
/// 1:1 across the two stacks.
async fn ws_bridge(
    mut browser: actix_ws::Session,
    mut browser_rx: actix_ws::MessageStream,
    upstream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    let (mut up_tx, mut up_rx) = upstream.split();

    loop {
        tokio::select! {
            // Container → browser
            up_msg = up_rx.next() => {
                match up_msg {
                    Some(Ok(tungstenite::Message::Binary(b))) => {
                        if browser.binary(b.to_vec()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Text(t))) => {
                        if browser.text(t.to_string()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Ping(b))) => {
                        let _ = browser.ping(&b).await;
                    }
                    Some(Ok(tungstenite::Message::Pong(_))) => {}
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    Some(Ok(tungstenite::Message::Frame(_))) => {}
                    Some(Err(e)) => {
                        warn!("cluster_browser ws upstream read: {}", e);
                        break;
                    }
                }
            }
            // Browser → container
            br_msg = browser_rx.next() => {
                match br_msg {
                    Some(Ok(Message::Binary(b))) => {
                        if up_tx.send(tungstenite::Message::Binary(b.to_vec().into())).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(t))) => {
                        if up_tx.send(tungstenite::Message::Text(t.to_string().into())).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(b))) => {
                        let _ = browser.pong(&b).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    let _ = browser.close(None).await;
}
