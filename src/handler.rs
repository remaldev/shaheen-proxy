use crate::auth::{
    build_auth_required_response, extract_credentials_from_header, extract_credentials_from_uri,
    validate_user_credentials,
};
use crate::proxy_provider::{ClientConfig, UpstreamEnum};
use crate::session_store::SessionStore;
use crate::user_store::UserStore;
use crate::ProxyManager;
use base64::Engine as _;
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

/// Select upstream proxy from ProxyManager with session support
/// Returns (generated_proxy_url, base_proxy_url_for_exclusion)
pub fn select_internal_proxy(
    cfg: &ClientConfig,
    session_store: &SessionStore,
    proxy_manager: &ProxyManager,
    exclude_urls: &[String],
) -> Option<(String, String)> {
    // Check session store first if sid exists (only on first attempt)
    if exclude_urls.is_empty() {
        if let Some(sid) = &cfg.sid {
            if let Some(cached_proxy) = session_store.get(sid) {
                // For cached session, we don't have base_url, but it's OK since we won't retry
                return Some((cached_proxy.clone(), cached_proxy));
            }
        }
    }

    // No cached session, select new proxy
    let (proxy, base_url) = proxy_manager.select_proxy(&cfg, exclude_urls)?;

    // Store in session if ttl provided
    if let Some(ref sid) = cfg.sid {
        if let Some(ttl) = cfg.ttl {
            session_store.set(sid.clone(), proxy.clone(), ttl);
        }
    }

    Some((proxy, base_url))
}

/// Parse upstream proxy URL into UpstreamEnum
fn parse_internal_proxy_config(proxy: &str) -> UpstreamEnum {
    if proxy == "direct" {
        return UpstreamEnum::Direct;
    }

    let url = url::Url::parse(proxy).unwrap();
    let host = url.host_str().unwrap().to_string();
    let port = url.port_or_known_default().unwrap();
    let user = url.username().to_string();
    let pass = url.password().map(|p| p.to_string());
    let auth: Option<String> = pass
        .as_ref()
        .map(|p| base64::engine::general_purpose::STANDARD.encode(format!("{user}:{p}")));

    if proxy.starts_with("socks5") {
        UpstreamEnum::Socks5 {
            host,
            port,
            user,
            pass,
        }
    } else {
        UpstreamEnum::Http { host, port, auth }
    }
}

/// Intercept and analyze upstream proxy responses - log only, don't modify response
fn intercept_upstream_response(response_text: &str) {
    // Log the full upstream response for server-side analysis
    eprintln!("[UPSTREAM RESPONSE] {}", response_text);

    // Analyze and log status - but don't modify the response
    if response_text.contains("407") || response_text.contains("Proxy Authentication Required") {
        eprintln!("[ANALYSIS] Detected auth failure (407)");
    } else if response_text.contains("403")
        || response_text.contains("Bandwidth")
        || response_text.contains("limit")
        || response_text.contains("rate limit")
        || response_text.contains("quota")
    {
        eprintln!("[ANALYSIS] Detected bandwidth/limit error from upstream");
    } else if response_text.starts_with("HTTP/1.1 200") || response_text.starts_with("HTTP/1.0 200")
    {
        eprintln!("[SUCCESS] Upstream connection succeeded (200 OK)");
    } else if response_text.starts_with("HTTP/1.1 502") || response_text.starts_with("HTTP/1.0 502")
    {
        eprintln!("[ANALYSIS] Bad Gateway (502)");
    } else if response_text.starts_with("HTTP/1.1 503") || response_text.starts_with("HTTP/1.0 503")
    {
        eprintln!("[ANALYSIS] Service Unavailable (503)");
    } else {
        eprintln!(
            "[ANALYSIS] Other response code / {}",
            response_text.lines().next().unwrap_or("")
        );
    }
}

/// Intercept and analyze SOCKS5/general connection errors - log only
fn intercept_connection_error(error_msg: &str) {
    eprintln!("[CONNECTION ERROR] {}", error_msg);

    let error_lower = error_msg.to_lowercase();

    // Analyze and log error type - but don't modify the response
    if error_lower.contains("auth") || error_lower.contains("authentication") {
        eprintln!("[ANALYSIS] Error type: Authentication failure");
    } else if error_lower.contains("timeout") || error_lower.contains("timed out") {
        eprintln!("[ANALYSIS] Error type: Connection timeout");
    } else if error_lower.contains("refused") || error_lower.contains("unreachable") {
        eprintln!("[ANALYSIS] Error type: Connection refused/unreachable");
    } else {
        eprintln!("[ANALYSIS] Error type: Generic connection error");
    }
}

/// Establish connection with retry logic - tries all available proxies until success
async fn connect_with_retry(
    cfg: &ClientConfig,
    target: &str,
    session_store: &SessionStore,
    proxy_manager: &ProxyManager,
) -> Result<(tokio::net::TcpStream, String), Response<Body>> {
    let mut failed_proxies = Vec::new();
    let mut attempt = 0;

    loop {
        attempt += 1;

        // Select proxy (excludes previously failed base URLs)
        let (proxy_url, base_url) =
            match select_internal_proxy(cfg, session_store, proxy_manager, &failed_proxies) {
                Some((url, base)) => (url, base),
                None => {
                    let msg = if attempt == 1 {
                        "No proxy available"
                    } else {
                        "All proxies failed"
                    };
                    eprintln!("[ERROR] {} (tried {} proxies)", msg, failed_proxies.len());
                    return Err(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(msg))
                        .unwrap());
                }
            };

        eprintln!("[CONNECT] Attempt {} using proxy: {}", attempt, proxy_url);

        // Try to connect
        match connect_via_upstream_proxy(&proxy_url, target).await {
            Ok(stream) => {
                eprintln!(
                    "[SUCCESS] Connected via {} (after {} attempts)",
                    proxy_url, attempt
                );
                return Ok((stream, proxy_url));
            }
            Err(e) => {
                eprintln!(
                    "[RETRY] Connection failed: {} - trying next proxy",
                    e.status()
                );
                // Add base URL to exclusion list
                failed_proxies.push(base_url);
                continue;
            }
        }
    }
}

/// Establish connection through upstream proxy
/// Returns TcpStream on success, or Response with error for client
async fn connect_via_upstream_proxy(
    proxy_url: &str,
    target: &str,
) -> Result<tokio::net::TcpStream, Response<Body>> {
    let upstream_result = match parse_internal_proxy_config(proxy_url) {
        UpstreamEnum::Direct => tokio::net::TcpStream::connect(target).await,

        UpstreamEnum::Socks5 {
            host,
            port,
            user,
            pass,
        } => {
            let proxy_addr = format!("{}:{}", host, port);
            let parts: Vec<&str> = target.split(':').collect();
            let target_host = parts[0];
            let target_port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

            let result = if let Some(password) = pass {
                tokio_socks::tcp::Socks5Stream::connect_with_password(
                    proxy_addr.as_str(),
                    (target_host, target_port),
                    user.as_str(),
                    password.as_str(),
                )
                .await
                .map(|s| s.into_inner())
            } else {
                tokio_socks::tcp::Socks5Stream::connect(
                    proxy_addr.as_str(),
                    (target_host, target_port),
                )
                .await
                .map(|s| s.into_inner())
            };

            result.map_err(|e| {
                eprintln!("[SOCKS5 ERROR] {}", e);
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            })
        }

        UpstreamEnum::Http { host, port, auth } => {
            let proxy_addr = format!("{}:{}", host, port);

            match tokio::net::TcpStream::connect(&proxy_addr).await {
                Ok(mut stream) => {
                    // Send CONNECT request
                    let mut connect_req =
                        format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);
                    if let Some(auth_header) = auth {
                        connect_req
                            .push_str(&format!("Proxy-Authorization: Basic {}\r\n", auth_header));
                    }
                    connect_req.push_str("\r\n");

                    if let Err(e) =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, connect_req.as_bytes())
                            .await
                    {
                        eprintln!("[HTTP PROXY] Failed to send CONNECT request: {}", e);
                        return Err(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from("Failed to connect to upstream proxy"))
                            .unwrap());
                    }

                    // Read CONNECT response
                    let mut buf = vec![0u8; 1024];
                    let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[HTTP PROXY] Failed to read CONNECT response: {}", e);
                            return Err(Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from("Upstream proxy connection failed"))
                                .unwrap());
                        }
                    };

                    let resp = String::from_utf8_lossy(&buf[..n]);

                    // Log and analyze response
                    intercept_upstream_response(&resp);

                    // Check for errors
                    if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
                        eprintln!("[ERROR] CONNECT failed, upstream returned non-200");
                        return Err(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from(resp.to_string()))
                            .unwrap());
                    }

                    Ok(stream)
                }
                Err(e) => {
                    eprintln!("[HTTP PROXY] Failed to connect: {}", e);
                    Err(e)
                }
            }
        }
    };

    // Handle connection result
    match upstream_result {
        Ok(stream) => Ok(stream),
        Err(e) => {
            eprintln!("[UPSTREAM CONNECTION FAILED] {}", e);
            intercept_connection_error(&e.to_string());
            Err(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Failed to connect: {}", e)))
                .unwrap())
        }
    }
}

/// Open bidirectional tunnel for CONNECT requests with retry
async fn open_bidirectional_tunnel(
    req: Request<Body>,
    cfg: &ClientConfig,
    target: String,
    session_store: Arc<SessionStore>,
    proxy_manager: Arc<ProxyManager>,
) -> Result<Response<Body>, Infallible> {
    // Try to establish connection with retry
    let (mut upstream, proxy_url) =
        match connect_with_retry(cfg, &target, &session_store, &proxy_manager).await {
            Ok(result) => result,
            Err(error_response) => return Ok(error_response),
        };

    eprintln!("[TUNNEL] Opened for {} via {}", target, proxy_url);

    // Spawn bidirectional tunnel
    tokio::spawn(async move {
        let mut client = hyper::upgrade::on(req).await.unwrap();
        eprintln!("[TUNNEL] Starting bidirectional copy for {}", target);
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .ok();
        eprintln!("[TUNNEL] Connection closed for {}", target);
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

/// Build reqwest client configured for the upstream proxy
fn build_upstream_client(upstream: UpstreamEnum) -> reqwest::Client {
    match upstream {
        UpstreamEnum::Direct => reqwest::Client::builder().build().unwrap(),

        UpstreamEnum::Socks5 {
            host,
            port,
            user,
            pass,
        } => {
            let url = if !user.is_empty() {
                match pass {
                    Some(p) => format!("socks5://{}:{}@{}:{}", user, p, host, port),
                    None => format!("socks5://{}@{}:{}", user, host, port),
                }
            } else {
                format!("socks5://{}:{}", host, port)
            };

            reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(&url).unwrap())
                .build()
                .unwrap()
        }

        UpstreamEnum::Http { host, port, auth } => {
            let proxy_addr = format!("http://{}:{}", host, port);
            let mut builder =
                reqwest::Client::builder().proxy(reqwest::Proxy::all(&proxy_addr).unwrap());

            if let Some(auth_header) = auth {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::PROXY_AUTHORIZATION,
                    format!("Basic {}", auth_header).parse().unwrap(),
                );
                builder = builder.default_headers(headers);
            }

            builder.build().unwrap()
        }
    }
}

/// Forward HTTP (non-CONNECT) requests to upstream with retry until all proxies exhausted
async fn forward_http_request(
    req: Request<Body>,
    cfg: &ClientConfig,
    session_store: Arc<SessionStore>,
    proxy_manager: Arc<ProxyManager>,
) -> Result<Response<Body>, Infallible> {
    let mut failed_proxies = Vec::new();
    let mut attempt = 0;

    let uri = req.uri().to_string();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = hyper::body::to_bytes(req.into_body()).await.unwrap();

    loop {
        attempt += 1;

        // Select proxy (excludes previously failed base URLs)
        let (proxy_url, base_url) =
            match select_internal_proxy(cfg, &session_store, &proxy_manager, &failed_proxies) {
                Some((url, base)) => (url, base),
                None => {
                    let msg = if attempt == 1 {
                        "No proxy available"
                    } else {
                        "All proxies failed"
                    };
                    eprintln!("[ERROR] {} (tried {} proxies)", msg, failed_proxies.len());
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(msg))
                        .unwrap());
                }
            };

        eprintln!("[HTTP] Attempt {} using proxy: {}", attempt, proxy_url);

        let upstream = parse_internal_proxy_config(&proxy_url);
        let client = build_upstream_client(upstream);

        // Build outgoing request
        let mut req_builder = client.request(method.clone(), &uri);
        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            if !name_str.starts_with("proxy-") && name_str != "connection" {
                req_builder = req_builder.header(name_str, value.as_bytes());
            }
        }
        req_builder = req_builder.body(body.to_vec());

        // Send request
        match req_builder.send().await {
            Ok(resp) if resp.status().is_success() => {
                eprintln!(
                    "[SUCCESS] HTTP request via {} (after {} attempts)",
                    proxy_url, attempt
                );
                // Forward response to client
                let status = resp.status();
                let resp_headers = resp.headers().clone();
                let resp_body = resp.bytes().await.unwrap();

                let mut response = Response::builder().status(status.as_u16());
                for (name, value) in resp_headers.iter() {
                    response = response.header(name.as_str(), value.as_bytes());
                }

                return Ok(response.body(Body::from(resp_body.to_vec())).unwrap());
            }
            Ok(resp) if resp.status().is_server_error() => {
                eprintln!(
                    "[RETRY] HTTP request failed with {} - trying next proxy",
                    resp.status()
                );
                failed_proxies.push(base_url);
                continue;
            }
            Ok(resp) => {
                // Client error - return immediately (don't retry)
                eprintln!("[CLIENT ERROR] {} - not retrying", resp.status());
                let status = resp.status();
                let resp_headers = resp.headers().clone();
                let resp_body = resp.bytes().await.unwrap();

                let mut response = Response::builder().status(status.as_u16());
                for (name, value) in resp_headers.iter() {
                    response = response.header(name.as_str(), value.as_bytes());
                }

                return Ok(response.body(Body::from(resp_body.to_vec())).unwrap());
            }
            Err(e) => {
                eprintln!("[RETRY] Connection error: {} - trying next proxy", e);
                intercept_connection_error(&e.to_string());
                failed_proxies.push(base_url);
                continue;
            }
        }
    }
}

/// Log proxy request to file
fn log_proxy_request(source_ip: &str, username: &str, proxy: &str, target: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_line = format!(
        "{} | {} | {} | {} | {}\n",
        timestamp, source_ip, username, proxy, target
    );

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("proxy.log")
    {
        let _ = file.write_all(log_line.as_bytes());
    }
}

/// Route client requests to appropriate handler
pub async fn route_client_request(
    req: Request<Body>,
    remote_addr: std::net::SocketAddr,
    session_store: Arc<SessionStore>,
    user_store: Arc<UserStore>,
    proxy_manager: Arc<ProxyManager>,
) -> Result<Response<Body>, Infallible> {
    // Step 1: Extract credentials first
    let creds =
        extract_credentials_from_header(&req).or_else(|| extract_credentials_from_uri(&req));
    let (username, password) = match creds {
        Some(c) => c,
        None => return Ok(build_auth_required_response()),
    };

    // Step 2: Validate auth
    let cfg = match validate_user_credentials(&username, &password, &user_store) {
        Some(c) => c,
        None => return Ok(build_auth_required_response()),
    };

    // Get source IP (prefer x-forwarded-for if behind proxy, otherwise use direct connection IP)
    let remote_ip = remote_addr.ip().to_string();
    let source_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&remote_ip)
        .to_string();

    // Extract request info
    let target = req.uri().to_string();
    let is_connect = req.method() == hyper::Method::CONNECT;

    log_proxy_request(&source_ip, &username, "[auto-select]", &target);

    // Forward request with automatic retry
    if is_connect {
        open_bidirectional_tunnel(req, &cfg, target, session_store, proxy_manager).await
    } else {
        forward_http_request(req, &cfg, session_store, proxy_manager).await
    }
}
