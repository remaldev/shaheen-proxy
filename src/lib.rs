mod proxy_provider;
mod session_store;
mod user_store;

use crate::proxy_provider::{ClientConfig, UpstreamEnum};
pub use crate::session_store::SessionStore;
pub use crate::user_store::UserStore;
use base64::Engine as _;
use hyper::{Body, Request, Response, StatusCode};
use once_cell::sync::Lazy;
use proxy_provider::ProxyManager;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

pub fn parse_username(raw: &str) -> ClientConfig {
    let mut parts = raw.split('_');
    let user = parts.next().unwrap_or("").to_string();

    let mut country = None;
    let mut state = None;
    let mut city = None;
    let mut sid = None;
    let mut ttl = None;
    let mut host_id = None;
    let mut parse_error: Option<String> = None;

    for part in parts {
        let mut kv = part.splitn(2, '-');
        let key = kv.next().unwrap_or("");
        let val = kv.next();

        // ensure value is present and not empty for key-value items
        if let Some(vstr) = val {
            if vstr.is_empty() {
                let msg = format!("empty value for key '{}'", key);
                if parse_error.is_none() {
                    parse_error = Some(msg);
                }
                continue;
            }
        }

        match (key, val) {
            // cy=Country is optional metadata for more granular proxy selection
            ("c", Some(v)) => {
                if country.is_some() {
                    let msg = format!("duplicate country value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    country = Some(v.to_string());
                }
            }
            // st=State is optional metadata for more granular proxy selection
            ("st", Some(v)) => {
                if state.is_some() {
                    let msg = format!("duplicate state value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    state = Some(v.to_string());
                }
            }
            // cy=City is optional metadata for more granular proxy selection
            ("cy", Some(v)) => {
                if city.is_some() {
                    let msg = format!("duplicate city value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    city = Some(v.to_string());
                }
            }
            // Session ID (sid) is optional string identifier for session persistence
            // - must be alphanumeric and <=10 chars if provided
            ("s", Some(v)) => {
                if sid.is_some() {
                    let msg = format!("duplicate sid value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else if v.len() <= 10 && v.chars().all(|c| c.is_ascii_alphanumeric()) {
                    sid = Some(v.to_string());
                } else {
                    let msg = format!("sid invalid or too long (len={}): '{}'", v.len(), v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                }
            }
            // host_id is optional numeric identifier for proxies that have fixed number of hosts
            ("h", Some(v)) => {
                if host_id.is_some() {
                    let msg = format!("duplicate host_id value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else if let Ok(n) = v.parse::<u64>() {
                    host_id = Some(n);
                } else {
                    let msg = format!("host_id value not a number: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                }
            }
            // ttl=time to live in seconds for session persistence
            // - optional, but if sid provided then ttl=0 or missing means 60 seconds
            ("ttl", Some(v)) => {
                if ttl.is_some() {
                    let msg = format!("duplicate ttl value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else if let Ok(n) = v.parse::<u64>() {
                    ttl = Some(n);
                } else {
                    let msg = format!("ttl value not a number: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                }
            }
            // unknown or missing value: ignore
            _ => {}
        }
    }

    let mut conf = ClientConfig {
        user,
        country,
        state,
        city,
        sid,
        host_id,
        ttl,
        parse_error,
    };
    if conf.sid.is_some() && conf.ttl.is_none() {
        conf.ttl = Some(60);
    }
    conf
}

/// Validate a username (may include metadata like `user_country-US`) and password
/// against the UserStore. On success returns the parsed ClientConfig.
pub fn validate_user_credentials(
    username: &str,
    password: &str,
    user_store: &UserStore,
) -> Option<ClientConfig> {
    // parse username into ClientConfig (extract base user + metadata)
    let cfg = parse_username(username);
    let base_user = cfg.user.clone();

    // if parsing found an error reject immediately
    if cfg.parse_error.is_some() {
        return None;
    }

    if user_store.validate(&base_user, password) {
        return Some(cfg);
    }

    None
}

fn extract_credentials_from_header(req: &Request<Body>) -> Option<(String, String)> {
    if let Some(header_val) = req.headers().get("Proxy-Authorization") {
        let header_str = header_val.to_str().ok()?;
        let (scheme, b64) = header_str.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let (u, p) = decoded_str.split_once(':')?;
        return Some((u.to_string(), p.to_string()));
    }
    None
}

fn extract_credentials_from_uri(req: &Request<Body>) -> Option<(String, String)> {
    let authority = req.uri().authority()?;
    let auth_str = authority.as_str();
    let (userinfo, _host) = auth_str.split_once('@')?;
    let (u, p) = userinfo.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

pub fn parse_proxy_auth(req: &Request<Body>, user_store: &UserStore) -> Option<ClientConfig> {
    let creds = extract_credentials_from_header(req).or_else(|| extract_credentials_from_uri(req));
    let (username, password) = creds?;
    validate_user_credentials(&username, &password, user_store)
}

fn auth_required_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", r#"Basic realm="shaheen-proxy""#)
        .body(Body::from("Proxy authentication required\n"))
        .unwrap()
}

// Lazy-loaded proxy manager singleton
static PROXY_MANAGER: Lazy<Option<ProxyManager>> =
    Lazy::new(|| match ProxyManager::new("proxies.json") {
        Ok(manager) => Some(manager),
        Err(e) => {
            eprintln!("[!] Failed to load proxies.json: {}", e);
            None
        }
    });

pub fn select_upstream_proxy(cfg: &ClientConfig, session_store: &SessionStore) -> Option<String> {
    // Check session store first if sid exists
    if let Some(sid) = &cfg.sid {
        if let Some(cached_proxy) = session_store.get(sid) {
            return Some(cached_proxy);
        }
    }

    // No cached session, select new proxy
    let manager = PROXY_MANAGER.as_ref().cloned().unwrap();
    let proxy = manager.select_proxy(&cfg)?;

    // Store in session if ttl provided
    if let Some(ref sid) = cfg.sid {
        if let Some(ttl) = cfg.ttl {
            session_store.set(sid.clone(), proxy.clone(), ttl);
        }
    }

    Some(proxy)
}

fn parse_upstream(proxy: &str) -> UpstreamEnum {
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

/// Establish connection through upstream proxy
/// Returns TcpStream on success, or Response with error for client
async fn connect_through_upstream(
    proxy_url: &str,
    target: &str,
) -> Result<tokio::net::TcpStream, Response<Body>> {
    let upstream_result = match parse_upstream(proxy_url) {
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

async fn handle_connect_tunnel(
    req: Request<Body>,
    proxy_url: String,
) -> Result<Response<Body>, Infallible> {
    let target = req.uri().authority().unwrap().as_str().to_string();

    // Establish upstream connection (handles all proxy types)
    let mut upstream = match connect_through_upstream(&proxy_url, &target).await {
        Ok(stream) => stream,
        Err(error_response) => return Ok(error_response),
    };

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
fn build_reqwest_client(upstream: UpstreamEnum) -> reqwest::Client {
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

async fn handle_http_request(
    req: Request<Body>,
    proxy_url: String,
) -> Result<Response<Body>, Infallible> {
    let upstream = parse_upstream(&proxy_url);
    let uri = req.uri().to_string();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = hyper::body::to_bytes(req.into_body()).await.unwrap();

    // Build configured client
    let client = build_reqwest_client(upstream);

    // Build outgoing request
    let mut req_builder = client.request(method, &uri);
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !name_str.starts_with("proxy-") && name_str != "connection" {
            req_builder = req_builder.header(name_str, value.as_bytes());
        }
    }
    req_builder = req_builder.body(body.to_vec());

    // Send request with error interception
    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[HTTP REQUEST ERROR] {}", e);
            intercept_connection_error(&e.to_string());
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Request failed: {}", e)))
                .unwrap());
        }
    };

    // Forward response to client
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let resp_body = resp.bytes().await.unwrap();

    let mut response = Response::builder().status(status.as_u16());
    for (name, value) in resp_headers.iter() {
        response = response.header(name.as_str(), value.as_bytes());
    }

    Ok(response.body(Body::from(resp_body.to_vec())).unwrap())
}

fn log_request(source_ip: &str, username: &str, proxy: &str, target: &str) {
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

pub async fn handle(
    req: Request<Body>,
    remote_addr: std::net::SocketAddr,
    session_store: Arc<SessionStore>,
    user_store: Arc<UserStore>,
) -> Result<Response<Body>, Infallible> {
    // Step 1: Extract credentials first
    let creds =
        extract_credentials_from_header(&req).or_else(|| extract_credentials_from_uri(&req));
    let (username, password) = match creds {
        Some(c) => c,
        None => return Ok(auth_required_response()),
    };

    // Step 2: Validate auth
    let cfg = match validate_user_credentials(&username, &password, &user_store) {
        Some(c) => c,
        None => return Ok(auth_required_response()),
    };

    // Get source IP (prefer x-forwarded-for if behind proxy, otherwise use direct connection IP)
    let remote_ip = remote_addr.ip().to_string();
    let source_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&remote_ip);

    // Get proxy and target info
    let target = req.uri().to_string();
    let proxy_url =
        select_upstream_proxy(&cfg, &session_store).unwrap_or_else(|| "direct".to_string());

    log_request(source_ip, &username, &proxy_url, &target);
    // Step 3: Forward request
    if req.method() == hyper::Method::CONNECT {
        handle_connect_tunnel(req, proxy_url).await
    } else {
        handle_http_request(req, proxy_url).await
    }
}
