use base64::Engine as _;
use hyper::{Body, Request, Response, StatusCode};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Debug)]
pub struct ClientConfig {
    pub user: String,
    pub country: Option<String>,
    pub area: Option<String>,
    pub city: Option<String>,
    pub sid: Option<String>,
    pub ttl: Option<u64>,
    /// proxies pool indices (e.g. p-1-4-5 -> [1,4,5])
    pub proxies: Vec<u32>,
    /// rotate proxies on/off
    pub rotate: bool,
    pub parse_error: Option<String>,
}

pub fn parse_username(raw: &str) -> ClientConfig {
    let mut parts = raw.split('_');
    let user = parts.next().unwrap_or("").to_string();

    let mut country = None;
    let mut area = None;
    let mut city = None;
    let mut sid = None;
    let mut ttl = None;
    let mut proxies: Vec<u32> = Vec::new();
    let mut rotate = false;
    let mut parse_error: Option<String> = None;

    for part in parts {
        // special flag: rot-on (no value)
        if part == "rot-on" {
            rotate = true;
            continue;
        }

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
            ("country", Some(v)) => {
                if country.is_some() {
                    let msg = format!("duplicate country value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    country = Some(v.to_string());
                }
            }
            ("area", Some(v)) => {
                if area.is_some() {
                    let msg = format!("duplicate area value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    area = Some(v.to_string());
                }
            }
            ("city", Some(v)) => {
                if city.is_some() {
                    let msg = format!("duplicate city value: {}", v);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    city = Some(v.to_string());
                }
            }
            ("sid", Some(v)) => {
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
            ("p", Some(v)) => {
                if v.is_empty() {
                    let msg = "empty proxies list".to_string();
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    // v like "1-4-5" -> split by '-' and parse ints, treat duplicates as error
                    for s in v.split('-') {
                        if s.is_empty() {
                            let msg = "empty proxy index in 'p'".to_string();
                            if parse_error.is_none() {
                                parse_error = Some(msg);
                            }
                            continue;
                        }
                        if let Ok(idx) = s.parse::<u32>() {
                            if !proxies.contains(&idx) {
                                proxies.push(idx);
                            } else {
                                let msg = format!("duplicate proxy index {}", idx);
                                if parse_error.is_none() {
                                    parse_error = Some(msg);
                                }
                            }
                        } else {
                            let msg = format!("invalid proxy index '{}'", s);
                            if parse_error.is_none() {
                                parse_error = Some(msg);
                            }
                        }
                    }
                }
            }
            // unknown or missing value: ignore
            _ => {}
        }
    }

    ClientConfig {
        user,
        country,
        area,
        city,
        sid,
        ttl,
        proxies,
        rotate,
        parse_error,
    }
}

/// Validate a username (may include metadata like `user_country-US`) and password
/// against the hardcoded USERS DB. On success returns the parsed ClientConfig.
pub fn validate_user_credentials(username: &str, password: &str) -> Option<ClientConfig> {
    // parse username into ClientConfig (extract base user + metadata)
    let cfg = parse_username(username);
    let base_user = cfg.user.clone();

    // if parsing found an error reject immediately
    if cfg.parse_error.is_some() {
        return None;
    }

    if let Some(user) = lookup_user(&base_user) {
        if user.active && password == user.password {
            return Some(cfg);
        }
        return None;
    }

    None
}

#[derive(Debug)]
struct User {
    password: &'static str,
    active: bool,
}

// Static hardcoded user DB. Edit here to add/remove users.
static USERS: Lazy<HashMap<&'static str, User>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(
        "shaheen",
        User {
            password: "100000001",
            active: true,
        },
    );
    m
});

fn lookup_user(username: &str) -> Option<&'static User> {
    USERS.get(username)
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

pub fn parse_proxy_auth(req: &Request<Body>) -> Option<ClientConfig> {
    let creds = extract_credentials_from_header(req).or_else(|| extract_credentials_from_uri(req));
    let (username, password) = creds?;
    validate_user_credentials(&username, &password)
}

fn auth_required_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", r#"Basic realm="shaheen-proxy""#)
        .body(Body::from("Proxy authentication required\n"))
        .unwrap()
}

fn select_upstream_proxy(_cfg: &ClientConfig) -> Option<String> {
    // TODO: Implement your proxy selection logic
    // Use cfg.proxies, cfg.country, cfg.rotate, cfg.sid
    // Return None for direct, or Some("http://proxy:port") for upstream proxy

    // Example: Some("http://upstream-proxy:8080".to_string())
    None
}

async fn handle_connect_tunnel(
    req: Request<Body>,
    cfg: ClientConfig,
) -> Result<Response<Body>, Infallible> {
    let target = req.uri().authority().unwrap().as_str().to_string();
    let proxy_url = select_upstream_proxy(&cfg);

    // CONNECT target and selected upstream proxy (if any)

    tokio::spawn(async move {
        let mut client = hyper::upgrade::on(req).await.unwrap();

        let mut upstream = if let Some(proxy) = proxy_url {
            if proxy.starts_with("socks5") {
                // SOCKS5 proxy
                let proxy_url_parsed = url::Url::parse(&proxy).unwrap();
                let proxy_host = proxy_url_parsed.host_str().unwrap();
                let proxy_port = proxy_url_parsed.port().unwrap();
                let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

                // Parse target host:port
                let target_parts: Vec<&str> = target.split(':').collect();
                let target_host = target_parts[0];
                let target_port: u16 = target_parts[1].parse().unwrap();

                if let Some(password) = proxy_url_parsed.password() {
                    tokio_socks::tcp::Socks5Stream::connect_with_password(
                        proxy_addr.as_str(),
                        (target_host, target_port),
                        proxy_url_parsed.username(),
                        password,
                    )
                    .await
                    .unwrap()
                    .into_inner()
                } else {
                    tokio_socks::tcp::Socks5Stream::connect(
                        proxy_addr.as_str(),
                        (target_host, target_port),
                    )
                    .await
                    .unwrap()
                    .into_inner()
                }
            } else {
                // HTTP/HTTPS proxy - send CONNECT request
                let proxy_url_parsed = url::Url::parse(&proxy).unwrap();
                let proxy_host = proxy_url_parsed.host_str().unwrap();
                let proxy_port = proxy_url_parsed.port().unwrap();
                let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

                let mut stream = tokio::net::TcpStream::connect(&proxy_addr).await.unwrap();

                // Build CONNECT request with auth if present
                let mut connect_req =
                    format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);
                if let Some(password) = proxy_url_parsed.password() {
                    let auth = format!("{}:{}", proxy_url_parsed.username(), password);
                    let auth_encoded = base64::engine::general_purpose::STANDARD.encode(auth);
                    connect_req
                        .push_str(&format!("Proxy-Authorization: Basic {}\r\n", auth_encoded));
                }
                connect_req.push_str("\r\n");

                tokio::io::AsyncWriteExt::write_all(&mut stream, connect_req.as_bytes())
                    .await
                    .unwrap();

                // Read 200 response
                let mut buf = vec![0u8; 1024];
                tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                    .await
                    .unwrap();

                stream
            }
        } else {
            tokio::net::TcpStream::connect(&target).await.unwrap()
        };

        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .ok();
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

async fn handle_http_request(
    req: Request<Body>,
    cfg: ClientConfig,
) -> Result<Response<Body>, Infallible> {
    let uri = req.uri().to_string();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let proxy_url = select_upstream_proxy(&cfg);

    // HTTP request and selected upstream proxy (if any)

    // Build client with optional proxy
    let mut builder = reqwest::Client::builder();
    if let Some(proxy) = proxy_url {
        builder = builder.proxy(reqwest::Proxy::all(proxy).unwrap());
    }
    let client = builder.build().unwrap();

    // Build request
    let mut req_builder = client.request(method.as_str().parse().unwrap(), &uri);
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !name_str.starts_with("proxy-") && name_str != "connection" {
            req_builder = req_builder.header(name_str, value.as_bytes());
        }
    }
    req_builder = req_builder.body(body.to_vec());

    // Send request
    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[!] Request failed: {} - Error: {}", uri, e);
            panic!("Request failed");
        }
    };
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let resp_body = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[!] Failed to read response body: {} - Error: {}", uri, e);
            panic!("Response read failed");
        }
    };

    // Build response
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
) -> Result<Response<Body>, Infallible> {
    // Step 1: Extract credentials first
    let creds =
        extract_credentials_from_header(&req).or_else(|| extract_credentials_from_uri(&req));
    let (username, password) = match creds {
        Some(c) => c,
        None => return Ok(auth_required_response()),
    };

    // Step 2: Validate auth
    let cfg = match validate_user_credentials(&username, &password) {
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
    let proxy_url = select_upstream_proxy(&cfg);
    let proxy_used = proxy_url.as_ref().map(|s| s.as_str()).unwrap_or("direct");

    // Log request with full username string
    log_request(source_ip, &username, proxy_used, &target);
    println!("[*] {} {} - user:{}", req.method(), req.uri(), cfg.user);

    // Step 3: Forward request
    if req.method() == hyper::Method::CONNECT {
        handle_connect_tunnel(req, cfg).await
    } else {
        handle_http_request(req, cfg).await
    }
}
