use base64::Engine as _;
use hyper::client::Client;
use hyper::client::HttpConnector;
use hyper::{Body, Request, Response, StatusCode};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::convert::Infallible;

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
    println!("[dbg] parse_username: raw='{}'", raw);
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
                println!("[dbg] {}", msg);
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
                    println!("[dbg] {}", msg);
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
                    println!("[dbg] {}", msg);
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
                    println!("[dbg] {}", msg);
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
                    println!("[dbg] {}", msg);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else if v.len() <= 10 && v.chars().all(|c| c.is_ascii_alphanumeric()) {
                    sid = Some(v.to_string());
                } else {
                    let msg = format!("sid invalid or too long (len={}): '{}'", v.len(), v);
                    println!("[dbg] {}", msg);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                }
            }
            ("ttl", Some(v)) => {
                if ttl.is_some() {
                    let msg = format!("duplicate ttl value: {}", v);
                    println!("[dbg] {}", msg);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else if let Ok(n) = v.parse::<u64>() {
                    ttl = Some(n);
                } else {
                    let msg = format!("ttl value not a number: {}", v);
                    println!("[dbg] {}", msg);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                }
            }
            ("p", Some(v)) => {
                if v.is_empty() {
                    let msg = "empty proxies list".to_string();
                    println!("[dbg] {}", msg);
                    if parse_error.is_none() {
                        parse_error = Some(msg);
                    }
                } else {
                    // v like "1-4-5" -> split by '-' and parse ints, treat duplicates as error
                    for s in v.split('-') {
                        if s.is_empty() {
                            let msg = "empty proxy index in 'p'".to_string();
                            println!("[dbg] {}", msg);
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
                                println!("[dbg] {}", msg);
                                if parse_error.is_none() {
                                    parse_error = Some(msg);
                                }
                            }
                        } else {
                            let msg = format!("invalid proxy index '{}'", s);
                            println!("[dbg] {}", msg);
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

    // if parsing found an error (duplicate keys, empty values, invalid formats)
    // reject the credentials immediately
    if let Some(ref err) = cfg.parse_error {
        println!("[dbg] parse error in username '{}': {}", username, err);
        return None;
    }

    if let Some(user) = lookup_user(&base_user) {
        println!(
            "[dbg] user '{}' found in hardcoded DB (active={})",
            base_user, user.active
        );

        if user.active && password == user.password {
            println!("[dbg] auth success for '{}' via hardcoded DB", base_user);
            return Some(cfg);
        }

        println!(
            "[dbg] auth failed for '{}' via hardcoded DB (active={}, password_match={})",
            base_user,
            user.active,
            password == user.password
        );
        return None;
    }

    println!("[dbg] user '{}' not found in DB; rejecting", base_user);
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
        let header_str = match header_val.to_str() {
            Ok(s) => s,
            Err(_) => {
                println!("[dbg] Proxy-Authorization header present but invalid utf-8");
                return None;
            }
        };
        println!(
            "[dbg] Proxy-Authorization header present: {}",
            &header_str.split_whitespace().next().unwrap_or("<scheme?>")
        );
        // Expect "Basic base64..."
        let (scheme, b64) = match header_str.split_once(' ') {
            Some(pair) => pair,
            None => {
                println!("[dbg] Proxy-Authorization header malformed");
                return None;
            }
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            println!("[dbg] Proxy-Authorization scheme not Basic: {}", scheme);
            return None;
        }
        let decoded = match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(d) => d,
            Err(_) => {
                println!("[dbg] base64 decode failed for Proxy-Authorization");
                return None;
            }
        };
        let decoded_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => {
                println!("[dbg] decoded credentials are not valid UTF-8");
                return None;
            }
        };
        // decoded_str is "username:password"
        let (u, p) = match decoded_str.split_once(':') {
            Some(pair) => pair,
            None => {
                println!("[dbg] decoded credentials missing ':' separator");
                return None;
            }
        };
        println!(
            "[dbg] extracted credentials from header: username='{}', password_len={}",
            u,
            p.len()
        );
        return Some((u.to_string(), p.to_string()));
    }
    None
}

fn extract_credentials_from_uri(req: &Request<Body>) -> Option<(String, String)> {
    if let Some(authority) = req.uri().authority() {
        let auth_str = authority.as_str();
        println!(
            "[dbg] No Proxy-Authorization header; using URI authority: {}",
            auth_str
        );
        // authority looks like "userinfo@host:port" when userinfo is present
        let (userinfo, _host) = match auth_str.split_once('@') {
            Some(pair) => pair,
            None => {
                println!("[dbg] URI authority missing userinfo");
                return None;
            }
        };
        let (u, p) = match userinfo.split_once(':') {
            Some(pair) => pair,
            None => {
                println!("[dbg] userinfo missing ':' separator");
                return None;
            }
        };
        println!(
            "[dbg] extracted credentials from URI: username='{}', password_len={}",
            u,
            p.len()
        );
        return Some((u.to_string(), p.to_string()));
    }
    None
}

pub fn parse_proxy_auth(req: &Request<Body>) -> Option<ClientConfig> {
    println!("[dbg] parse_proxy_auth called");

    // prefer header, then fall back to URI userinfo
    let creds = extract_credentials_from_header(req).or_else(|| extract_credentials_from_uri(req));

    let (username, password) = match creds {
        Some((u, p)) => (u, p),
        None => {
            println!("[dbg] No Proxy-Authorization header and no URI authority present");
            return None;
        }
    };

    // delegate actual validation to the extracted function
    validate_user_credentials(&username, &password)
}

pub async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if let Some(cfg) = parse_proxy_auth(&req) {
        println!("[*] New request with client config: {:?}", cfg);

        // Forward the request as-is: keep the original URI and headers (do not strip userinfo).
        // We still remove hop-by-hop and proxy-specific headers to avoid leaking them upstream.
        println!("[dbg] Forwarding original request URI: {}", req.uri());
        let forward_uri = req.uri().clone();

        // Build outbound request, copying method and headers (but removing proxy headers)
        let mut builder = Request::builder()
            .method(req.method().clone())
            .uri(forward_uri);

        // Copy headers except hop-by-hop and proxy-specific ones
        for (name, value) in req.headers().iter() {
            // print key/value
            println!(
                "[dbg] processing header : {} / Value: {}",
                name.as_str(),
                value.to_str().unwrap_or("<invalid>")
            );
            let name_str = name.as_str();
            if name_str.eq_ignore_ascii_case("proxy-authorization")
                || name_str.eq_ignore_ascii_case("proxy-authenticate")
                || name_str.eq_ignore_ascii_case("proxy-connection")
                || name_str.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            // keep Host header as-is (do not rewrite)
            builder = builder.header(name_str, value.clone());
        }

        let outbound_req = match builder.body(req.into_body()) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!(
                        "Internal error building request: {}\n",
                        e
                    )))
                    .unwrap();
                return Ok(resp);
            }
        };

        // Perform the request using a simple HTTP connector (no TLS here).
        // For HTTPS you'd need to enable TLS connector (e.g., hyper_tls).
        let client: Client<HttpConnector> = Client::new();
        match client.request(outbound_req).await {
            Ok(resp) => {
                // Return the upstream response directly to the client
                Ok(resp)
            }
            Err(err) => {
                let resp = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(format!("Upstream request failed: {}\n", err)))
                    .unwrap();
                Ok(resp)
            }
        }
    } else {
        println!("[*] Request without valid proxy auth");

        // Respond with 407 Proxy Authentication Required and a Proxy-Authenticate header
        let resp = Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header("Proxy-Authenticate", r#"Basic realm="shaheen-proxy""#)
            .body(Body::from("Proxy authentication required\n"))
            .unwrap();
        Ok(resp)
    }
}
