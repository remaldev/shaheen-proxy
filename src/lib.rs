use base64::Engine as _;
use hyper::{Body, Request, Response, StatusCode};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::convert::Infallible;

#[derive(Debug)]
pub struct ClientConfig {
    pub user: String,
    pub country: Option<String>,
    pub sid: Option<String>,
}

pub fn parse_username(raw: &str) -> ClientConfig {
    let mut parts = raw.split('_');
    println!("[dbg] parse_username: raw='{}'", raw);
    let user = parts.next().unwrap_or("").to_string();

    let mut country = None;
    let mut sid = None;

    for part in parts {
        let mut kv = part.splitn(2, '-');
        let key = kv.next().unwrap_or("");
        let val = kv.next().unwrap_or("");

        match key {
            "country" => country = Some(val.to_string()),
            "sid" => sid = Some(val.to_string()),
            _ => {}
        }
    }

    ClientConfig { user, country, sid }
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

pub fn parse_proxy_auth(req: &Request<Body>) -> Option<ClientConfig> {
    println!("[dbg] parse_proxy_auth called");

    // First, prefer Proxy-Authorization header (standard for HTTP proxies).
    // If missing, fall back to URI userinfo (username:password@host).
    let (username, password) = if let Some(header_val) = req.headers().get("Proxy-Authorization") {
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
        (u.to_string(), p.to_string())
    } else if let Some(authority) = req.uri().authority() {
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
        (u.to_string(), p.to_string())
    } else {
        println!("[dbg] No Proxy-Authorization header and no URI authority present");
        return None;
    };

    // Parse client info from username (e.g. "client_country-US").
    // Use the base user (before the first '_') to check the hardcoded DB.
    let cfg = parse_username(&username);
    let base_user = cfg.user.clone();

    // Check hardcoded user DB first — only known users are accepted.
    if let Some(user) = lookup_user(&base_user) {
        println!(
            "[dbg] user '{}' found in hardcoded DB (active={})",
            base_user, user.active
        );
        if user.active {
            if password == user.password {
                println!("[dbg] auth success for '{}' via hardcoded DB", base_user);
                return Some(cfg);
            } else {
                println!(
                    "[dbg] auth failed for '{}' via hardcoded DB (password mismatch)",
                    base_user
                );
                return None;
            }
        } else {
            println!("[dbg] user '{}' exists but is not active", base_user);
            return None;
        }
    }

    // If username is not in the hardcoded DB, reject.
    println!("[dbg] user '{}' not found in DB; rejecting", base_user);
    None
}

pub async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if let Some(cfg) = parse_proxy_auth(&req) {
        println!("[*] New request with client config: {:?}", cfg);

        // For now we don't forward; just respond OK
        let body = "shaheen-proxy: OK (no upstream yet)\n";
        Ok(Response::new(Body::from(body)))
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
