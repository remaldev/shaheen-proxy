use crate::proxy_provider::ClientConfig;
use crate::user_store::UserStore;
use base64::Engine as _;
use hyper::{Body, Request, Response, StatusCode};

/// Parse a username string into a ClientConfig structure
/// Format: `username_c-US_st-California_cy-LosAngeles_s-sessionid_ttl-120_h-5`
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

/// Extract credentials from Proxy-Authorization header
pub(crate) fn extract_credentials_from_header(req: &Request<Body>) -> Option<(String, String)> {
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

/// Extract credentials from URI (e.g., http://user:pass@host:port)
pub(crate) fn extract_credentials_from_uri(req: &Request<Body>) -> Option<(String, String)> {
    let authority = req.uri().authority()?;
    let auth_str = authority.as_str();
    let (userinfo, _host) = auth_str.split_once('@')?;
    let (u, p) = userinfo.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

/// Parse proxy authentication from request
/// Returns ClientConfig on success, None on failure
pub fn parse_proxy_auth(req: &Request<Body>, user_store: &UserStore) -> Option<ClientConfig> {
    let creds = extract_credentials_from_header(req).or_else(|| extract_credentials_from_uri(req));
    let (username, password) = creds?;
    validate_user_credentials(&username, &password, user_store)
}

/// Build 407 authentication required response
pub(crate) fn auth_required_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", r#"Basic realm="shaheen-proxy""#)
        .body(Body::from("Proxy authentication required\n"))
        .unwrap()
}
