use std::convert::Infallible;
use std::net::SocketAddr;

use base64::Engine as _;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};

#[derive(Debug)]
struct ClientConfig {
    user: String,
    country: Option<String>,
    sid: Option<String>,
}

fn parse_username(raw: &str) -> ClientConfig {
    let mut parts = raw.split('|');
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

fn parse_proxy_auth(req: &Request<Body>) -> Option<ClientConfig> {
    // Try Proxy-Authorization first (what curl/browser send for HTTP proxy)
    let header = req
        .headers()
        .get("Proxy-Authorization")
        .or_else(|| req.headers().get("Authorization"))?;

    let header_str = header.to_str().ok()?;

    // Expect "Basic base64..."
    let (scheme, b64) = header_str.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }

    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    // "username:password"
    let (username, _password) = decoded_str.split_once(':')?;
    Some(parse_username(username))
}

async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if let Some(cfg) = parse_proxy_auth(&req) {
        println!("[*] New request with client config: {:?}", cfg);
    } else {
        println!("[*] Request without valid proxy auth");
    }

    // For now we don't forward; just respond
    let body = "shaheen-proxy: OK (no upstream yet)\n";
    Ok(Response::new(Body::from(body)))
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    let make_svc =
        make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(|req| handle(req))) });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
