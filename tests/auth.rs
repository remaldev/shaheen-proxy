use base64::Engine as _;
use hyper::{Body, Request};
use shaheen_proxy::parse_proxy_auth;

#[test]
fn test_shaheen_accepts() {
    let creds = "shaheen:100000001";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg = parse_proxy_auth(&req).expect("shaheen should authenticate");
    assert_eq!(cfg.user, "shaheen");
}

#[test]
fn test_shaheen_wrong_password_rejects() {
    let creds = "shaheen:wrongpass";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg = parse_proxy_auth(&req);
    assert!(cfg.is_none());
}

#[test]
fn test_shaheen_with_metadata_accepts() {
    let creds = "shaheen_country-US:100000001";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg = parse_proxy_auth(&req).expect("shaheen with metadata should authenticate");
    assert_eq!(cfg.user, "shaheen");
}

#[test]
fn test_unknown_user_rejects() {
    let creds = "client_country-US:somepass";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg = parse_proxy_auth(&req);
    assert!(cfg.is_none());
}
