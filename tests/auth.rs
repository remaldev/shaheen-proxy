use base64::Engine as _;
use hyper::{Body, Request};
use shaheen_proxy::{parse_proxy_auth, UserStore};

#[test]
fn test_shaheen_accepts() {
    let user_store = UserStore::new();
    user_store.add_user("shaheen".to_string(), "psswd".to_string(), true);

    let creds = "shaheen:psswd";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg = parse_proxy_auth(&req, &user_store).expect("shaheen should authenticate");
    assert_eq!(cfg.user, "shaheen");
}

#[test]
fn test_shaheen_wrong_password_rejects() {
    let user_store = UserStore::new();
    user_store.add_user("shaheen".to_string(), "psswd".to_string(), true);

    let creds = "shaheen:wrongpsswd";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg = parse_proxy_auth(&req, &user_store);
    assert!(cfg.is_none());
}

#[test]
fn test_shaheen_with_metadata_accepts() {
    let user_store = UserStore::new();
    user_store.add_user("shaheen".to_string(), "psswd".to_string(), true);

    let creds = "shaheen_c-US:psswd";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg =
        parse_proxy_auth(&req, &user_store).expect("shaheen with metadata should authenticate");
    assert_eq!(cfg.user, "shaheen");
}

#[test]
fn test_unknown_user_rejects() {
    let user_store = UserStore::new();
    user_store.add_user("shaheen".to_string(), "100000001".to_string(), true);

    let creds = "client_c-MA:somepass";
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let header = format!("Basic {}", b64);

    let req = Request::builder()
        .header("Proxy-Authorization", header)
        .body(Body::empty())
        .unwrap();

    let cfg = parse_proxy_auth(&req, &user_store);
    assert!(cfg.is_none());
}
