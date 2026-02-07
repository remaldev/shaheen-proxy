use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use shaheen_proxy::{SessionStore, UserStore};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

const PORT: u16 = 1337;
const MAX_CONCURRENT: usize = 512;

#[tokio::main(flavor = "multi_thread", worker_threads = 512)]
async fn main() {
    // print!("\x1B[2J\x1B[1;1H");
    let addr = SocketAddr::from(([0, 0, 0, 0], PORT));
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let session_store = Arc::new(SessionStore::new());
    let user_store = Arc::new(UserStore::new());

    // Add default test user for testing purposes (TODO: should be removed in production)
    user_store.add_user("test".to_string(), "test".to_string(), true);

    // Cleanup expired sessions every 60 seconds
    SessionStore::spawn_cleanup_task(session_store.clone(), 60);

    let make_svc = make_service_fn(|conn: &hyper::server::conn::AddrStream| {
        let remote_addr = conn.remote_addr();
        let semaphore = semaphore.clone();
        let session_store = session_store.clone();
        let user_store = user_store.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let semaphore = semaphore.clone();
                let session_store = session_store.clone();
                let user_store = user_store.clone();
                async move {
                    let _permit = semaphore.acquire().await; // This queues when limit reached
                    shaheen_proxy::handle(req, remote_addr, session_store, user_store).await
                }
            }))
        }
    });

    let server = Server::bind(&addr)
        .tcp_nodelay(true)
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .http1_keepalive(true)
        .serve(make_svc);

    println!("\nيستمع إلى http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
