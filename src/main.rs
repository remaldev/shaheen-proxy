use std::convert::Infallible;
use std::net::SocketAddr;

use hyper::service::{make_service_fn, service_fn};
use hyper::Server;

const PORT: u16 = 1337;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], PORT));

    let make_svc = make_service_fn(|conn: &hyper::server::conn::AddrStream| {
        let remote_addr = conn.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                shaheen_proxy::handle(req, remote_addr)
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
