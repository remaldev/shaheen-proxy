use std::convert::Infallible;
use std::net::SocketAddr;

use hyper::service::{make_service_fn, service_fn};
use hyper::Server;

const PORT: u16 = 1337;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], PORT));

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(|req| shaheen_proxy::handle(req)))
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
