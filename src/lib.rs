// Module declarations
mod auth;
mod handler;
mod proxy_provider;
mod session_store;
mod user_store;

// Re-export core types and structs
pub use crate::proxy_provider::{ClientConfig, ProxyManager, UpstreamEnum};
pub use crate::session_store::SessionStore;
pub use crate::user_store::UserStore;

// Re-export public API functions
pub use crate::auth::{parse_proxy_auth, parse_username, validate_user_credentials};
pub use crate::handler::{route_client_request, select_internal_proxy};
