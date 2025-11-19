mod helpers;
mod proxy_manager;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
// Re-export submodules
pub use proxy_manager::ProxyManager;

#[derive(Debug)]
pub struct ClientConfig {
    pub user: String,
    pub country: Option<String>,
    pub state: Option<String>,
    pub city: Option<String>,
    pub sid: Option<String>,
    pub ttl: Option<u64>,
    pub parse_error: Option<String>,
}

#[derive(Debug)]
pub struct User {
    pub password: &'static str,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub url: String,
    #[serde(default)]
    pub countries: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub hosts_per_country: HashMap<String, u32>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    // opts is array of (string | string[])[]
    pub opts: Vec<serde_json::Value>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedConfig {
    #[serde(default)]
    pub templates: HashMap<String, TemplateConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxiesConfig {
    #[serde(default)]
    pub shared_config: SharedConfig,
    #[serde(default)]
    pub accounts: Vec<Account>,
}

pub enum UpstreamEnum {
    Direct,
    Socks5 {
        host: String,
        port: u16,
        user: String,
        pass: Option<String>,
    },
    Http {
        host: String,
        port: u16,
        auth: Option<String>,
    },
}
