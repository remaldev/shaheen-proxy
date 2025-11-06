use super::ProxiesConfig;
use crate::{proxy_provider::Account, ClientConfig};
use rand::seq::SliceRandom;
use serde_json::Value;
use std::fs;

/// Parses a proxy URL into components
///
/// # Parameters
/// - `url_str`: The proxy URL string to parse
///
/// # Returns
/// An `Option` containing a tuple of (protocol, username, password, host, port)
pub fn parse_url(url_str: &str) -> Option<(String, String, String, String, u16)> {
    let url = url::Url::parse(url_str).ok()?;

    let protocol = url.scheme().to_string();
    let username = url.username().to_string();
    let password = url.password().unwrap().to_string();
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;

    Some((protocol, username, password, host, port))
}

/// Processes a proxy option string, replacing template placeholders with real values.
///
/// # Behavior
/// - If the input string contains a template in `{}` (e.g. `"-{sessionId}"`),
///   it extracts the word inside and replaces it with the corresponding value
///   from `ProxySettings`.
/// - If no `{}` is found (e.g. `"-rotate"`), the string is appended unchanged.
/// - Returns `Some(true)` if the string was processed successfully,
///   `Some(false)` if the placeholder value was missing, or `None` if input was invalid.
///
/// # Examples
/// ```
/// // Case 1: template found and replaced
/// // input: "-{country}" → output: "-US"
///
/// // Case 2: no template, kept as is
/// // input: "-rotate" → output: "-rotate"
/// ```
///
/// # Parameters
/// - `opt`: JSON value containing the option string.
/// - `settings`: ProxySettings providing available field values.
/// - `opts`: mutable string where the processed result is appended.
///
/// # Returns
/// `Option<bool>` indicating processing success or failure.
fn process_word(opt: &Value, settings: &ClientConfig, opts: &mut String) -> Option<bool> {
    let s = opt.as_str()?;
    // println!("----Processing option: {:?}", settings);

    // Case 1: it's a template like "-{sessionId}"
    if let (Some(start), Some(end)) = (s.find('{'), s.find('}')) {
        let word = &s[start + 1..end];
        let value = match word {
            "country" => settings.country.as_deref()?,
            "state" => settings.state.as_deref()?,
            "city" => settings.city.as_deref()?,
            "session" => settings.sid.as_deref()?,
            "ttl" => &settings.ttl?.to_string(),
            _ => "",
        };

        if value.is_empty() {
            println!("⚠️ Empty value for '{}'", word);
            Some(false)
        } else {
            opts.push_str(&s.replace(&format!("{{{}}}", word), value));
            Some(true)
        }
    }
    // Case 2: not a template (no braces)
    else {
        println!("No template found, keeping original: {}", s);
        opts.push_str(s);
        Some(true)
    }
}

#[derive(Clone)]
pub struct ProxyManager {
    proxies: Vec<Account>,
    templates: std::collections::HashMap<String, super::TemplateConfig>,
}

impl ProxyManager {
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(config_path)?;
        let proxies: ProxiesConfig = serde_json::from_str(&content)?;
        // filter active proxies
        let accounts = proxies
            .accounts
            .into_iter()
            .filter(|a| a.active)
            .collect::<Vec<_>>();
        let config = proxies.shared_config;
        println!("Loaded {} active proxies", accounts.len());
        Ok(Self {
            proxies: accounts,
            templates: config.templates,
        })
    }

    pub fn select_proxy(&self, settings: &ClientConfig) -> Option<String> {
        // TODO: Filter by country support
        // TODO: filter proxies by session support
        // TODO: handle session id range for hosts per country proxies
        let proxy = self.proxies.choose(&mut rand::thread_rng())?;
        let (protocol, username, password, host, port) = parse_url(&proxy.url).unwrap();
        let base_url = self.templates[proxy.provider.as_str()]
            .template
            .replace("{protocol}", &protocol)
            .replace("{username}", &username)
            .replace("{password}", &password)
            .replace("{host}", &host)
            .replace("{port}", &port.to_string());
        let mut opts = String::new();

        // loop through self.templates[proxy.provider.as_str()].opts and build opts string
        for opt in &self.templates[proxy.provider.as_str()].opts {
            for word in opt.as_array().unwrap() {
                if let Some(true) = process_word(word, &settings, &mut opts) {
                    break;
                }
            }
        }
        let base_url = base_url.replace("{opts}", &opts);
        println!("Using base URL template: {}", base_url);
        return Some(base_url);
    }
}
