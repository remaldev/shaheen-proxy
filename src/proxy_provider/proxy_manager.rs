use super::helpers::{parse_url, process_word};
use super::ProxiesConfig;
use crate::{proxy_provider::Account, ClientConfig};
use rand::seq::SliceRandom;
use std::fs;

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
        let mut accounts = proxies
            .accounts
            .into_iter()
            .filter(|a| a.active)
            .map(|mut a| {
                a.countries = a.countries.to_lowercase();
                a
            })
            .collect::<Vec<_>>();
        accounts.shuffle(&mut rand::thread_rng());
        let config = proxies.shared_config;
        println!("Loaded {} active proxies", accounts.len());
        Ok(Self {
            proxies: accounts,
            templates: config.templates,
        })
    }

    pub fn select_proxy(&self, settings: &ClientConfig) -> Option<String> {
        // TODO: filter proxies by session support
        // TODO: handle session id range for hosts per country proxies
        let mut proxies = self.proxies.clone();
        // filter by country if specified
        if let Some(country) = &settings.country {
            proxies = proxies
                .into_iter()
                .filter(|p| p.r#type != "random" && p.countries.contains(&country.to_lowercase()))
                .collect();
        }
        let proxy = proxies.choose(&mut rand::thread_rng())?;
        let (protocol, username, password, host, port) = parse_url(&proxy.url).unwrap();

        // Build URL string efficiently
        let template = &self.templates[proxy.provider.as_str()];
        let mut base_url = template
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

        base_url = base_url.replace("{opts}", &opts);
        println!(">>> {}", base_url);
        Some(base_url)
    }
}
