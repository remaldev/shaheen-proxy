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
                return a;
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
        // TODO: handle session id range for hosts per country proxies

        // Filter proxies based on settings
        let mut filtered: Vec<&Account> = self.proxies.iter().collect();

        // Filter by session support if session ID requested
        if settings.sid.is_some() {
            filtered.retain(|p| {
                // Only allow proxies whose templates support {session} in opts
                if let Some(template) = self.templates.get(p.provider.as_str()) {
                    template.opts.iter().any(|opt| {
                        if let Some(arr) = opt.as_array() {
                            arr.iter().any(|item| {
                                if let Some(s) = item.as_str() {
                                    s.contains("{session}")
                                } else {
                                    false
                                }
                            })
                        } else {
                            false
                        }
                    })
                } else {
                    false
                }
            });
        }

        // Filter by country if specified
        if let Some(country) = &settings.country {
            let country_lower = country.to_lowercase();
            filtered.retain(|p| p.r#type != "random" && p.countries.contains(&country_lower));
        }

        // Filter by host_id if specified
        if let Some(host_id) = settings.host_id {
            filtered.retain(|p| {
                p.hosts_per_country
                    .as_ref()
                    .map(|hosts| hosts.values().any(|&id| id as u64 == host_id))
                    .unwrap_or(false)
            });
        }

        // TODO: If proxy has hosts_per_country and no host_id specified,
        // randomly select a host_id from the available range for session stickiness

        let proxy = filtered.choose(&mut rand::thread_rng())?;

        let (protocol, username, password, host, port) = parse_url(&proxy.url)?;

        // Get template for provider
        let template = match self.templates.get(proxy.provider.as_str()) {
            Some(t) => t,
            None => {
                eprintln!(
                    "[ERROR] Template '{}' not found for proxy URL: {}",
                    proxy.provider, proxy.url
                );
                return None;
            }
        };

        // Build URL from template
        let mut base_url = template
            .template
            .replace("{protocol}", &protocol)
            .replace("{username}", &username)
            .replace("{password}", &password)
            .replace("{host}", &host)
            .replace("{port}", &port.to_string());

        let mut opts = String::new();

        // Process template options
        for opt in &template.opts {
            if let Some(arr) = opt.as_array() {
                for word in arr {
                    if let Some(true) = process_word(word, settings, &mut opts) {
                        break;
                    }
                }
            }
        }

        base_url = base_url.replace("{opts}", &opts);
        println!(">>> {}", base_url);
        Some(base_url)
    }
}
