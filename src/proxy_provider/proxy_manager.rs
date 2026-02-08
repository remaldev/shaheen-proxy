use super::helpers::{parse_proxy_url, replace_template_placeholder};
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

    pub fn select_proxy(
        &self,
        settings: &ClientConfig,
        exclude_urls: &[String],
    ) -> Option<(String, String)> {
        // Returns: (generated_proxy_url, base_proxy_url_for_exclusion)
        // TODO: support random host id even when no session id requested (for proxies with hosts_per_country)
        // Filter proxies based on settings
        let mut filtered: Vec<&Account> = self.proxies.iter().collect();

        // Filter out excluded proxy base URLs
        if !exclude_urls.is_empty() {
            filtered.retain(|p| !exclude_urls.contains(&p.url));
        }

        // Filter by session support if session ID requested
        if settings.sid.is_some() {
            filtered.retain(|p| {
                // Allow proxies with {session} support OR hosts_per_country (for host_id-based sessions)
                let has_session_support =
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
                    };

                has_session_support || p.hosts_per_country.is_some()
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

        let proxy = filtered.choose(&mut rand::thread_rng())?;

        // Prepare settings (potentially with generated host_id and country for hosts_per_country proxies)
        let settings_owned;
        let final_settings: &ClientConfig;

        // If proxy has hosts_per_country and session is requested, generate host_id
        if let (Some(_), Some(hosts_map)) = (&settings.sid, &proxy.hosts_per_country) {
            if settings.host_id.is_none() {
                // Determine which country to use
                let target_country = if let Some(country) = &settings.country {
                    country.to_lowercase()
                } else {
                    // Pick random country from proxy's available countries
                    let countries: Vec<&String> = hosts_map.keys().collect();
                    countries.choose(&mut rand::thread_rng())?.to_string()
                };

                // Get max host_id for that country
                if let Some(&max_hosts) = hosts_map.get(&target_country) {
                    // Generate random host_id in range [1, max_hosts]
                    let random_host_id = (rand::random::<u32>() % max_hosts) + 1;

                    // Create modified settings
                    settings_owned = ClientConfig {
                        user: settings.user.clone(),
                        country: Some(target_country),
                        state: settings.state.clone(),
                        city: settings.city.clone(),
                        sid: settings.sid.clone(),
                        host_id: Some(random_host_id as u64),
                        ttl: settings.ttl,
                        parse_error: None,
                    };
                    final_settings = &settings_owned;
                } else {
                    final_settings = settings;
                }
            } else {
                final_settings = settings;
            }
        } else {
            final_settings = settings;
        }

        let (protocol, username, password, host, port) = parse_proxy_url(&proxy.url)?;
        println!(
            "Parsed proxy URL - protocol: {}, username: {}, password: {}, host: {}, port: {}",
            protocol, username, password, host, port
        );
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
                    if let Some(true) =
                        replace_template_placeholder(word, final_settings, &mut opts)
                    {
                        break;
                    }
                }
            }
        }

        base_url = base_url.replace("{opts}", &opts);
        println!(">>> {}", base_url);
        Some((base_url, proxy.url.clone()))
    }
}
