use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct SessionStore {
    sessions: DashMap<String, SessionEntry>,
}

struct SessionEntry {
    proxy_url: String,
    expires_at: Instant,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn get(&self, sid: &str) -> Option<String> {
        if let Some(entry) = self.sessions.get(sid) {
            if entry.expires_at > Instant::now() {
                return Some(entry.proxy_url.clone());
            }
            drop(entry);
            self.sessions.remove(sid);
        }
        None
    }

    pub fn set(&self, sid: String, proxy_url: String, ttl_secs: u64) {
        self.sessions.insert(
            sid,
            SessionEntry {
                proxy_url,
                expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
    }

    /// Remove all expired sessions from memory
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.sessions.retain(|_, entry| entry.expires_at > now);
    }

    /// Spawn background task to cleanup expired sessions every interval
    pub fn spawn_cleanup_task(store: Arc<Self>, interval_secs: u64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let before = store.sessions.len();
                store.cleanup_expired();
                let after = store.sessions.len();
                if before != after {
                    eprintln!(
                        "[SESSION CLEANUP] Removed {} expired sessions",
                        before - after
                    );
                }
            }
        });
    }
}
