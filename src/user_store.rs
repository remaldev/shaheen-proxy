use dashmap::DashMap;

#[derive(Clone)]
pub struct User {
    pub password: String,
    pub active: bool,
}

pub struct UserStore {
    users: DashMap<String, User>,
}

impl UserStore {
    pub fn new() -> Self {
        Self {
            users: DashMap::new(),
        }
    }

    pub fn add_user(&self, username: String, password: String, active: bool) {
        self.users.insert(username, User { password, active });
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        self.users.get(username).map(|u| u.clone())
    }

    pub fn validate_credentials(&self, username: &str, password: &str) -> bool {
        if let Some(user) = self.get_user(username) {
            return user.active && user.password == password;
        }
        false
    }
}
