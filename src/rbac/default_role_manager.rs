
use std::collections::HashMap;

use crate::rbac::role::Role;
use crate::rbac::role_manager::RoleManager;

pub struct DefaultRoleManager {
    pub all_roles: HashMap<String, Role>,
}

impl RoleManager for DefaultRoleManager {

    fn clear(&self) {

    }

    fn add_link(&self, name1: &str, name2: &str, domain: &str) {

    }

    fn delete_link(&self, name1: &str, name2: &str, domain: &str) {

    }

    fn has_link(&self, name1: &str, name2: &str, domain: &str) {

    }

    fn get_roles(&self, name: &str, domain: &str) -> Vec<String> {
        Vec::new()
    }

    fn get_users(&self, name: &str) -> Vec<String> {
        Vec::new()
    }

    fn print_roles() {

    }
}
