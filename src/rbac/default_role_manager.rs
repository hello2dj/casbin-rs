use std::collections::HashMap;

use crate::error::Error;
use crate::rbac::role::Role;
use crate::rbac::role_manager::RoleManager;

pub struct DefaultRoleManager {
    all_roles: HashMap<String, Role>,
    max_hierarchy_level: i32,
}

impl RoleManager for DefaultRoleManager {
    fn clear(&mut self) -> Result<(), Error> {
        Ok(self.all_roles.clear())
    }

    fn add_link(&mut self, name1: &str, name2: &str, domain: &str) -> Result<(), Error> {
        unimplemented!()
    }

    fn delete_link(&mut self, name1: &str, name2: &str, domain: &str) -> Result<(), Error> {
        unimplemented!()
    }

    fn has_link(&self, name1: &str, name2: &str, domain: &str) -> Result<bool, Error> {
        unimplemented!()
    }

    fn get_roles(&self, name: &str, domain: &str) -> Result<Vec<String>, Error> {
        unimplemented!()
    }

    fn get_users(&self, name: &str) -> Result<Vec<String>, Error> {
        unimplemented!()
    }

    fn print_roles() -> Result<(), Error> {
        unimplemented!()
    }
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: i32) -> Self {
        DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level: max_hierarchy_level,
        }
    }

    fn has_role(&self, name: &str) -> bool {
        self.all_roles.contains_key(name)
    }

    fn create_role(&mut self, name: &str) -> &mut Role {
        if self.has_role(name) {
            self.all_roles.get_mut(name).unwrap()
        } else {
            let mut role = Role::new(name);
            &self.all_roles.insert(name.to_string(), role);
            self.all_roles.get_mut(name).unwrap()
        }
    }
}
