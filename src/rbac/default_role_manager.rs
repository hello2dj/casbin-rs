use std::collections::HashMap;

use crate::error::Error;
use crate::rbac::{Role, RoleManager};

pub struct DefaultRoleManager {
    all_roles: HashMap<String, Role>,
    max_hierarchy_level: i32,
}

impl RoleManager for DefaultRoleManager {
    fn clear(&mut self) -> Result<(), Error> {
        Ok(self.all_roles.clear())
    }

    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error> {
        unimplemented!()
    }

    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error> {
        unimplemented!()
    }

    fn has_link(&self, name1: &str, name2: &str, domain: Option<&str>) -> Result<bool, Error> {
        unimplemented!()
    }

    fn get_roles(&self, name: &str, domain: Option<&str>) -> Result<Vec<String>, Error> {
        unimplemented!()
    }

    fn get_users(&self, name: &str) -> Result<Vec<String>, Error> {
        unimplemented!()
    }

    fn print_roles(&self) -> Result<(), Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_role() {
        let mut manager = DefaultRoleManager::new(3);
        manager.add_link("u1", "g1", None).unwrap();
        manager.add_link("u2", "g1", None).unwrap();
        manager.add_link("u3", "g2", None).unwrap();
        manager.add_link("u4", "g2", None).unwrap();
        manager.add_link("u4", "g3", None).unwrap();
        manager.add_link("g1", "g3", None).unwrap();

        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2
    
        assert_eq!(manager.has_link("u1", "g1", None).unwrap(), true);
        assert_eq!(manager.has_link("u1", "g2", None).unwrap(), false);
        assert_eq!(manager.has_link("u1", "g3", None).unwrap(), true);
        assert_eq!(manager.has_link("u2", "g1", None).unwrap(), true);
        assert_eq!(manager.has_link("u2", "g2", None).unwrap(), false);
        assert_eq!(manager.has_link("u2", "g3", None).unwrap(), true);
        assert_eq!(manager.has_link("u3", "g1", None).unwrap(), false);
        assert_eq!(manager.has_link("u3", "g2", None).unwrap(), true);
        assert_eq!(manager.has_link("u3", "g3", None).unwrap(), false);
        assert_eq!(manager.has_link("u4", "g2", None).unwrap(), true);
        assert_eq!(manager.has_link("u4", "g3", None).unwrap(), true);   
    
    }
}