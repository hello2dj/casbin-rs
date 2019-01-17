// TODO:
// - Add support for matching functions.
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::error::Error;
use crate::rbac::{Role, RoleManager};

pub struct DefaultRoleManager {
    all_roles: HashMap<String, Rc<RefCell<Role>>>,
    max_hierarchy_level: i32,
}

impl RoleManager for DefaultRoleManager {
    fn clear(&mut self) -> Result<(), Error> {
        Ok(self.all_roles.clear())
    }

    // Add a link such that `name1` inherits the role `name2`.
    // 
    // `domain` is a prefix to the roles.
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error> {
        let (name1, name2) = DefaultRoleManager::get_names_with_domain(name1, name2, domain);

        let role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);

        role1.borrow_mut().add_role(role2);

        Ok(())
    }

    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error> {
        unimplemented!()
    }

    // Return true if `name1` inherits the role `name2`.
    fn has_link(&self, name1: &str, name2: &str, domain: Option<&str>) -> Result<bool, Error> {
        let (name1, name2) = DefaultRoleManager::get_names_with_domain(name1, name2, domain);
        
        let role1 = self.get_role(&name1).ok_or(Error::MissingRole(name1.clone()))?;

        if !self.has_role(&name2) {
            return Err(Error::MissingRole(name2));
        }

        if name1 == name2 {
            return Ok(true);
        }

        let result = role1.borrow().has_role(&name2, self.max_hierarchy_level);
        Ok(result)
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

    fn create_role(&mut self, name: &str) -> Rc<RefCell<Role>> {
        if self.has_role(name) {
            Rc::clone(self.all_roles.get(name).unwrap())
        } else {
            let role = Role::new(name);
            &self.all_roles.insert(name.to_string(), Rc::new(RefCell::new(role)));
            Rc::clone(self.all_roles.get(name).unwrap())
        }
    }

    fn get_role(&self, name: &str) -> Option<Rc<RefCell<Role>>> {
        if self.has_role(name) {
            Some(Rc::clone(self.all_roles.get(name).unwrap()))
        } else {
            None
        }
    }

    fn get_names_with_domain(name1: &str, name2: &str, domain: Option<&str>) -> (String, String) {
        match domain {
            Some(domain) => (domain.to_string() + "::" + name1, domain.to_string() + "::" + name2),
            None => (name1.to_string(), name2.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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