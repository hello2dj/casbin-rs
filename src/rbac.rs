use std::fmt;
use std::cell::RefCell;
use std::rc::Rc;

use crate::error::Error;

mod default_role_manager;

pub use crate::rbac::default_role_manager::DefaultRoleManager;

pub trait RoleManager {
    fn clear(&mut self) -> Result<(), Error>;
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error>;
    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error>;
    fn has_link(&self, name1: &str, name2: &str, domain: Option<&str>) -> Result<bool, Error>;
    fn get_roles(&self, name: &str, domain: Option<&str>) -> Result<Vec<String>, Error>;
    fn get_users(&self, name: &str) -> Result<Vec<String>, Error>;
    fn print_roles(&self) -> Result<(), Error>;
}

#[derive(Clone)]
pub struct Role {
    pub name: String,
    roles: Vec<Rc<RefCell<Role>>>,
}

impl Role {
    pub fn new(name: &str) -> Self {
        Role {
            name: name.to_string(),
            roles: Vec::new(),
        }
    }

    pub fn add_role(&mut self, role: Rc<RefCell<Role>>) {
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    pub fn delete_role(&mut self, role: Rc<RefCell<Role>>) {
        let index = self.roles.iter().position(|x| *x == role);
        if let Some(index) = index {
            self.roles.remove(index);
        }
    }

    pub fn has_role(&self, name: &str, hierarchy_level: i32) -> bool {
        if self.name == name {
            return true;
        }

        if hierarchy_level <= 0 {
            return false;
        }

        for role in &self.roles {
            if role.borrow().has_role(name, hierarchy_level - 1) {
                return true;
            }
        }

        false
    }

    pub fn has_direct_role(&self, name: &str) -> bool {
        for role in &self.roles {
            if self.name == role.borrow().name {
                return true;
            }
        }

        false
    }

    pub fn get_roles(&self) -> Vec<String> {
        let mut roles = Vec::new();
        for role in &self.roles {
            roles.push(role.borrow().name.clone());
        }
        roles
    }
}

impl PartialEq for Role {
    fn eq(&self, other: &Role) -> bool {
        self.name == other.name
    }
}

impl fmt::Display for Role {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.name.as_ref())?;
        fmt.write_str(" < ")?;
        let roles = self.get_roles();
        fmt.write_str(&roles.join(","))?;
        Ok(())
    }
}