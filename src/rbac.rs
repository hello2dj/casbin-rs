
use std::fmt;
use std::collections::HashMap;

use crate::error::Error;

pub trait RoleManager {
    fn clear(&mut self) -> Result<(), Error>;
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<(), Error>;
    fn delete_link(&mut self, name1: &str, name2: &str, domain: &str) -> Result<(), Error>;
    fn has_link(&self, name1: &str, name2: &str, domain: &str) -> Result<bool, Error>;
    fn get_roles(&self, name: &str, domain: &str) -> Result<Vec<String>, Error>;
    fn get_users(&self, name: &str) -> Result<Vec<String>, Error>;
    fn print_roles(&self) -> Result<(), Error>;
}

#[derive(Clone)]
pub struct Role {
    pub name: String,
    roles: Vec<Role>,
}

impl Role {
    pub fn new(name: &str) -> Self {
        Role {
            name: name.to_string(),
            roles: Vec::new(),
        }
    }

    pub fn add_role(&mut self, role: Role) {
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    pub fn delete_role(&mut self, role: Role) {
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
            if role.has_role(name, hierarchy_level - 1) {
                return true;
            }
        }

        false
    }

    pub fn has_direct_role(&self, name: &str) -> bool {
        for role in &self.roles {
            if self.name == role.name {
                return true;
            }
        }

        false
    }

    pub fn get_roles(&self) -> Vec<String> {
        let mut roles = Vec::new();
        for role in &self.roles {
            roles.push(role.name.clone());
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
