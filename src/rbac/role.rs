
use std::fmt;

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
        if index.is_some() {
            self.roles.remove(index.unwrap());
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
