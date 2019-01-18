use crate::error::Error;
use crate::rbac::RoleManager;

pub struct Assertion {
    pub key: String,
    pub value: String,
    pub tokens: Vec<String>,
    pub policy: Vec<Vec<String>>,
}

impl Assertion {
    pub fn new() -> Self {
        Assertion {
            key: "".to_string(),
            value: "".to_string(),
            tokens: Vec::new(),
            policy: Vec::new(),
        }
    }

    pub fn build_role_links<RM: RoleManager>(&mut self, role_manager: &mut RM) -> Result<(), Error> {
        let count = self.value.matches("_").count();
        for rule in &self.policy {
            if count < 2 {
                // the number of '_' characters in a role definition must be at least 2
                return Err(Error::ParsingFailure);
            } else if rule.len() < count {
                // grouping policy elements does not match the role definition
                return Err(Error::ParsingFailure);
            }

            if count == 2 {
                role_manager.add_link(&rule[0], &rule[1], None)?;
            } else if count == 3 {
                role_manager.add_link(&rule[0], &rule[1], Some(&rule[2]))?;
            } else if count == 4 {
                // the original code does something here, but I'm not sure if it's supposed to work.
                return Err(Error::ParsingFailure);
            } else {
                return Err(Error::ParsingFailure);
            }
        }
        Ok(())
    }
}
