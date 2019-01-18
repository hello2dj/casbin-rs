use crate::error::Error;
use crate::model::Model;
use crate::rbac::RoleManager;

impl Model {
    pub fn build_role_links(&mut self, role_manager: &mut Box<RoleManager>) -> Result<(), Error> {
        if let Some(g) = self.data.get_mut("g") {
            for (name, assertion) in g.iter_mut() {
                assertion.build_role_links(role_manager)?;
            }
        }
        Ok(())
    }

    pub fn clear_policy(&mut self) -> Result<(), Error> {
        if let Some(p) = self.data.get_mut("p") {
            p.clear();
        }
        if let Some(g) = self.data.get_mut("g") {
            g.clear();
        }
        Ok(())
    }

    pub fn get_policy(&mut self, sec: &str, ptype: &str) -> Option<Vec<Vec<String>>> {
        if let Some(sec_map) = self.data.get(sec) {
            if let Some(assertion) = sec_map.get(ptype) {
                Some(assertion.policy.clone()); // FIXME: check if we need a reference, or a copy
            }
        }
        None
    }

    pub fn get_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: i32,
        field_values: Vec<String>,
    ) -> Option<Vec<Vec<String>>> {
        unimplemented!()
    }

    pub fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        if let Some(sec_map) = self.data.get(sec) {
            if let Some(assertion) = sec_map.get(ptype) {
                for a_rule in &assertion.policy {
                    if a_rule == &rule {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool, Error> {
        unimplemented!()
    }

    pub fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool, Error> {
        unimplemented!()
    }

    pub fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: i32,
        field_values: Vec<String>,
    ) -> Result<bool, Error> {
        unimplemented!()
    }

    pub fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: i32,
    ) -> Result<Vec<String>, Error> {
        unimplemented!()
    }
}
