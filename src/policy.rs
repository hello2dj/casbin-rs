use std::collections::HashMap;

use crate::error::Error;
use crate::model::Model;
use crate::rbac::RoleManager;
use crate::assertion::Assertion;

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

    pub fn has_policy(&self, sec: &str, ptype: &str, rule: &Vec<String>) -> bool {
        if let Some(sec_map) = self.data.get(sec) {
            if let Some(assertion) = sec_map.get(ptype) {
                for a_rule in &assertion.policy {
                    if a_rule == rule {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        if !self.has_policy(sec, ptype, &rule) {
            if !self.data.contains_key(sec) {
                let sec_map: HashMap<String, Assertion> = HashMap::new();
                self.data.insert(sec.to_string(), sec_map);
            }

            let sec_map = self.data.get_mut(sec).unwrap();
            if !sec_map.contains_key(ptype) {
                let assertion = Assertion::new();
                sec_map.insert(ptype.to_string(), assertion);
            }

            let assertion = sec_map.get_mut(ptype).unwrap();
            assertion.policy.push(rule);

            true;
        }
        false
    }

    pub fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        if let Some(sec_map) = self.data.get_mut(sec) {
            if let Some(assertion) = sec_map.get_mut(ptype) {
                let index = assertion.policy.iter().position(|x| *x == rule);
                if let Some(index) = index {
                    assertion.policy.remove(index);
                    return true;
                }
            }
        }
        false
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
    ) -> Vec<String> {
        let mut values: Vec<String> = Vec::new();

        for (_, sec_map) in &self.data {
            for (_, assertion) in sec_map {
                for rules in &assertion.policy {
                    for rule in rules {
                        values.push(rule.to_string());
                    }
                }
            }
        }

        values.sort();
        values.dedup();

        return values;
    }
}
