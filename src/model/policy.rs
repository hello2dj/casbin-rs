use std::collections::HashMap;

use crate::assertion::Assertion;
use crate::error::Error;
use crate::model::Model;
use crate::rbac::RoleManager;

impl Model {
    /// Initialize the roles in RBAC.
    pub fn build_role_links<RM: RoleManager + Send + 'static>(&mut self, role_manager: &mut RM) -> Result<(), Error> {
        if let Some(g) = self.data.get_mut("g") {
            for assertion in g.values_mut() {
                assertion.build_role_links(role_manager)?;
            }
        }
        Ok(())
    }

    /// Clear all the current policies.
    pub fn clear_policy(&mut self) {
        if let Some(p) = self.data.get_mut("p") {
            for assertion in p.values_mut() {
                assertion.policy.clear();
            }
        }
        if let Some(g) = self.data.get_mut("g") {
            for assertion in g.values_mut() {
                assertion.policy.clear();
            }
        }
    }

    /// Get all the rules in a policy.
    pub fn get_policy(&self, section: &str, ptype: &str) -> Option<Vec<Vec<String>>> {
        if let Some(section_map) = self.data.get(section) {
            if let Some(assertion) = section_map.get(ptype) {
                return Some(assertion.policy.clone());
            }
        }
        None
    }

    /// Get rules based on field filters from a policy.
    pub fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: &[&str],
    ) -> Option<Vec<Vec<String>>> {
        let mut res: Vec<Vec<String>> = Vec::new();
        if let Some(sec_map) = self.data.get(sec) {
            if let Some(assertion) = sec_map.get(ptype) {
                for rules in &assertion.policy {
                    let mut matched = true;
                    let i_rules = &rules[field_index..];
                    for (rule, field_value) in i_rules.iter().zip(field_values) {
                        if !field_value.is_empty() && rule != field_value {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res.push(rules.clone());
                    }
                }
            }
        }
        if res.is_empty() {
            None
        } else {
            Some(res)
        }
    }

    /// Determine whether a model has the specified policy rule.
    pub fn has_policy(&self, sec: &str, ptype: &str, rule: &[&str]) -> bool {
        if let Some(sec_map) = self.data.get(sec) {
            if let Some(assertion) = sec_map.get(ptype) {
                for a_rule in &assertion.policy {
                    if a_rule.as_slice() == rule {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Add a policy rule to the model.
    pub fn add_policy(&mut self, sec: &str, ptype: &str, rule: &[&str]) -> bool {
        if !self.has_policy(sec, ptype, rule) {
            if !self.data.contains_key(sec) {
                let sec_map: HashMap<String, Assertion> = HashMap::new();
                self.data.insert(sec.to_string(), sec_map);
            }

            let sec_map = self.data.get_mut(sec).unwrap();
            if !sec_map.contains_key(ptype) {
                let assertion = Assertion::new();
                sec_map.insert(ptype.to_string(), assertion);
            }

            let rule: Vec<String> = rule.iter().map(|s| s.to_string()).collect();

            let assertion = sec_map.get_mut(ptype).unwrap();
            assertion.policy.push(rule);

            true
        } else {
            false
        }
    }

    /// Removes a policy rule from the model.
    pub fn remove_policy(&mut self, sec: &str, ptype: &str, rule: &[&str]) -> bool {
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

    /// Removes policy rules based on field filters from the model.
    pub fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: i32,
        field_values: Vec<String>,
    ) -> bool {
        let mut res: bool = false;
        if let Some(sec_map) = self.data.get_mut(sec) {
            if let Some(assertion) = sec_map.get_mut(ptype) {
                let mut tmp: Vec<Vec<String>> = Vec::new();
                for rules in &assertion.policy {
                    let mut matched = true;
                    let i_rules = &rules[field_index as usize..];
                    for (rule, field_value) in i_rules.iter().zip(&field_values) {
                        if !field_value.is_empty() && rule != field_value {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res = true;
                    } else {
                        tmp.push(rules.clone());
                    }
                }
                assertion.policy = tmp;
            }
        }
        res
    }

    /// Get all values for a field for all rules in a policy, duplicated values are removed.
    pub fn get_values_for_field_in_policy(&self, section: &str, ptype: &str, field_index: i32) -> Vec<String> {
        let mut values: Vec<String> = Vec::new();

        if let Some(sec_map) = self.data.get(section) {
            if let Some(assertion) = sec_map.get(ptype) {
                for rules in &assertion.policy {
                    if let Some(rule) = rules.get(field_index as usize) {
                        values.push(rule.to_string());
                    }
                }
            }
        }

        values.sort();
        values.dedup();
        values
    }
}
