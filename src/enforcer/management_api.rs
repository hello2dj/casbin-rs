use crate::effect::Effector;
use crate::enforcer::Enforcer;
use crate::persist::Adapter;
use crate::rbac::RoleManager;

impl<A: Adapter, RM: RoleManager + Send + 'static, E: Effector> Enforcer<A, RM, E> {
    /// Get the list of subjects that show up in the current policy.
    pub fn get_all_subjects(&self) -> Vec<String> {
        self.get_all_named_subjects("p")
    }
    
    /// Get the list of subjects that show up in the current named policy.
    pub fn get_all_named_subjects(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("p", ptype, 0)
    }

    /// Get the list of objects that show up in the current policy.
    pub fn get_all_objects(&self) -> Vec<String> {
        self.get_all_named_objects("p")
    }
    
    /// Get the list of objects that show up in the current named policy.
    pub fn get_all_named_objects(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("p", ptype, 1)
    }

    /// Get the list of actions that show up in the current policy.
    pub fn get_all_actions(&self) -> Vec<String> {
        self.get_all_named_actions("p")
    }

    /// Get the list of actions that show up in the current named policy.
    pub fn get_all_named_actions(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("p", ptype, 2)
    }

    /// Get the list of roles that show up in the current policy.
    pub fn get_all_roles(&self) -> Vec<String> {
        self.get_all_named_roles("g")
    }

    /// Get the list of roles that show up in the current named policy.
    pub fn get_all_named_roles(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("g", ptype, 1)
    }

    /// Get all the authorization rules in the policy.
    pub fn get_policy(&self) -> Vec<Vec<String>> {
        self.get_named_policy("p")
    }

    /// Get all the authorization rules in the named policy.
    pub fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.model.get_policy("p", ptype).unwrap_or(vec![vec![]])
    }

    /// Get all the role inheritance rules in the policy.
    pub fn get_grouping_policy(&self) -> Vec<Vec<String>> {
        self.get_named_grouping_policy("g")
    }

    /// Get all the role inheritance rules in the policy.
    pub fn get_named_grouping_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.model.get_policy("g", ptype).unwrap_or(vec![vec![]])
    }

    /// Determine whether an authorization rule exists.
    pub fn has_policy(&self, policy: &[&str]) -> bool {
        self.has_named_policy("p", policy)
    }
    
    /// Determines whether a named authorization rule exists.
    pub fn has_named_policy(&self, ptype: &str, policy: &[&str]) -> bool {
        self.model.has_policy("p", ptype, policy)
    }

    /// Add an authorization rule to the current policy.
    ///
    /// If the rule already exists, the function returns false and the rule will not be added.
    /// Otherwise the function returns true by adding the new rule.
    pub fn add_policy(&mut self, policy: &[&str]) -> bool {
        self.add_named_policy("p", policy)
    }

    /// Add an authorization rule to the current named policy.
    ///
    /// If the rule already exists, the function returns false and the rule will not be added.
    /// Otherwise the function returns true by adding the new rule.
    pub fn add_named_policy(&mut self, ptype: &str, policy: &[&str]) -> bool {
        self.add_policy_internal("p", ptype, policy)
    }

    /// Remove an authorization rule from the current policy.
    pub fn remove_policy(&mut self, policy: &[&str]) -> bool {
        self.remove_named_policy("p", policy)
    }

    /// Remove an authorization rule from the current named policy.
    pub fn remove_named_policy(&mut self, ptype: &str, policy: &[&str]) -> bool {
        self.remove_policy_internal("p", ptype, policy)
    }

    /// Determine whether a role inheritance rule exists.
    pub fn has_grouping_policy(&self, policy: &[&str]) -> bool {
        self.has_named_grouping_policy("g", policy)
    }

    /// Determine whether a named role inheritance rule exists.
    pub fn has_named_grouping_policy(&self, ptype: &str, policy: &[&str]) -> bool {
        self.model.has_policy("g", ptype, policy)
    }

    /// Add a role inheritance rule to the current policy.
    ///
    /// If the rule already exists, the function returns false and the rule will not be added.
    /// Otherwise the function returns true by adding the new rule.
    pub fn add_grouping_policy(&mut self, policy: &[&str]) -> bool {
        self.add_named_grouping_policy("g", policy)
    }

    /// Add a named role inheritance rule to the current policy.
    ///
    /// If the rule already exists, the function returns false and the rule will not be added.
    /// Otherwise the function returns true by adding the new rule.
    pub fn add_named_grouping_policy(&mut self, ptype: &str, policy: &[&str]) -> bool {
        let rule_added = self.add_policy_internal("g", ptype, policy);

        if rule_added && self.auto_build_role_links {
            self.build_role_links().expect("build_role_links failed");
        }

        rule_added
    }

    /// Remove a role inheritance rule from the current policy.
    pub fn remove_grouping_policy(&mut self, policy: &[&str]) -> bool {
        self.remove_named_grouping_policy("g", policy)
    }

    /// Remove a role inheritance rule from the current policy.
    pub fn remove_named_grouping_policy(&mut self, ptype: &str, policy: &[&str]) -> bool {
        let rule_removed = self.remove_policy_internal("g", ptype, policy);

        if rule_removed && self.auto_build_role_links {
            self.build_role_links().expect("build_role_links failed");
        }

        rule_removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::enforcer::DefaultEnforcer;
    use crate::model::Model;
    use crate::persist::file_adapter::FileAdapter;

    #[test]
    #[ignore]
    // TODO(sduquette): This test is currently failing.
    fn test_get_policy_api() {
        let model = Model::from_file("examples/rbac_model.conf").expect("failed to load model");
        let adapter = FileAdapter::new("examples/rbac_policy.csv", false);
        let enforcer = DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");

    }
}