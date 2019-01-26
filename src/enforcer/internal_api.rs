use crate::effect::Effector;
use crate::enforcer::Enforcer;
use crate::persist::Adapter;
use crate::rbac::RoleManager;

impl<A: Adapter, RM: RoleManager + Send + 'static, E: Effector> Enforcer<A, RM, E> {
    /// Add a rule to the current policy.
    pub(crate) fn add_policy_internal(&mut self, section: &str, ptype: &str, rule: &[&str]) -> bool {
        self.model.add_policy(section, ptype, rule)
    }

    /// Remove a rule from the current policy
    pub(crate) fn remove_policy_internal(&mut self, section: &str, ptype: &str, rule: &[&str]) -> bool {
        self.model.remove_policy(section, ptype, rule)
    }

    /// Remove rules based on field filters from the current policy.
    pub(crate) fn remove_filtered_policy_internal(
        &mut self,
        section: &str,
        ptype: &str,
        field_index: usize,
        field_values: &[&str],
    ) -> bool {
        self.model
            .remove_filtered_policy(section, ptype, field_index, field_values)
    }
}
