use crate::effect::Effector;
use crate::enforcer::Enforcer;
use crate::persist::Adapter;
use crate::rbac::RoleManager;

impl<A: Adapter, RM: RoleManager + Send + 'static, E: Effector> Enforcer<A, RM, E> {
    /// Add a rule to the current policy.
    pub(crate) fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: &[&str]) -> bool {
        self.model.add_policy(sec, ptype, rule)
    }

    /// Remove a rule from the current policy
    pub(crate) fn remove_policy_internal(&mut self, sec: &str, ptype: &str, rule: &[&str]) -> bool {
        self.model.remove_policy(sec, ptype, rule)
    }
}
