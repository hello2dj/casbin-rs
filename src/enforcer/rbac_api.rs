use crate::effect::Effector;
use crate::enforcer::Enforcer;
use crate::persist::Adapter;
use crate::rbac::RoleManager;

impl<A: Adapter, RM: RoleManager + Send + 'static, E: Effector> Enforcer<A, RM, E> {
    /// Get the list of roles for `user`.
    pub fn get_roles_for_user(&self, user: &str, domain: Option<&str>) -> Vec<String> {
        self.role_manager.lock().unwrap().get_roles(user, domain)
    }

    /// Get the list users that have the speficied `role`.
    pub fn get_users_for_role(&self, role: &str, domain: Option<&str>) -> Vec<String> {
        self.role_manager.lock().unwrap().get_users(role, domain)
    }

    /// Returns true if `user` has the specified `role`.
    pub fn has_role_for_user(&self, user: &str, role: &str, domain: Option<&str>) -> bool {
        let roles = self.get_roles_for_user(user, domain);
        roles.iter().any(|r| r == role)
    }

    /// Add a `role` for a `user`.
    pub fn add_role_for_user(&mut self, user: &str, role: &str) -> bool {
        let policy = [user, role];
        self.add_grouping_policy(&policy)
    }

    /// Delete a `role` for a `user`.
    pub fn delete_role_for_user(&mut self, user: &str, role: &str) -> bool {
        let policy = [user, role];
        self.remove_grouping_policy(&policy)
    }

    /// Adds a permission for a `user` or `role`.
    ///
    /// Returns false if the user or role already has the permission.
    pub fn add_permission_for_user(&mut self, user: &str, permission: &[&str]) -> bool {
        let mut params = vec![user];
        params.extend(permission);
        self.add_policy(&params)
    }
}
