use std::path::{Path, PathBuf};

use crate::effect::{DefaultEffector, Effect, Effector};
use crate::error::Error;
use crate::model::Model;
use crate::model::{get_function_map, FunctionMap};
use crate::persist::Adapter;
use crate::rbac::{DefaultRoleManager, RoleManager};

#[derive(Debug)]
pub struct DefaultEnforcer();

impl DefaultEnforcer {
    pub fn new<M: AsRef<Path>, A: Adapter>(
        model: M,
        policy: A,
    ) -> Result<Enforcer<A, DefaultRoleManager, DefaultEffector>, Error> {
        Enforcer::new(model, policy, DefaultRoleManager::new(10), DefaultEffector::new())
    }
}

/// Enforcer is the main interface for authorization enforcement and policy management.
#[derive(Debug)]
pub struct Enforcer<A: Adapter, RM: RoleManager, E: Effector> {
    model: Model,
    model_path: PathBuf,
    function_map: FunctionMap,
    adapter: A,
    role_manager: RM,
    effector: E,
    auto_build_role_links: bool,
}

impl<A: Adapter, RM: RoleManager, E: Effector> Enforcer<A, RM, E> {
    /// Create an instance of an Enforcer from a `model` and `policy`.
    pub fn new<M: AsRef<Path>>(
        model: M,
        policy: A,
        role_manager: RM,
        effector: E,
    ) -> Result<Enforcer<A, RM, E>, Error> {
        let mut enforcer = Enforcer {
            model_path: PathBuf::from(model.as_ref()),
            model: Model::from_file(model)?,
            function_map: get_function_map(),
            adapter: policy,
            role_manager,
            effector,
            auto_build_role_links: true,
        };

        enforcer.load_policy()?;

        Ok(enforcer)
    }

    /// Rebuild the role inheritance relations.
    fn build_role_links(&mut self) -> Result<(), Error> {
        self.role_manager.clear()?;
        self.model.build_role_links(&mut self.role_manager)?;
        Ok(())
    }

    /// Reload the policy from source.
    fn load_policy(&mut self) -> Result<(), Error> {
        self.model.clear_policy();
        self.adapter.load_policy(&mut self.model)?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        Ok(())
    }

    /// Decide whether `subject` can access `object` with the operation `action`.

    // TODO: enforce does not handle matcherResults.
    pub fn enforce(&self, subject: &str, object: &str, action: &str) -> Result<bool, Error> {
        let mut policy_effects: Vec<Effect> = vec![];

        for policy in &self.model.data["p"]["p"].policy {
            dbg!(policy);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::persist::file_adapter::FileAdapter;

    #[test]
    fn test_match_in_memory() {
        let adapter = FileAdapter::new("examples/basic_policy.csv", false);
        let enforcer =
            DefaultEnforcer::new("examples/basic_model.conf", adapter).expect("failed to create instance of Enforcer");

        enforcer.enforce("alice", "data1", "read");
    }
}
