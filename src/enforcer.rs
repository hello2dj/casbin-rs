use std::path::{Path, PathBuf};

use crate::effect::{DefaultEffector, Effector, Effect};
use crate::error::Error;
use crate::model::Model;
use crate::model::{get_function_map, FunctionMap};
use crate::persist::Adapter;
use crate::rbac::{DefaultRoleManager, RoleManager};

/// Enforcer is the main interface for authorization enforcement and policy management.
pub struct Enforcer {
    model: Model,
    model_path: PathBuf,
    function_map: FunctionMap,
    adapter: Box<Adapter>,
    role_manager: Box<RoleManager>,
    effector: Box<Effector>,
    auto_build_role_links: bool,
}

impl Enforcer {
    /// Create an instance of an Enforcer from a `model` and `policy`.
    pub fn new<M: AsRef<Path>, P: 'static + Adapter>(model: M, policy: P) -> Result<Self, Error> {
        let mut enforcer = Enforcer {
            model_path: PathBuf::from(model.as_ref()),
            model: Model::from_file(model)?,
            function_map: get_function_map(),
            adapter: Box::new(policy),
            role_manager: Box::new(DefaultRoleManager::new(10)),
            effector: Box::new(DefaultEffector::new()),
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
        let enforcer = Enforcer::new("examples/basic_model.conf", adapter).expect("failed to create instance of Enforcer");

        enforcer.enforce("alice", "data1", "read");
    }
}