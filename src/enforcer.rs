use std::path::{Path, PathBuf};

use crate::effect::{DefaultEffector, Effector};
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
    pub fn new<P: 'static + Adapter>(model: &Path, policy: P) -> Result<Self, Error> {
        let mut enforcer = Enforcer {
            model: Model::new(model)?,
            model_path: PathBuf::from(model),
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
    pub fn enforce(subject: &str, object: &str, action: &str) -> Result<bool, Error> {
        unimplemented!()
    }

}
