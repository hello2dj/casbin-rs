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
}

impl Enforcer {
    pub fn new<P: 'static + Adapter>(model: &Path, policy: P) -> Result<Self, Error> {
        Ok(Enforcer {
            model: Model::new(model)?,
            model_path: PathBuf::from(model),
            function_map: get_function_map(),
            adapter: Box::new(policy),
            role_manager: Box::new(DefaultRoleManager::new(10)),
            effector: Box::new(DefaultEffector::new()),
        })
    }
}
