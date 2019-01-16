use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::model::Model;
use crate::persist::Adapter;

/// Enforcer is the main interface for authorization enforcement and policy management.
pub struct Enforcer{
    model: Model,
    model_path: PathBuf,
    adapter: Box<Adapter>,
}

impl Enforcer {
    pub fn new<P: 'static + Adapter>(model: &Path, policy: P) -> Result<Self, Error> {
        Ok(Enforcer{
            model: Model::new(model)?,
            model_path: PathBuf::from(model),
            adapter: Box::new(policy),
        })
    }
}