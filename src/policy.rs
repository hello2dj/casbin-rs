use crate::error::Error;
use crate::model::Model;
use crate::rbac::RoleManager;

impl Model {
    pub fn build_role_links(&mut self, role_manager: &mut Box<RoleManager>) -> Result<(), Error> {
        unimplemented!()
    }
}