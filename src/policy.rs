use crate::error::Error;
use crate::model::Model;
use crate::rbac::RoleManager;

impl Model {
    pub fn build_role_links(&mut self, role_manager: &mut Box<RoleManager>) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn clear_policy(&mut self) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn get_policy(&mut self, sec: &str, ptype: &str) -> Result<Vec<Vec<String>>, Error> {
        unimplemented!()
    }

    pub fn get_filtered_policy(&mut self, sec: &str, ptype: &str, field_index: i32, field_values: Vec<String>) -> Result<Vec<Vec<String>>, Error> {
        unimplemented!()
    }

    pub fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool, Error> {
        unimplemented!()
    }

    pub fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool, Error> {
        unimplemented!()
    }

    pub fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool, Error> {
        unimplemented!()
    }

    pub fn remove_filtered_policy(&mut self, sec: &str, ptype: &str, field_index: i32, field_values: Vec<String>) -> Result<bool, Error> {
        unimplemented!()
    }

    pub fn get_values_for_field_in_policy(&self, sec: &str, ptype: &str, field_index: i32) -> Result<Vec<String>, Error> {
        unimplemented!()
    }
}
