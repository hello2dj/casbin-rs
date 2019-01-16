use crate::error::Error;
use crate::model::model::Model;

pub trait Adapter {
    fn load_policy(&self, model: Model) -> Result<(), Error>;
    fn save_policy(&self, model: Model) -> Result<(), Error>;
    fn add_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<(), Error>;
    fn remove_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<(), Error>;
    fn remove_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: i32,
        field_values: Vec<String>,
    ) -> Result<(), Error>;
}
