
use crate::model::Model;

pub trait Adapter {
    fn load_policy(&self, model: Model);
    fn save_policy(&self, model: Model);
    fn add_policy(&self, sec: &str, ptype: &str, rule: Vec<String>);
    fn remove_policy(&self, sec: &str, ptype: &str, Vec<String>);
    fn remove_filtered_policy(&self, sec: &str, ptype: &str, fieldIndex: i32, field_values: Vec<String>);
}
