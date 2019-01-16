
use crate::model::model::Model;
use crate::persist::adapter::Adapter;

pub struct FileAdapter ();

impl Adapter for FileAdapter {

    fn load_policy(&self, model: Model) {

    }

    fn save_policy(&self, model: Model) {

    }

    fn add_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) {

    }

    fn remove_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) {

    }

    fn remove_filtered_policy(&self, sec: &str, ptype: &str, field_index: i32, field_values: Vec<String>) {

    }
}
