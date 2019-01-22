use crate::error::Error;
use crate::model::Model;

pub mod file_adapter;

pub trait Adapter {
    fn load_policy(&self, model: &mut Model) -> Result<(), Error>;
    fn save_policy(&self, model: &mut Model) -> Result<(), Error>;
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

pub struct Filter {
    pub p: Vec<String>,
    pub g: Vec<String>,
}

impl Filter {
    pub fn new() -> Self {
        Filter {
            p: Vec::new(),
            g: Vec::new(),
        }
    }
}

pub trait FilteredAdapter: Adapter {
    fn load_filtered_policy(&self, model: &mut Model, filter: Option<&Filter>) -> Result<(), Error>;
    fn is_filtered(&self) -> bool;
}

pub trait Watcher {
    fn set_update_callback<F: FnMut(&str) + 'static>(&mut self, callback: F) -> Result<(), Error>;
    fn update(&self) -> Result<(), Error>;
}
