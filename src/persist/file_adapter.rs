
use crate::error::Error;
use crate::model::model::Model;
use crate::persist::adapter::Adapter;

pub struct FileAdapter ();

impl Adapter for FileAdapter {

    fn load_policy(&self, model: Model) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }

    fn save_policy(&self, model: Model) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }

    fn add_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }

    fn remove_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }

    fn remove_filtered_policy(&self, sec: &str, ptype: &str,
                              field_index: i32, field_values: Vec<String>) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
}
