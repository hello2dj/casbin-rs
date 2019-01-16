use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::error::Error;

pub struct Model {
    pub data: HashMap<String, String>,
}

impl Model {
    fn load_assertion(&self, cfg: Config, sec: &str, key: &str) -> Result<bool, Error> {
        unimplemented!()
    }

    fn add_def(&self, sec: &str, key: &str, value: &str) -> Result<bool, Error> {
        unimplemented!()
    }

    fn load_section(&self, cfg: Config, sec: &str) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let text = fs::read_to_string(path)?;
        Model::from_string(&text)
    }

    pub fn from_string(text: &str) -> Result<Self, Error> {
        let mut model = Model { data: HashMap::new() };
        Ok(model)
    }

    pub fn print_model(&self) -> Result<(), Error> {
        unimplemented!()
    }
}
