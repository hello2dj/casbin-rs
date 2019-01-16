
use std::fs;
use std::path::Path;
use std::collections::HashMap;

use crate::error::Error;
use crate::config::config::Config;

pub struct Model {
    pub data: HashMap<String, String>,
}

impl Model {

    fn load_assertion(&self, cfg: Config, sec: &str, key: &str) -> Result<bool, Error> {
        Err(Error::NotImplemented)
    }

    fn add_def(&self, sec: &str, key: &str, value: &str) -> Result<bool, Error> {
        Err(Error::NotImplemented)
    }

    fn load_section(&self, cfg: Config, sec: &str) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }

    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        if let Ok(text) = fs::read_to_string(path) {
            Model::new_from_string(&text)
        } else {
            Err(Error::FileRead)
        }
    }

    pub fn new_from_string(text: &str) -> Result<Self, Error> {
        let mut model = Model {
            data: HashMap::new()
        };
        Ok(model)
    }

    pub fn print_model(&self) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
}
