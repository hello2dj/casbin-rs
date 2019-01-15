use std::fs;
use std::path::Path;
use std::error::Error;

pub struct Config {
    pub dummy: String,
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<Error>> {
        let contents = fs::read_to_string(path)?;
        Config::new_from_string(&contents)
    }

    pub fn new_from_string(_contents: &str) -> Result<Self, Box<Error>> {
        let config = Config {
            dummy: "".to_string(),
        };
        Ok(config)
    }
}
