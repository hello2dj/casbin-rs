use std::fs;
use std::path::Path;
use std::error::Error;
use std::collections::HashMap;

use regex::Regex;

lazy_static! {
    static ref REGEX_CONFIG: Regex = Regex::new(r"^\s*(\w+)=(.*)$").unwrap();
}

pub struct Config {
    pub data: HashMap<String, HashMap<String, String>>,
}

impl Config {
    const DEFAULT_SECTION: &'static str = "default";

    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<Error>> {
        let contents = fs::read_to_string(path)?;
        Config::new_from_string(&contents)
    }

    pub fn new_from_string(contents: &str) -> Result<Self, Box<Error>> {
        let mut config = Config {
            data: HashMap::new()
        };
        config.parse(contents);
        Ok(config)
    }

    fn add_config(&mut self, section: &str, option: &str, value: &str) {
        if !self.data.contains_key(section) {
            self.data.insert(section.to_string(), HashMap::new());
        }
        self.data.get_mut(section).unwrap().insert(option.to_string(), value.to_string());
    }

    fn parse(&mut self, contents: &str) {
        let mut section = Self::DEFAULT_SECTION;
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            } else if line.starts_with('[') && line.ends_with(']') {
                section = line.get(1..line.len()-1).unwrap();
            } else {
                if REGEX_CONFIG.is_match(line) {
                    let captures = REGEX_CONFIG.captures(line).unwrap();
                    let option = &captures[1].trim();
                    let value = &captures[2].trim();
                    self.add_config(section, option, value);
                }
            }
        }
    }
}
