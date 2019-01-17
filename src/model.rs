
use std::fs;
use std::path::Path;
use std::collections::HashMap;

use lazy_static::lazy_static;
use regex::Regex;

use crate::error::Error;
use crate::config::Config;
use crate::assertion::Assertion;
use crate::util::{escape_assertion, remove_comments};

mod function;

pub use crate::model::function::{FunctionMap, get_function_map};

pub struct Model {
    pub data: HashMap<String, String>,
}

lazy_static! {
    static ref SECTION_NAME_MAP: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        map.insert("r", "request_definition");
        map.insert("p", "policy_definition");
        map.insert("g", "role_definition");
        map.insert("e", "policy_effect");
        map.insert("m", "matchers");
        map
    };
}

fn get_section_name(name: &str) -> &str {
    SECTION_NAME_MAP.get(name).unwrap()
}

fn get_section_value(sec: &str, i: i32) -> String {
    if i == 1 {
        sec.to_string()
    } else {
        format!("{}{}", sec, i)
    }
}

impl Model {
    fn load_assertion(&mut self, cfg: &Config, sec: &str, key: &str) -> Result<bool, Error> {
        let value = format!("{}::{}", get_section_name(sec), key);
        self.add_def(sec, key, value.as_str())
    }

    fn add_def(&mut self, sec: &str, key: &str, value: &str) -> Result<bool, Error> {
        let mut assertion = Assertion::new();

        if assertion.value.is_empty() {
            return Ok(false);
        }

        if sec == "r" || sec == "p" {
            assertion.tokens = assertion.value.split(", ").map(|v|
                format!("{}_{}", key, v)
            ).collect();
        } else {

        }

        Ok(true)
    }

    fn load_section(&mut self, cfg: &Config, sec: &str) -> Result<(), Error> {
        let mut i = 1;
        while self.load_assertion(cfg, sec, get_section_value(sec, i).as_str()).unwrap() {
            i = i + 1;
        }
        Ok(())
    }

    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let text = fs::read_to_string(path)?;
        Model::from_string(&text)
    }

    pub fn from_string(text: &str) -> Result<Self, Error> {
        let mut model = Model { data: HashMap::new() };
        let cfg = Config::from_string(text)?;

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;

        model.load_section(&cfg, "g")?;
        Ok(model)
    }

    pub fn print_model(&self) -> Result<(), Error> {
        unimplemented!()
    }
}
