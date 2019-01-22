use std::collections::HashMap;
use std::fs;
use std::path::Path;

use lazy_static::lazy_static;

use crate::assertion::Assertion;
use crate::config::Config;
use crate::error::Error;
use crate::rbac::RoleManager;
use crate::util::{escape_assertion, remove_comments};

mod function;

pub use crate::model::function::{get_function_map, FunctionMap};

type AssertionMap = HashMap<String, Assertion>;

#[derive(Debug)]
pub struct Model {
    pub data: HashMap<String, AssertionMap>,
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
    /// Create an empty Model instance.
    pub fn new() -> Self {
        Model { data: HashMap::new() }
    }

    /// Create a Model instance from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let text = fs::read_to_string(path)?;
        Model::from_string(&text)
    }

    /// Create a Model instance from a string.
    pub fn from_string(text: &str) -> Result<Self, Error> {
        let mut model = Model::new();
        let cfg = Config::from_string(text)?;

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;
        model.load_section(&cfg, "g")?;

        Ok(model)
    }

    fn load_assertion(&mut self, cfg: &Config, sec: &str, key: &str) -> Result<bool, Error> {
        if let Some(value) = cfg.string(key, Some(sec)) {
            self.add_def(sec, key, value.as_str())
        } else {
            Ok(false)
        }
    }

    pub(crate) fn add_def(&mut self, sec: &str, key: &str, value: &str) -> Result<bool, Error> {
        let mut assertion = Assertion::new();

        if value == "" {
            return Ok(false);
        }

        assertion.key = key.to_string();
        assertion.value = value.to_string();

        if sec == "r" || sec == "p" {
            assertion.tokens = assertion.value.split(", ").map(|v| format!("{}_{}", key, v)).collect();
        } else {
            assertion.value = escape_assertion(remove_comments(assertion.value.as_str())).to_string();
        }

        if !self.data.contains_key(sec) {
            let sec_map: HashMap<String, Assertion> = HashMap::new();
            self.data.insert(sec.to_string(), sec_map);
        }

        let sec_map = self.data.get_mut(sec).unwrap();
        sec_map.insert(key.to_string(), assertion);

        Ok(true)
    }

    fn load_section(&mut self, cfg: &Config, sec: &str) -> Result<(), Error> {
        let mut i = 1;
        while self
            .load_assertion(cfg, sec, get_section_value(sec, i).as_str())
            .unwrap()
        {
            i = i + 1;
        }
        Ok(())
    }

    pub fn print_model(&self) -> Result<(), Error> {
        unimplemented!()
    }

    /// Load a policy rule from a line of text.
    pub fn load_policy_line(&mut self, line: &str) -> Result<(), Error> {
        if line.len() == 0 || line.starts_with("#") {
            return Ok(());
        }

        let tokens: Vec<&str> = line.split(',').map(|t| t.trim()).collect();

        if tokens.len() < 2 {
            return Err(Error::InvalidValue);
        }

        let key = tokens[0];
        let section = &key[0..1];

        if !self.data.contains_key(section) {
            self.data.insert(String::from(section), AssertionMap::new());
        }

        let assertion_map = self.data.get_mut(section).unwrap();

        if !assertion_map.contains_key(key) {
            assertion_map.insert(key.to_string(), Assertion::new());
        }

        let assertion = assertion_map.get_mut(key).unwrap();
        let mut value = vec![];

        for s in &tokens[1..] {
            value.push(String::from(*s));
        }

        assertion.policy.push(value);

        Ok(())
    }
}
