// Note: multi-line values are not currently supported.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use lazy_static::lazy_static;
use regex::Regex;

use crate::error::Error;

const DEFAULT_SECTION: &'static str = "default";

lazy_static! {
    static ref REGEX_CONFIG: Regex = Regex::new(r"^\s*([\w\.]+)\s*=\s*(.+)\s*$").unwrap();
}

/// A configuration.
pub struct Config {
    data: HashMap<String, HashMap<String, String>>,
}

impl Config {
    /// Load a configuration file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let contents = fs::read_to_string(path)?;
        let config = Config::from_string(&contents)?;
        Ok(config)
    }

    /// Parse a configuration from a string.
    pub fn from_string(contents: &str) -> Result<Self, Error> {
        let mut config = Config { data: HashMap::new() };
        config.parse(contents)?;
        Ok(config)
    }

    /// Set the `value` for `key` in the configuration.
    pub fn set(&mut self, key: &str, value: &str, section: Option<&str>) {
        let section = section.unwrap_or(DEFAULT_SECTION);

        if !self.data.contains_key(section) {
            self.data.insert(section.to_string(), HashMap::new());
        }
        self.data
            .get_mut(section)
            .expect("data should always contain `section`")
            .insert(key.to_string(), value.to_string());
    }

    fn parse(&mut self, contents: &str) -> Result<(), Error> {
        let mut section = DEFAULT_SECTION;
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            } else if line.starts_with('[') && line.ends_with(']') {
                section = line.get(1..line.len() - 1).ok_or(Error::ParsingFailure)?;
            } else {
                if REGEX_CONFIG.is_match(line) {
                    let captures = REGEX_CONFIG.captures(line).ok_or(Error::ParsingFailure)?;
                    let key = &captures[1].trim();
                    let value = &captures[2].trim();
                    self.set(key, value, Some(section));
                }
            }
        }
        Ok(())
    }

    fn get(&self, key: &str, section: Option<&str>) -> Option<&str> {
        let section_name = section.unwrap_or(DEFAULT_SECTION);

        let section = self.data.get(section_name)?;
        let value = section.get(key)?;
        Some(value.as_str())
    }

    /// Get the value using the provided key and convert the value to a string.
    pub fn string(&self, key: &str, section: Option<&str>) -> Option<String> {
        let value = self.get(key, section)?;
        Some(value.to_string())
    }

    /// Get the value using the provided key and convert the value to an array of string
    /// by splitting the string by comma.
    pub fn strings(&self, key: &str, section: Option<&str>) -> Option<Vec<String>> {
        let value = self.get(key, section)?;
        Some(value.split(',').map(|v| v.to_string()).collect())
    }

    /// Get the value using the provided key and convert the value to a bool.
    pub fn bool(&self, key: &str, section: Option<&str>) -> Result<bool, Error> {
        let value = self.get(key, section).ok_or(Error::MissingKey)?;

        match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(Error::InvalidValue),
        }
    }

    /// Get the value using the provided key and convert the value to an i64.
    pub fn int64(&self, key: &str, section: Option<&str>) -> Result<i64, Error> {
        let value = self.get(key, section).ok_or(Error::MissingKey)?;
        value.parse().map_err(|_| Error::InvalidValue)
    }

    /// Get the value using the provided key and convert the value to a f64.
    pub fn float64(&self, key: &str, section: Option<&str>) -> Result<f64, Error> {
        let value = self.get(key, section).ok_or(Error::MissingKey)?;
        value.parse().map_err(|_| Error::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let mut config = Config::new("test_data/testini.ini").expect("failed to open test file");

        // default section
        assert_eq!(config.bool("debug", None).unwrap(), true);
        assert_eq!(config.string("url", None).unwrap(), "act.wiki");

        // redis and mysql section
        assert_eq!(config.strings("redis.key", Some("redis")).unwrap(), ["push1", "push2"]);
        assert_eq!(config.string("mysql.dev.host", Some("mysql")).unwrap(), "127.0.0.1");
        assert_eq!(config.string("mysql.master.host", Some("mysql")).unwrap(), "10.0.0.1");

        // math section
        assert_eq!(config.int64("math.i64", Some("math")).unwrap(), 64);
        assert_eq!(config.float64("math.f64", Some("math")).unwrap(), 64.1);

        // other section
        assert_eq!(
            config.string("name", Some("other")).unwrap(),
            "ATC自动化测试^-^&($#……#"
        );
        assert_eq!(config.string("key1", Some("other")).unwrap(), "test key");

        config.set("key1", "new test key", Some("other"));
        assert_eq!(config.string("key1", Some("other")).unwrap(), "new test key");
    }
}
