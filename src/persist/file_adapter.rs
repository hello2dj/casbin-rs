use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::model::Model;
use crate::persist::Adapter;

pub struct FileAdapter {
    path: PathBuf,
}

impl FileAdapter {
    /// Create a FileAdapter instance.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        FileAdapter {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl Adapter for FileAdapter {
    /// Load all policy rules from the storage.
    fn load_policy(&self, model: &mut Model) -> Result<(), Error> {
        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        for line in contents.lines() {
            model.load_policy_line(line)?;
        }

        Ok(())
    }

    fn save_policy(&self, model: &mut Model) -> Result<(), Error> {
        unimplemented!()
    }

    fn add_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<(), Error> {
        unimplemented!()
    }

    fn remove_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<(), Error> {
        unimplemented!()
    }

    fn remove_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: i32,
        field_values: Vec<String>,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_policy() {
        let mut model = Model::new("examples/basic_model.conf").expect("failed to load model");
        let adapter = FileAdapter::new("examples/basic_policy.csv");
        adapter.load_policy(&mut model).expect("failed to load policy");
    }
}
