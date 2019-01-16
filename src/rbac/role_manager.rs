use crate::error::Error;

pub trait RoleManager {
    fn clear(&mut self) -> Result<(), Error>;
    fn add_link(&mut self, name1: &str, name2: &str, domain: &str) -> Result<(), Error>;
    fn delete_link(&mut self, name1: &str, name2: &str, domain: &str) -> Result<(), Error>;
    fn has_link(&self, name1: &str, name2: &str, domain: &str) -> Result<bool, Error>;
    fn get_roles(&self, name: &str, domain: &str) -> Result<Vec<String>, Error>;
    fn get_users(&self, name: &str) -> Result<Vec<String>, Error>;
    fn print_roles() -> Result<(), Error>;
}
