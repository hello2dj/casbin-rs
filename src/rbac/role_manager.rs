
pub trait RoleManager {
    fn clear(&self);
    fn add_link(&self, name1: &str, name2: &str, domain: &str);
    fn delete_link(&self, name1: &str, name2: &str, domain: &str);
    fn has_link(&self, name1: &str, name2: &str, domain: &str);
    fn get_roles(&self, name: &str, domain: &str) -> Vec<String>;
    fn get_users(&self, name: &str) -> Vec<String>;
    fn print_roles();
}
