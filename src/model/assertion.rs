
use crate::rbac::role_manager::RoleManager;

pub struct Assertion {
    pub key: String,
    pub value: String,
    pub tokens: Vec<String>,
    pub policy: Vec<Vec<String>>,
    //pub rm: RoleManager,
}

impl Assertion {
    pub fn new() -> Self {
        Assertion {
            key: "".to_string(),
            value: "".to_string(),
            tokens: Vec::new(),
            policy: Vec::new(),
        }
    }
}
