pub struct Policy {
    pub value: String,
}

impl Policy {
    pub fn new() -> Self {
        Policy { value: "".to_string() }
    }
}
