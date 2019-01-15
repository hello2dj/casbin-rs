
pub struct Model {
    pub value: String,
}

impl Model {
    pub fn new() -> Self {
        Model {
            value: "".to_string(),
        }
    }
}
