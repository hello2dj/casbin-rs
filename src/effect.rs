use crate::error::Error;

#[derive(Debug, PartialEq)]
pub enum Effect {
    Allow,
    Indeterminate,
    Deny,
}

pub trait Effector {
    fn merge_effects(&self, expr: &str, effects: Vec<Effect>, _results: Vec<f64>) -> Result<bool, Error>;
}

#[derive(Debug)]
pub struct DefaultEffector {}

impl DefaultEffector {
    /// Create an instance of DefaultEffector
    pub fn new() -> Self {
        DefaultEffector {}
    }
}

impl Effector for DefaultEffector {
    fn merge_effects(&self, expr: &str, effects: Vec<Effect>, _results: Vec<f64>) -> Result<bool, Error> {
        match expr {
            "some(where (p_eft == allow))" => {
                let mut result = false;
                for eft in effects {
                    if eft == Effect::Allow {
                        result = true;
                        break;
                    }
                }
                Ok(result)
            }
            "!some(where (p_eft == deny))" => {
                let mut result = true;
                for eft in effects {
                    if eft == Effect::Deny {
                        result = false;
                        break;
                    }
                }
                Ok(result)
            }
            "some(where (p_eft == allow)) && !some(where (p_eft == deny))" => {
                let mut result = false;
                for eft in effects {
                    match eft {
                        Effect::Allow => {
                            result = true;
                        }
                        Effect::Deny => {
                            result = false;
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(result)
            }
            "priority(p_eft) || deny" => {
                let mut result = false;
                for eft in effects {
                    if eft == Effect::Indeterminate {
                        match eft {
                            Effect::Allow => {
                                result = true;
                            }
                            _ => result = false,
                        }
                        break;
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnsupportedEffect),
        }
    }
}
