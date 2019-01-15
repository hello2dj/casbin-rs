
use crate::effect::Effect;

pub trait Effector {
    fn merge_effects(&self, expr: &str, effects: Vec<Effect>, results: Vec<f64>) -> bool;
}
