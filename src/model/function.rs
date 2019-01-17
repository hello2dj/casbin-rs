use std::collections::HashMap;

use crate::util::builtin_operators;

pub type Function = Fn(&str, &str) -> bool;

pub type FunctionMap = HashMap<&'static str, Box<Function>>;

pub fn get_function_map() -> FunctionMap {
    let mut map = FunctionMap::new();

    map.insert("keyMatch", Box::new(builtin_operators::key_match));
    map.insert("keyMatch2", Box::new(builtin_operators::key_match2));
    map.insert("regexMatch", Box::new(builtin_operators::regex_match));
    map.insert("ipMatch", Box::new(builtin_operators::ip_match));

    map
}