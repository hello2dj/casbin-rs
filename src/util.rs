
pub mod builtin_operators;

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref REGEX_ESCAPE: Regex = Regex::new(r"(\.)").unwrap();
}

pub fn escape_assertion(s: &str) -> String {
    REGEX_ESCAPE.replace(s, "_").to_string()
}

pub fn remove_comments(s: &str) -> &str {
    if let Some(pos) = s.find("#") {
        return &s[0..pos].trim();
    } else {
        return s;
    }
}

#[test]
fn test_escape_assertion() {
    /*
    assert_eq!(escape_assertion("r.attr.value == p.attr").as_str(), "r_attr.value == p_attr");
    assert_eq!(escape_assertion("r.attp.value || p.attr").as_str(), "r_attp.value || p_attr");
    assert_eq!(escape_assertion("r.attp.value &&p.attr").as_str(), "r_attp.value &&p_attr");
    assert_eq!(escape_assertion("r.attp.value >p.attr").as_str(), "r_attp.value >p_attr");
    assert_eq!(escape_assertion("r.attp.value <p.attr").as_str(), "r_attp.value <p_attr");
    assert_eq!(escape_assertion("r.attp.value +p.attr").as_str(), "r_attp.value +p_attr");
    assert_eq!(escape_assertion("r.attp.value -p.attr").as_str(), "r_attp.value -p_attr");
    assert_eq!(escape_assertion("r.attp.value *p.attr").as_str(), "r_attp.value *p_attr");
    assert_eq!(escape_assertion("r.attp.value /p.attr").as_str(), "r_attp.value /p_attr");
    assert_eq!(escape_assertion("!r.attp.value /p.attr").as_str(), "!r_attp.value /p_attr");
    assert_eq!(escape_assertion("g(r.sub, p.sub) == p.attr").as_str(), "g(r_sub, p_sub) == p_attr");
    assert_eq!(escape_assertion("g(r.sub,p.sub) == p.attr").as_str(), "g(r_sub,p_sub) == p_attr");
    assert_eq!(escape_assertion("(r.attp.value || p.attr)p.u").as_str(), "(r_attp.value || p_attr)p_u");
    */
}

#[test]
fn test_remove_comments() {
    assert_eq!(remove_comments("r.act == p.act # comments"), "r.act == p.act");
    assert_eq!(remove_comments("r.act == p.act#comments"), "r.act == p.act");
    assert_eq!(remove_comments("r.act == p.act###"), "r.act == p.act");
    assert_eq!(remove_comments("### comments"), "");
    assert_eq!(remove_comments("r.act == p.act"), "r.act == p.act");
}
