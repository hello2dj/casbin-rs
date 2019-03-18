pub mod builtin_operators;

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref REGEX_ESCAPE: Regex = Regex::new(r"(^|[\s|&><+\-*/\(\)|!,]+)([r|p])(\.)").unwrap();
}

pub fn escape_assertion(s: &str) -> String {
    let e = REGEX_ESCAPE.replace_all(s, "$1$2%").to_string();
    e.replace("%", "_")
}

pub fn remove_comments(s: &str) -> &str {
    if let Some(pos) = s.find('#') {
        &s[0..pos].trim()
    } else {
        s
    }
}

pub fn array_equals(a: &Vec<String>, b: &Vec<String>) -> bool{
    let a_size = a.len();

    if a_size != b.len(){
        return false;
    }

    for i in 0..a_size{
        if a[i] != b[i]{
            return false;
        }
    }

    return true;
}

pub fn array_2_d_equals(a: &Vec<Vec<String>>, b: &Vec<Vec<String>>) -> bool{
    let a_size = a.len();

    if a_size != b.len(){
        return false;
    }

    for i in 0..a_size{
        if !array_equals(&a[i], &b[i]){
            return false;
        }
    }

    return true;
}

pub fn set_equals(mut a: Vec<String>, mut b: Vec<String>) -> bool{
    let a_size = a.len();

    if a_size != b.len(){
        return false;
    }

    a.sort();
    b.sort();

    for i in 0..a_size{
        if a[i] != b[i]{
            return false;
        }
    }

    return true;
}

#[test]
fn test_escape_assertion() {
    assert_eq!(
        escape_assertion("r.attr.value == p.attr").as_str(),
        "r_attr.value == p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value || p.attr").as_str(),
        "r_attp.value || p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value &&p.attr").as_str(),
        "r_attp.value &&p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value >p.attr").as_str(),
        "r_attp.value >p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value <p.attr").as_str(),
        "r_attp.value <p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value +p.attr").as_str(),
        "r_attp.value +p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value -p.attr").as_str(),
        "r_attp.value -p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value *p.attr").as_str(),
        "r_attp.value *p_attr"
    );
    assert_eq!(
        escape_assertion("r.attp.value /p.attr").as_str(),
        "r_attp.value /p_attr"
    );
    assert_eq!(
        escape_assertion("!r.attp.value /p.attr").as_str(),
        "!r_attp.value /p_attr"
    );
    assert_eq!(
        escape_assertion("g(r.sub, p.sub) == p.attr").as_str(),
        "g(r_sub, p_sub) == p_attr"
    );
    assert_eq!(
        escape_assertion("g(r.sub,p.sub) == p.attr").as_str(),
        "g(r_sub,p_sub) == p_attr"
    );
    assert_eq!(
        escape_assertion("(r.attp.value || p.attr)p.u").as_str(),
        "(r_attp.value || p_attr)p_u"
    );
}

#[test]
fn test_remove_comments() {
    assert_eq!(remove_comments("r.act == p.act # comments"), "r.act == p.act");
    assert_eq!(remove_comments("r.act == p.act#comments"), "r.act == p.act");
    assert_eq!(remove_comments("r.act == p.act###"), "r.act == p.act");
    assert_eq!(remove_comments("### comments"), "");
    assert_eq!(remove_comments("r.act == p.act"), "r.act == p.act");
}

#[test]
fn test_array_equals(){
    assert_eq!(array_equals(&vec!["alice".to_owned(), "data1".to_owned(), "read".to_owned()], &vec!["alice".to_owned(), "data1".to_owned(), "read".to_owned()]), true);
    assert_eq!(array_equals(&vec!["alice".to_owned(), "data1".to_owned(), "read".to_owned()], &vec!["alice".to_owned(), "data2".to_owned(), "read".to_owned()]), false);
}

#[test]
fn test_array_2_d_equals(){
    let a = vec!["alice".to_owned(), "data1".to_owned(), "read".to_owned()];
    let b = vec!["alice".to_owned(), "data2".to_owned(), "read".to_owned()];

    assert_eq!(array_2_d_equals(&vec![a.to_owned(), a.to_owned(), a.to_owned()], &vec![a.to_owned(), a.to_owned(), a.to_owned()]), true);
    assert_eq!(array_2_d_equals(&vec![a.to_owned(), a.to_owned(), a.to_owned()], &vec![a.to_owned(), a.to_owned()]),false);
    assert_eq!(array_2_d_equals(&vec![a.to_owned(), b.to_owned()], &vec![b.to_owned(), a.to_owned()]),false);
}
