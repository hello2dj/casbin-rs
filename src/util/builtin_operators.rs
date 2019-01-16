use std::net::Ipv4Addr;

use iprange::IpRange;
use ipnet::Ipv4Net;
use regex::Regex;

/// Determines whether `key1` matches the pattern of `key2` (similar to RESTful path).
///
/// `key2` can contain a *. For example, "/foo/bar" matches "/foo/*"
fn key_match(key1: &str, key2: &str) -> bool {
    if let Some(i) = key2.find("*") {
        if key1.len() > i {
            key1[0..i] == key2[0..i]
        } else {
            key1 == &key2[0..i]
        }
        
    } else {
        key1 == key2
    }
}

fn regex_match(key1: &str, key2: &str) -> bool {
    let regex = Regex::new(key2).expect(&format!("invalid regex: {}", key2));
    regex.is_match(key1)
}

// TODO: ip_match supports only IPv4 addresses.
fn ip_match(ip1: &str, ip2: &str) -> bool {
    let ip1: Ipv4Addr = ip1.parse().expect(&format!("invalid ip address: {}", ip1));
    
    if let Ok(ip2) = ip2.parse() {
        let mut ip_range: IpRange<Ipv4Net> = IpRange::new();
        ip_range.add(ip2);
        return ip_range.contains(&ip1);
    }

    // We failed to parse `ip2` as a network, in this case we try to parse it as an IP address.
    let ip2: Ipv4Addr = ip2.parse().expect(&format!("invalid ip address or network: {}", ip2));
    ip1 == ip2   
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_match() {
        assert_eq!(key_match("/foo", "/foo"), true);
        assert_eq!(key_match("/foo", "/foo*"), true);
        assert_eq!(key_match("/foo", "/foo/*"), false);
        assert_eq!(key_match("/foo/bar", "/foo"), false);
        assert_eq!(key_match("/foo/bar", "/foo*"), true);
        assert_eq!(key_match("/foo/bar", "/foo/*"), true);
        assert_eq!(key_match("/foobar", "/foo"), false);
        assert_eq!(key_match("/foobar", "/foo*"), true);
        assert_eq!(key_match("/foobar", "/foo/*"), false);
    }

    #[test]
    fn test_regex_match() {
        assert_eq!(regex_match("/topic/create", "/topic/create"), true);
        assert_eq!(regex_match("/topic/create/123", "/topic/create"), true);
        assert_eq!(regex_match("/topic/delete", "/topic/create"), false);
        assert_eq!(regex_match("/topic/edit", "/topic/edit/[0-9]+"), false);
        assert_eq!(regex_match("/topic/edit/123", "/topic/edit/[0-9]+"), true);
        assert_eq!(regex_match("/topic/edit/abc", "/topic/edit/[0-9]+"), false);
        assert_eq!(regex_match("/foo/delete/123", "/topic/delete/[0-9]+"), false);
        assert_eq!(regex_match("/topic/delete/0", "/topic/delete/[0-9]+"), true);
        assert_eq!(regex_match("/topic/edit/123s", "/topic/delete/[0-9]+"), false);
    }

    #[test]
    fn test_ip_match() {
        assert_eq!(ip_match("192.168.2.123", "192.168.2.0/24"), true);
        assert_eq!(ip_match("192.168.2.123", "192.168.3.0/24"), false);
        assert_eq!(ip_match("192.168.2.123", "192.168.2.0/16"), true);
        assert_eq!(ip_match("192.168.2.123", "192.168.2.123"), true);
        assert_eq!(ip_match("192.168.2.123", "192.168.2.123/32"), true);
        assert_eq!(ip_match("10.0.0.11", "10.0.0.0/8"), true);
        assert_eq!(ip_match("11.0.0.123", "10.0.0.0/8"), false);
    }
}