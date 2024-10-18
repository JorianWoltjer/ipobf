use libc::{c_char, in_addr};
use std::{
    error::Error,
    ffi::{CStr, CString},
    net::{Ipv4Addr, Ipv6Addr},
};

pub mod cli;

extern "C" {
    fn inet_aton(cp: *const c_char, inp: *mut in_addr) -> libc::c_int;
    fn inet_ntoa(in_: in_addr) -> *const c_char;
}

// `man inet_aton`
pub fn to_8bit(octets: [u8; 4]) -> Vec<u32> {
    octets.into_iter().map(Into::into).collect()
}
pub fn to_16bit([a, b, c, d]: [u8; 4]) -> Vec<u32> {
    let c_and_d = u16::from_be_bytes([c, d]);
    vec![a.into(), b.into(), c_and_d.into()]
}
pub fn to_24bit([a, b, c, d]: [u8; 4]) -> Vec<u32> {
    let b_and_c_and_d = u32::from_be_bytes([0, b, c, d]);
    vec![a.into(), b_and_c_and_d]
}
pub fn to_32bit(octets: [u8; 4]) -> Vec<u32> {
    vec![u32::from_be_bytes(octets)]
}

pub fn str_decimal(octet: u32, _padding: usize) -> String {
    octet.to_string()
}
pub fn str_hex_lower(octet: u32, padding: usize) -> String {
    format!("0x{}{:x}", "0".repeat(padding), octet)
}
pub fn str_hex_upper(octet: u32, padding: usize) -> String {
    format!("0X{}{:X}", "0".repeat(padding), octet)
}
pub fn str_octal(octet: u32, padding: usize) -> String {
    format!("0{}{:o}", "0".repeat(padding), octet)
}

/// Compress an IPv6 address (without special IPv4 formating)
pub fn compress_ipv6(ip: &Ipv6Addr) -> String {
    if let Some(ipv4) = ip.to_ipv4() {
        // IPv4-mapped addresses are displayed as ::ffff:1.2.3.4, this code avoids that
        let [_, _, _, _, _, _, g, h] = ip.segments();
        let mut compressed = ip.to_string();
        compressed = compressed.replace(&ipv4.to_string(), &format!("{:x}:{:x}", g, h));
        compressed
    } else {
        ip.to_string()
    }
}

/// Generate a public DNS name for an IP address
pub fn dns_public(ip: &Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{:02x}{:02x}{:02x}{:02x}.nip.io", a, b, c, d)
}

/// Randomly resolve between two IP addresses
pub fn dns_rbndr(ip1: &Ipv4Addr, ip2: &Ipv4Addr) -> String {
    let [a1, b1, c1, d1] = ip1.octets();
    let [a2, b2, c2, d2] = ip2.octets();
    format!(
        "{:02x}{:02x}{:02x}{:02x}.{:02x}{:02x}{:02x}{:02x}.rbndr.us",
        a1, b1, c1, d1, a2, b2, c2, d2
    )
}

/// HTTP Redirect to an IP address
pub fn dns_redirect(ip: &Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{a}-{b}-{c}-{d}.redir.jtw.sh")
}

/// Generate many obfuscated versions of an IPv4 address
pub fn gen_permutations_v4(ip: &Ipv4Addr, req_padding: usize) -> Vec<String> {
    let octets = ip.octets();
    let ips = [
        to_8bit(octets),
        to_16bit(octets),
        to_24bit(octets),
        to_32bit(octets),
    ];

    let encoders = [str_decimal, str_hex_lower, str_hex_upper, str_octal];
    let mut paddings = vec![0];
    if req_padding > 0 {
        paddings.push(req_padding);
    }

    let mut permutations = Vec::new();
    // Go through all IP classes
    for ip in ips.iter() {
        // Go through all octet encoders
        for (i, encoder) in encoders.iter().enumerate() {
            for &padding in &paddings {
                if i == 0 && padding != 0 {
                    continue; // Decimal numbers can't be padded, they would be recognized as octal
                }

                let encoded: Vec<String> =
                    ip.iter().map(|&octet| encoder(octet, padding)).collect();
                permutations.push(encoded.join("."));
            }
        }
    }
    permutations
}

/// Generate many obfuscated versions of an IPv6 address
pub fn gen_permutations_v6(ip: &Ipv6Addr) -> Vec<String> {
    let segments = ip.segments();
    let mut permutations = Vec::new();
    let compressed = compress_ipv6(ip);
    // Compressed versions
    permutations.push(compressed.clone());
    permutations.push(compressed.to_uppercase());
    // Uncompressed version
    permutations.push(segments.map(|segment| format!("{:x}", segment)).join(":"));
    // IPv4 mapped and compatible
    if let Some(ipv4) = ip.to_ipv4() {
        // segments[5] may be 0000 or ffff
        if segments[5] == 0 {
            permutations.push(format!("::{}", ipv4));
        } else {
            permutations.push(format!("::ffff:{}", ipv4));
        }
        permutations.push(format!("0:0:00:000:0000:{:x}:{}", segments[5], ipv4));
    }

    permutations
}

/// Decode and encode IPv4 addresses to normalize it
pub fn inet_parse(ip: &str) -> Result<String, Box<dyn Error>> {
    let mut inp = unsafe { std::mem::zeroed() };
    let c_ip = CString::new(ip)?;
    if unsafe { inet_aton(c_ip.as_ptr(), &mut inp) } == 0 {
        return Err("Invalid IP address".into());
    }
    let c_str = unsafe { inet_ntoa(inp) };
    let c_str = unsafe { CStr::from_ptr(c_str) };
    Ok(c_str.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inet_parse() {
        assert_eq!(inet_parse("127.0.0.1").unwrap(), "127.0.0.1");
        assert_eq!(inet_parse("127.1").unwrap(), "127.0.0.1");
        assert_eq!(inet_parse("127.0x1").unwrap(), "127.0.0.1");
        assert_eq!(inet_parse("2130706433").unwrap(), "127.0.0.1");
    }

    #[test]
    fn test_dns() {
        assert_eq!(
            dns_rbndr(
                &"127.0.0.1".parse().unwrap(),
                &"192.168.0.1".parse().unwrap()
            ),
            "7f000001.c0a80001.rbndr.us"
        );
        assert_eq!(dns_public(&"10.0.8.3".parse().unwrap()), "0a000803.nip.io");
        assert_eq!(
            dns_redirect(&"169.254.169.254".parse().unwrap()),
            "169-254-169-254.redir.jtw.sh"
        );
    }

    #[test]
    fn test_permutations_v4() {
        for ip in ["127.0.0.1", "169.254.169.254", "0.0.0.0"] {
            let permutations = gen_permutations_v4(&ip.parse().unwrap(), 3);
            for permutation in permutations {
                assert_eq!(ip, inet_parse(&permutation).unwrap());
            }
        }
    }

    #[test]
    fn test_permutations_v6() {
        for ip in ["127.0.0.1", "169.254.169.254", "0.0.0.0"] {
            let ip = ip.parse::<Ipv4Addr>().unwrap();
            let mut permutations = gen_permutations_v6(&ip.to_ipv6_compatible());
            permutations.extend_from_slice(&gen_permutations_v6(&ip.to_ipv6_mapped()));
            for permutation in permutations {
                assert_eq!(
                    ip,
                    permutation.parse::<Ipv6Addr>().unwrap().to_ipv4().unwrap()
                );
            }
        }

        let ip = "fd00:ec2::254".parse().unwrap();
        let permutations = gen_permutations_v6(&ip);
        for permutation in permutations {
            assert_eq!(ip, permutation.parse::<Ipv6Addr>().unwrap());
        }
    }
}
