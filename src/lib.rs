use libc::{c_char, in_addr};
use std::{
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

/// Generate many obfuscated versions of an IPv4 address
pub fn gen_permutations_v4(ip: &Ipv4Addr, padding: usize) -> Vec<String> {
    let octets = ip.octets();
    let ips = [
        to_8bit(octets),
        to_16bit(octets),
        to_24bit(octets),
        to_32bit(octets),
    ];

    let mut permutations = Vec::new();
    // Go through all IP classes
    for ip in ips.iter() {
        // Go through all octet encoders
        for encoder in [str_decimal, str_hex_lower, str_hex_upper, str_octal] {
            for padding in [0, padding] {
                if encoder == str_decimal && padding != 0 {
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
/// TODO: write tests
pub fn gen_permutations_v6(ip: &Ipv6Addr) -> Vec<String> {
    let segments = ip.segments();
    let [a, b, c, d, e, f, g, h] = segments;
    // TODO: permute string. maybe regex replacements?
    // vec![
    //     // https://datatracker.ietf.org/doc/html/rfc4291#section-2.2
    //     format!("::ffff:{:x}:{:x}", a_and_b, c_and_d),
    //     format!("::FFFF:{:X}:{:X}", a_and_b, c_and_d),
    //     format!("0:0:00:000:0000:FFFF:{:X}:{:X}", a_and_b, c_and_d),
    //     format!("0:0:0:0:0:FFFF:{a}.{b}.{c}.{d}"),
    //     format!("::ffff:{a}.{b}.{c}.{d}"),
    //     format!("::{:x}:{:x}", a_and_b, c_and_d),
    //     format!("0:0:0:0:0:0:{a}.{b}.{c}.{d}"),
    //     format!("::{a}.{b}.{c}.{d}"),
    // ]
    vec![segments.map(|segment| format!("{:x}", segment)).join(":")]
}

/// Decode and encode IPv4 addresses to normalize it
pub fn inet_parse(ip: &str) -> Result<String, ()> {
    let mut inp = unsafe { std::mem::zeroed() };
    let c_ip = CString::new(ip).map_err(|_| ())?;
    if unsafe { inet_aton(c_ip.as_ptr(), &mut inp) } == 0 {
        return Err(());
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
    fn test_permutations() {
        for ip in ["127.0.0.1", "169.254.169.254", "0.0.0.0"] {
            let permutations = gen_permutations_v4(&ip.parse().unwrap(), 3);
            for permutation in permutations {
                dbg!(&permutation);
                if permutation.contains(":") {
                    assert_eq!(
                        ip.parse::<Ipv4Addr>().unwrap(),
                        permutation.parse::<Ipv6Addr>().unwrap().to_ipv4().unwrap()
                    );
                } else {
                    assert_eq!(ip, inet_parse(&permutation).unwrap());
                }
            }
        }
    }
}
