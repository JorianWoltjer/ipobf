use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    net::{IpAddr, Ipv4Addr},
};

use clap::Parser;
use dns_lookup::lookup_host;
use ipobf::{
    cli::Cli, dns_public, dns_rbndr, dns_redirect, gen_permutations_v4, gen_permutations_v6,
};

fn parse_host_to_ip(host: &str) -> Result<Ipv4Addr, String> {
    // Try to parse as a raw IP address
    host.parse::<Ipv4Addr>().or_else(|_| match host {
        // Special cases
        "cloud" | "meta" | "metadata" => Ok(Ipv4Addr::new(169, 254, 169, 254)),
        // Try to resolve as a hostname (DNS)
        _ => lookup_host(host)
            .map_err(|e| e.to_string())
            .and_then(|ips| {
                // Find the first IPv4 address
                ips.iter()
                    .find_map(|ip| {
                        if let IpAddr::V4(ip) = *ip {
                            Some(Ok(ip))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(Err("No IPv4 address found".to_string()))
            }),
    })
}

fn main() {
    let args = Cli::parse();

    let mut file = args.output.map(|path| {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(!args.output_append)
            .append(args.output_append)
            .open(path)
            .unwrap();
        BufWriter::new(file)
    });

    let ip = parse_host_to_ip(&args.host).unwrap();

    let mut permutations = gen_permutations_v4(&ip, args.padding);
    if !args.no_aliases {
        if ip.is_loopback() {
            for alias in ["0.0.0.0", "127.13.37.255"] {
                let alias = alias.parse().unwrap();
                permutations.extend_from_slice(&gen_permutations_v4(&alias, args.padding));
            }
        } else if ip == Ipv4Addr::new(169, 254, 169, 254) {
            let alias = "fd00:ec2::254".parse().unwrap();
            permutations.extend_from_slice(&gen_permutations_v6(&alias));
        }
    }
    permutations.extend_from_slice(&gen_permutations_v6(&ip.to_ipv6_compatible()));
    permutations.extend_from_slice(&gen_permutations_v6(&ip.to_ipv6_mapped()));

    permutations.push(dns_public(&ip));
    permutations.push(dns_rbndr(&ip, &"1.1.1.1".parse().unwrap()));
    permutations.push(dns_rbndr(&"1.1.1.1".parse().unwrap(), &ip));
    permutations.push(dns_redirect(&ip));

    for mut permutation in permutations {
        if args.brackets && permutation.contains(":") {
            permutation = format!("[{permutation}]");
        }
        if let Some(ref mut file) = file {
            writeln!(file, "{permutation}").unwrap();
        } else {
            println!("{permutation}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_to_ip() {
        for (host, ip) in [
            ("127.0.0.1", Ipv4Addr::new(127, 0, 0, 1)),
            ("localhost", Ipv4Addr::new(127, 0, 0, 1)),
            ("cloud", Ipv4Addr::new(169, 254, 169, 254)),
            ("meta", Ipv4Addr::new(169, 254, 169, 254)),
            ("metadata", Ipv4Addr::new(169, 254, 169, 254)),
        ] {
            assert_eq!(parse_host_to_ip(host).unwrap(), ip);
        }
        assert!(parse_host_to_ip("invalid.tld").is_err());
        assert!(parse_host_to_ip("ipv6.google.com").is_err());
        assert!([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)]
            .contains(&parse_host_to_ip("one.one.one.one").unwrap()));
    }
}
