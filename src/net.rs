//! Addresses and host names: who is asking, and under which name.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address or a network such as `10.0.0.0/8` (GRIZZLE_TRUSTED_PROXIES).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    address: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// `1.2.3.4`, `10.0.0.0/8`, `fd00::/8`. Host bits may be set (`10.1.2.3/8` means `10.0.0.0/8`).
    ///
    /// Also what Python's `ipaddress` took and a configuration written for the earlier versions
    /// may therefore hold: an IPv4 network with its mask spelled out (`10.0.0.0/255.0.0.0`, or
    /// the inverse `10.0.0.0/0.255.255.255`), and an IPv6 address with a zone (`fe80::1%eth0`;
    /// the zone plays no part in matching).
    pub fn parse(text: &str) -> Result<IpNet, String> {
        let unusable = || format!("{text:?} does not appear to be an IPv4 or IPv6 network");
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = match address.split_once('%') {
            Some((address, zone)) if !zone.is_empty() => address.parse::<Ipv6Addr>().map(IpAddr::V6).map_err(|_| unusable())?,
            _ => address.parse().map_err(|_| unusable())?,
        };
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => bits,
            Some(prefix) if prefix.bytes().all(|b| b.is_ascii_digit()) => {
                prefix.parse::<u8>().ok().filter(|p| *p <= bits).ok_or_else(unusable)?
            }
            Some(mask) if address.is_ipv4() => {
                let mask = u32::from(mask.parse::<Ipv4Addr>().map_err(|_| unusable())?);
                if mask.leading_ones() + mask.trailing_zeros() == 32 {
                    mask.leading_ones() as u8 // 255.255.0.0
                } else if mask.leading_zeros() + mask.trailing_ones() == 32 {
                    mask.leading_zeros() as u8 // 0.0.255.255
                } else {
                    return Err(unusable());
                }
            }
            Some(_) => return Err(unusable()),
        };
        Ok(IpNet { address, prefix })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => same_prefix(&net.octets(), &addr.octets(), self.prefix),
            (IpAddr::V6(net), IpAddr::V6(addr)) => same_prefix(&net.octets(), &addr.octets(), self.prefix),
            _ => false,
        }
    }
}

fn same_prefix(a: &[u8], b: &[u8], bits: u8) -> bool {
    let whole = usize::from(bits / 8);
    let rest = bits % 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    rest == 0 || (a[whole] ^ b[whole]) >> (8 - rest) == 0
}

/// An IP address from `1.2.3.4`, `1.2.3.4:5678`, `[::1]:5678` or `::1`; `None` for anything else.
pub fn address(text: &str) -> Option<IpAddr> {
    let mut text = text.trim();
    if let Some(rest) = text.strip_prefix('[') {
        text = rest.split(']').next().unwrap_or("");
    } else if text.matches(':').count() == 1 {
        text = text.split(':').next().unwrap_or("");
    }
    text.split('%').next()?.parse().ok()
}

fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> IpNet {
    IpNet { address: IpAddr::V4(Ipv4Addr::new(a, b, c, d)), prefix }
}

fn v6(text: &str, prefix: u8) -> IpNet {
    IpNet { address: IpAddr::V6(text.parse::<Ipv6Addr>().expect("a literal address")), prefix }
}

/// Is this an address anyone on the Internet could have? (The IANA special-purpose registries say no
/// for loopback, link-local, the private ranges, documentation ranges and the like.)
pub fn is_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => {
            let special = [
                v4(0, 0, 0, 0, 8),
                v4(10, 0, 0, 0, 8),
                v4(100, 64, 0, 0, 10),
                v4(127, 0, 0, 0, 8),
                v4(169, 254, 0, 0, 16),
                v4(172, 16, 0, 0, 12),
                v4(192, 0, 0, 0, 24),
                v4(192, 0, 0, 170, 31),
                v4(192, 0, 2, 0, 24),
                v4(192, 168, 0, 0, 16),
                v4(198, 18, 0, 0, 15),
                v4(198, 51, 100, 0, 24),
                v4(203, 0, 113, 0, 24),
                v4(240, 0, 0, 0, 4),
                v4(255, 255, 255, 255, 32),
            ];
            let exceptions = [v4(192, 0, 0, 9, 32), v4(192, 0, 0, 10, 32)];
            exceptions.iter().any(|net| net.contains(address)) || !special.iter().any(|net| net.contains(address))
        }
        IpAddr::V6(six) => {
            if let Some(mapped) = six.to_ipv4_mapped() {
                return is_global(IpAddr::V4(mapped));
            }
            let special = [
                v6("::1", 128),
                v6("::", 128),
                v6("::ffff:0:0", 96),
                v6("64:ff9b:1::", 48),
                v6("100::", 64),
                v6("2001::", 23),
                v6("2001:db8::", 32),
                v6("2002::", 16),
                v6("3fff::", 20),
                v6("fc00::", 7),
                v6("fe80::", 10),
            ];
            let exceptions = [
                v6("2001:1::1", 128),
                v6("2001:1::2", 128),
                v6("2001:3::", 32),
                v6("2001:4:112::", 48),
                v6("2001:20::", 28),
                v6("2001:30::", 28),
            ];
            exceptions.iter().any(|net| net.contains(address)) || !special.iter().any(|net| net.contains(address))
        }
    }
}

/// The parts of a URL this server looks at.
#[derive(Debug, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    /// What follows `//` up to the next `/`, `?` or `#`: `user@host:port`.
    pub netloc: String,
    /// The host in lower case, without brackets, port or user. `None` when there is none.
    pub hostname: Option<String>,
}

/// Split a URL the way browsers' `Origin` values and pasted addresses need: scheme, authority, host.
/// `None` for an authority that cannot be one (unbalanced brackets).
pub fn split_url(url: &str) -> Option<UrlParts> {
    let url = url.trim_matches(|c: char| c <= ' ');
    let url: String = url.chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut rest = url.as_str();
    let mut scheme = String::new();
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        let valid = candidate.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && candidate.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if valid {
            scheme = candidate.to_ascii_lowercase();
            rest = &rest[colon + 1..];
        }
    }
    let mut netloc = "";
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = &after[..end];
        if netloc.contains('[') != netloc.contains(']') {
            return None;
        }
    }
    let host_port = netloc.rsplit('@').next().unwrap_or("");
    let hostname = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    Some(UrlParts {
        scheme,
        netloc: netloc.to_string(),
        hostname: (!hostname.is_empty()).then(|| hostname.to_lowercase()),
    })
}

/// Where a client on this machine finds the plain listener, given the address it is bound to.
pub fn upstream_host(listen_host: &str) -> String {
    match listen_host {
        "" | "0.0.0.0" => "127.0.0.1".to_string(),
        "::" => "::1".to_string(), // "::" may be IPv6 only, and then 127.0.0.1 would reach nothing
        specific => specific.to_string(), // a specific address: the listener is there and nowhere else
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_contain_their_addresses() {
        let net = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.200.3.4".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        assert!(!net.contains("::1".parse().unwrap()));
        assert_eq!(IpNet::parse("10.1.2.3/8").unwrap().prefix, 8);
        assert!(IpNet::parse("172.18.0.2").unwrap().contains("172.18.0.2".parse().unwrap()));
        assert!(!IpNet::parse("172.18.0.2").unwrap().contains("172.18.0.3".parse().unwrap()));
        assert!(IpNet::parse("fd00::/8").unwrap().contains("fd12::1".parse().unwrap()));
        assert!(IpNet::parse("172.16.0.0/12").unwrap().contains("172.31.255.255".parse().unwrap()));
        assert!(!IpNet::parse("172.16.0.0/12").unwrap().contains("172.32.0.0".parse().unwrap()));
        for bad in ["proxy", "10.0.0.0/33", "10.0.0.0/x", "", "10.0.0.0/+8"] {
            assert!(IpNet::parse(bad).is_err(), "{bad}");
        }
    }

    /// The spellings Python's `ipaddress` also read, which an existing configuration may use.
    #[test]
    fn networks_may_spell_out_their_mask_or_name_a_zone() {
        let prefix = |text: &str| IpNet::parse(text).map(|net| net.prefix);
        assert_eq!(prefix("10.0.0.0/255.0.0.0"), Ok(8));
        assert_eq!(prefix("172.18.0.0/255.255.0.0"), Ok(16));
        assert_eq!(prefix("10.0.0.0/0.255.255.255"), Ok(8));
        assert_eq!(prefix("192.168.1.7/255.255.255.255"), Ok(32));
        assert_eq!(prefix("10.0.0.0/08"), Ok(8));
        assert!(IpNet::parse("172.18.0.0/255.255.0.0").unwrap().contains("172.18.9.9".parse().unwrap()));
        assert!(IpNet::parse("fe80::1%eth0").unwrap().contains("fe80::1".parse().unwrap()));
        assert_eq!(prefix("fe80::%eth0/64"), Ok(64));
        for bad in ["10.0.0.0/255.0.255.0", "fd00::/ffff::", "10.0.0.0/ 8", "10.0.0.1%eth0", "fe80::1%", "10.0.0.0/255.0.0"] {
            assert!(IpNet::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn addresses_are_read_from_the_forms_headers_use() {
        assert_eq!(address("1.2.3.4"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(address(" 1.2.3.4:5678 "), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(address("[::1]:5678"), Some("::1".parse().unwrap()));
        assert_eq!(address("fe80::1%eth0"), Some("fe80::1".parse().unwrap()));
        assert_eq!(address("unknown"), None);
        assert_eq!(address(""), None);
    }

    #[test]
    fn global_addresses_are_told_from_local_ones() {
        for local in ["127.0.0.1", "10.1.2.3", "192.168.1.5", "172.20.0.1", "169.254.1.1", "100.64.0.1", "::1"] {
            assert!(!is_global(local.parse().unwrap()), "{local}");
        }
        for local in ["fe80::1", "fd00::1", "::ffff:192.168.1.5", "2001:db8::1", "0.0.0.0", "198.18.0.1"] {
            assert!(!is_global(local.parse().unwrap()), "{local}");
        }
        for public in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8", "192.0.0.9", "224.0.0.1"] {
            assert!(is_global(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn urls_are_split_into_scheme_and_host() {
        let parts = split_url("https://User@Grizzle.Example.com:8443/path?q#f").unwrap();
        assert_eq!(parts.scheme, "https");
        assert_eq!(parts.netloc, "User@Grizzle.Example.com:8443");
        assert_eq!(parts.hostname.as_deref(), Some("grizzle.example.com"));
        assert_eq!(split_url("http://[FD00::1]:9000").unwrap().hostname.as_deref(), Some("fd00::1"));
        assert_eq!(split_url("//nas.local:9000").unwrap().hostname.as_deref(), Some("nas.local"));
        assert_eq!(split_url("null").unwrap().hostname, None);
        assert_eq!(split_url("null").unwrap().scheme, "");
        assert_eq!(split_url("http://[::1").map(|p| p.hostname), None);
        assert_eq!(split_url("file:///etc/passwd").unwrap().hostname, None);
    }

    #[test]
    fn upstream_host_follows_the_listen_address() {
        assert_eq!(upstream_host("0.0.0.0"), "127.0.0.1");
        assert_eq!(upstream_host(""), "127.0.0.1");
        assert_eq!(upstream_host("::"), "::1");
        assert_eq!(upstream_host("192.168.1.5"), "192.168.1.5");
    }
}
