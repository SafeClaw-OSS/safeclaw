//! The private-address floor: one canonical check for every place a host is
//! judged (a definition's `hosts` and URLs, a connection's pinned hosts, and
//! the proxy's egress).
//!
//! Hosts are read with the `url` crate's WHATWG host parser, the same parser
//! the HTTP client (reqwest) applies to the URLs it fetches, and the floor
//! judges what that parser returns, never the text as written (OWASP SSRF
//! cheat sheet: hand IP and domain formats to a tested library). A host whose
//! written form differs from what the parser reads (an IP in dword, octal or
//! hex notation such as `2130706433` or `0x7f.1`, a percent-encoded or
//! non-ASCII name) is refused outright, so the string an anchor compares is
//! the host the client connects to.
//!
//! Names are not resolved (CREDENTIAL_BROKER.md §14): the primary control is
//! the owner-approved exact host anchor, and a self-hosted internal service
//! reached by name is a legitimate target. Only literal addresses in the
//! blocked ranges and the RFC 6761 loopback names are refused here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Host;

/// True if `ip` lies in a range a credential must never egress to: the OWASP
/// SSRF cheat sheet deny-list (127.0.0.0/8, 0.0.0.0/8, ::1, RFC 1918,
/// fc00::/7, fe80::/10, 224.0.0.0/4, ff00::/8, with 169.254.169.254 inside
/// the 169.254.0.0/16 link-local range), plus the limited broadcast address,
/// `::`, and every IPv4-mapped IPv6 address (`::ffff:0:0/96`). An IPv6
/// address that carries an IPv4 one (IPv4-compatible `::a.b.c.d`, SIIT
/// `::ffff:0:a.b.c.d`, NAT64 `64:ff9b::/96` and the local-use
/// `64:ff9b:1::/48`, 6to4 `2002::/16`) is judged by that IPv4 address.
pub fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_blocked(v4),
        IpAddr::V6(v6) => v6_is_blocked(v6),
    }
}

fn v4_is_blocked(v4: Ipv4Addr) -> bool {
    v4.octets()[0] == 0 // 0.0.0.0/8 ("this network", incl. 0.0.0.0)
        || v4.is_loopback() // 127.0.0.0/8
        || v4.is_private() // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local() // 169.254/16, incl. the cloud metadata address
        || v4.is_multicast() // 224.0.0.0/4
        || v4.is_broadcast() // 255.255.255.255
}

fn v6_is_blocked(v6: Ipv6Addr) -> bool {
    let first = v6.segments()[0];
    v6.is_loopback() // ::1
        || v6.is_unspecified() // ::
        || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (first & 0xff00) == 0xff00 // ff00::/8 multicast
        || v6.to_ipv4_mapped().is_some() // ::ffff:0:0/96
        || embedded_v4(v6).into_iter().any(v4_is_blocked)
}

/// The IPv4 addresses an IPv6 address may carry to a gateway or the host
/// stack: IPv4-compatible `::a.b.c.d` (RFC 4291), SIIT IPv4-translated
/// `::ffff:0:a.b.c.d` (RFC 2765), NAT64 `64:ff9b::a.b.c.d` (RFC 6052), 6to4
/// `2002:aabb:ccdd::/48` (RFC 3056), and the local-use NAT64 prefix
/// `64:ff9b:1::/48` (RFC 8215). A local-use network picks its own prefix
/// length (48, 56, 64 or 96), which sets where the IPv4 address sits
/// (RFC 6052 §2.2): the /96 reading always counts, and each shorter one
/// counts when its suffix bits are zero, as that format requires.
fn embedded_v4(v6: Ipv6Addr) -> Vec<Ipv4Addr> {
    let s = v6.segments();
    let b = v6.octets();
    let v4 = |o: [u8; 4]| Ipv4Addr::from(o);
    let last32 = v4([b[12], b[13], b[14], b[15]]);
    if s[..6] == [0, 0, 0, 0, 0, 0]
        || s[..6] == [0, 0, 0, 0, 0xffff, 0]
        || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
    {
        return vec![last32];
    }
    if s[0] == 0x2002 {
        return vec![v4([b[2], b[3], b[4], b[5]])];
    }
    if s[..3] == [0x64, 0xff9b, 0x1] {
        let mut found = vec![last32];
        // RFC 6052 §2.2: octet 8 (bits 64..71) is skipped; what follows the
        // IPv4 address is the zero suffix.
        let zero = |r: std::ops::Range<usize>| b[r].iter().all(|&x| x == 0);
        if zero(13..16) {
            found.push(v4([b[9], b[10], b[11], b[12]])); // /64
        }
        if zero(12..16) {
            found.push(v4([b[7], b[9], b[10], b[11]])); // /56
        }
        if zero(11..16) {
            found.push(v4([b[6], b[7], b[9], b[10]])); // /48
        }
        return found;
    }
    Vec::new()
}

/// True if `domain` (already parsed) is an RFC 6761 loopback name.
fn is_loopback_name(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    d == "localhost" || d.ends_with(".localhost")
}

/// Why a parsed host is refused by the floor, or `None` when it passes.
fn floor_problem(host: &Host<String>) -> Option<&'static str> {
    match host {
        Host::Domain(d) if is_loopback_name(d) => Some("a loopback name"),
        Host::Domain(_) => None,
        Host::Ipv4(ip) if v4_is_blocked(*ip) => {
            Some("a loopback, private, link-local or multicast address")
        }
        Host::Ipv6(ip) if v6_is_blocked(*ip) => {
            Some("a loopback, private, link-local, multicast or IPv4-mapped address")
        }
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

/// `host` as the URL standard reads it, refused when that reading differs
/// from the text beyond ASCII case (a non-canonical IP notation, a
/// percent-encoded or non-ASCII name). `Ok` carries the parsed host.
fn parse_canonical(host: &str) -> Result<Host<String>, String> {
    let parsed = Host::parse(host).map_err(|e| format!("is not a valid host ({})", e))?;
    let canonical = parsed.to_string();
    if !canonical.eq_ignore_ascii_case(host) {
        return Err(match parsed {
            Host::Ipv4(_) | Host::Ipv6(_) => format!(
                "is an IP address in a non-canonical notation (read as {}); write it as {}",
                canonical, canonical
            ),
            Host::Domain(_) => format!(
                "is not written in canonical form (read as '{}'); write it as '{}'",
                canonical, canonical
            ),
        });
    }
    Ok(parsed)
}

/// Strip a `:port` from an authority (`host:port`, `[v6]:port`), keeping a
/// bracketed IPv6 literal bracketed (the form the host parser expects).
fn authority_host(authority: &str) -> &str {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(end) => &authority[..=end],
            None => authority,
        };
    }
    match authority.rsplit_once(':') {
        Some((h, _)) => h,
        None => authority,
    }
}

/// The runtime floor beneath every brokered request: `authority` is the
/// destination as the proxy received it (`host[:port]`). Refused when the
/// host does not parse, is not in canonical form, or is a blocked address or
/// loopback name.
pub fn host_egress_allowed(authority: &str) -> bool {
    match parse_canonical(authority_host(authority)) {
        Ok(host) => floor_problem(&host).is_none(),
        Err(_) => false,
    }
}

/// An author-written host entry (a definition's `hosts`, a connection's
/// pinned host): a bare host with no port and no wildcard (the caller strips
/// a leading `*.`). It must be in canonical form and pass the floor.
pub fn check_host_entry(entry: &str) -> Result<(), String> {
    let host = parse_canonical(entry).map_err(|e| format!("host '{}' {}", entry, e))?;
    match floor_problem(&host) {
        Some(why) => Err(format!("host '{}' is {}, not an egress target", entry, why)),
        None => Ok(()),
    }
}

/// A URL a definition declares, parsed by the `url` crate (the HTTP client's
/// own parser). Refused when it does not parse, its scheme is not in
/// `schemes`, it carries userinfo, or its host is not written in canonical
/// form. With `egress`, the host must also pass the floor (the daemon itself
/// fetches it).
pub fn check_url(
    label: &str,
    raw: &str,
    schemes: &[&str],
    egress: bool,
) -> Result<url::Url, String> {
    let url = url::Url::parse(raw)
        .map_err(|e| format!("{}: '{}' is not a valid URL ({})", label, raw, e))?;
    if !schemes.contains(&url.scheme()) {
        return Err(format!(
            "{}: '{}' must use {}",
            label,
            raw,
            schemes
                .iter()
                .map(|s| format!("{}://", s))
                .collect::<Vec<_>>()
                .join(" or ")
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{}: '{}' must not carry userinfo (user@host)",
            label, raw
        ));
    }
    let Some(host) = url.host() else {
        return Err(format!("{}: '{}' has no host", label, raw));
    };
    let host = host.to_owned();
    // The host as written: between `://` and the first `/ ? # \`, minus the
    // port. It must read back as itself, so what a person reads is what the
    // client fetches.
    let written = raw
        .split_once("://")
        .map(|(_, rest)| {
            let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
            authority_host(&rest[..end])
        })
        .unwrap_or("");
    if !host.to_string().eq_ignore_ascii_case(written) {
        return Err(format!(
            "{}: '{}' does not write its host in canonical form (read as '{}')",
            label, raw, host
        ));
    }
    if egress {
        if let Some(why) = floor_problem(&host) {
            return Err(format!(
                "{}: host '{}' is {}, not an egress target",
                label, host, why
            ));
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owasp_ranges_and_mapped_addresses_are_blocked() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.0.9",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "224.0.0.1",
            "239.255.255.255",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
        ] {
            assert!(ip_is_blocked(ip.parse().unwrap()), "{ip} must be blocked");
        }
        // IPv6 forms that carry an IPv4 address are judged by it.
        for ip in [
            "::127.0.0.1",
            "::10.0.0.1",
            "::169.254.169.254",
            "64:ff9b::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::192.168.0.1",
            "2002:7f00:1::",
            "2002:a00:1::1",
            "2002:c0a8:101::",
            // SIIT IPv4-translated.
            "::ffff:0:127.0.0.1",
            "::ffff:0:10.0.0.1",
            "::ffff:0:a9fe:a9fe",
            // Local-use NAT64, at each prefix length's position.
            "64:ff9b:1::127.0.0.1",        // /96
            "64:ff9b:1:abcd::192.168.0.1", // /96, a subnet of the /48
            "64:ff9b:1::7f:0:100:0",       // /64: 127.0.0.1
            "64:ff9b:1:a9:fe:a9fe::",      // /56: 169.254.169.254
            "64:ff9b:1:a00:0:100::",       // /48: 10.0.0.1
        ] {
            assert!(ip_is_blocked(ip.parse().unwrap()), "{ip} must be blocked");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.64.0.1",
            "2001:4860:4860::8888",
            "fec0::1",
            "::8.8.8.8",
            "64:ff9b::8.8.8.8",
            "2002:808:808::1",
            "::ffff:0:8.8.8.8",
            "64:ff9b:1::8.8.8.8",
            "64:ff9b:1:abcd::1.1.1.1",
            "64:ff9b:1:0:8:808:800:0", // /64: 8.8.8.8
        ] {
            assert!(!ip_is_blocked(ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[test]
    fn host_entries_must_be_canonical_and_public() {
        assert!(check_host_entry("api.github.com").is_ok());
        assert!(
            check_host_entry("API.GitHub.com").is_ok(),
            "ASCII case is not a different host"
        );
        assert!(check_host_entry("8.8.8.8").is_ok());
        assert!(
            check_host_entry("metadata.google.internal").is_ok(),
            "names are not special-cased"
        );
        for bad in [
            "2130706433",       // dword 127.0.0.1
            "0x7f.1",           // hex + short form
            "0177.0.0.1",       // octal
            "127.1",            // short form
            "134744072",        // dword 8.8.8.8: non-canonical even when public
            "127%2e0%2e0%2e1",  // percent-encoded
            "\u{ff4c}ocalhost", // fullwidth letter, maps to localhost
            "localhost",
            "app.localhost",
            "localhost.",
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "",
            "a b.com",
        ] {
            assert!(check_host_entry(bad).is_err(), "{bad:?} must be refused");
        }
        let e = check_host_entry("2130706433").unwrap_err();
        assert!(
            e.contains("non-canonical") && e.contains("127.0.0.1"),
            "{e}"
        );
    }

    #[test]
    fn egress_floor_reads_hosts_like_the_client() {
        assert!(host_egress_allowed("api.gitlab.com"));
        assert!(host_egress_allowed("git.acme.com:8443"));
        assert!(host_egress_allowed("vault.corp.internal"));
        assert!(host_egress_allowed("[2001:4860:4860::8888]:443"));
        for bad in [
            "127.0.0.1",
            "127.0.0.1:443",
            "2130706433",
            "2130706433:443",
            "0x7f.1",
            "0.0.0.0",
            "localhost",
            "localhost:8080",
            "[::1]",
            "[::1]:443",
            "[::ffff:7f00:1]",
            "[::ffff:127.0.0.1]:80",
            "[fd00::1]",
            "[fe80::1]",
            "[::127.0.0.1]",
            "[64:ff9b::7f00:1]",
            "[64:ff9b:1::7f00:1]",
            "[::ffff:0:7f00:1]:443",
            "[2002:a9fe:a9fe::]",
            "169.254.169.254",
            "134744072",
        ] {
            assert!(!host_egress_allowed(bad), "{bad} must be refused");
        }
    }

    #[test]
    fn urls_refuse_userinfo_noncanonical_hosts_and_the_floor() {
        let https = &["https"];
        assert!(check_url("u", "https://auth.acme.dev/token", https, true).is_ok());
        assert!(check_url("u", "https://AUTH.acme.dev/token", https, true).is_ok());
        for bad in [
            "http://auth.acme.dev/token",
            "https://user@auth.acme.dev/token",
            "https://user:pw@auth.acme.dev/token",
            "https://2130706433/",
            "https://0x7f.1/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://localhost:8443/x",
            "https:auth.acme.dev/token",
            "javascript:alert(1)",
            "not a url",
        ] {
            assert!(
                check_url("u", bad, https, true).is_err(),
                "{bad} must be refused"
            );
        }
        // Without the egress floor (a loopback redirect), the host may be local.
        let web = &["http", "https"];
        assert!(check_url("r", "http://127.0.0.1:8765/cb", web, false).is_ok());
        assert!(check_url("r", "http://localhost:1455/auth/callback", web, false).is_ok());
        assert!(check_url("r", "http://u@localhost:1455/cb", web, false).is_err());
    }
}
