//! URL handling (ADR-0041 decisions 4 and 7, security review M2 and L2;
//! review of #138 M1 and L5).
//!
//! - [`strip_credentials`]: before a registry value is classified, every
//!   URL in it (any token holding `//`: `scheme://…` and protocol-relative
//!   `//…`) loses everything up to the **last** `@` (or `%40`) of the token
//!   (the userinfo, whatever characters the password holds: `/`, `?`,
//!   `#`, `:`, `%`), then its query string and fragment. Over-stripping (a
//!   path holding `@`, a `?` of a regular expression `serviceId`) is
//!   accepted. The result is a zeroizing buffer.
//! - [`service_of`]: the audit record's `what` is reduced to the scheme and
//!   host of the first `http(s)://` URL it holds (searched without copying
//!   `what`), used only to select a registry entry; the ticket id, the
//!   userinfo, the path and the query string are dropped, and the host
//!   itself never leaves the agent.

use zeroize::Zeroizing;

/// Longest host kept, in bytes.
const MAX_HOST_BYTES: usize = 253;

/// Whether `b` ends a URL (blank or a delimiter that cannot be part of
/// one in logged text).
fn ends_url(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'`')
}

/// Index just after the last `@` or `%40` (any case) of `t`, or 0.
fn after_last_at(t: &str) -> usize {
    let b = t.as_bytes();
    let mut cut = 0;
    for (i, c) in b.iter().enumerate() {
        if *c == b'@' {
            cut = i + 1;
        } else if *c == b'%' && b.get(i + 1) == Some(&b'4') && b.get(i + 2) == Some(&b'0') {
            cut = i + 3;
        }
    }
    cut
}

/// Appends one blank-free token, its URL credentials removed.
fn push_token(out: &mut String, token: &str) {
    let Some(i) = token.find("//") else {
        out.push_str(token);
        return;
    };
    let (head, tail) = token.split_at(i + 2);
    out.push_str(head);
    let tail = tail.get(after_last_at(tail)..).unwrap_or("");
    let end = tail
        .bytes()
        .position(|b| matches!(b, b'?' | b'#'))
        .unwrap_or(tail.len());
    out.push_str(tail.get(..end).unwrap_or(""));
}

/// Removes the userinfo, query string and fragment of every URL in `s`
/// (see the module documentation). Text outside URLs is kept as is.
#[must_use]
pub fn strip_credentials(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    let mut rest = s;
    while !rest.is_empty() {
        let start = rest
            .bytes()
            .position(|b| !ends_url(b))
            .unwrap_or(rest.len());
        let (delims, r) = rest.split_at(start);
        out.push_str(delims);
        let end = r.bytes().position(ends_url).unwrap_or(r.len());
        let (token, r) = r.split_at(end);
        push_token(&mut out, token);
        rest = r;
    }
    out
}

/// Scheme of a service URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

/// The scheme and host of a service URL (lowercase host, no userinfo,
/// no port). Used only to select a registry entry.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServiceHost {
    /// Scheme.
    pub scheme: Scheme,
    /// Host: a DNS name or an IP literal (`[…]` for IPv6).
    pub host: String,
}

impl std::fmt::Debug for ServiceHost {
    // The host is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceHost")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl ServiceHost {
    /// `scheme://host/`, the text matched against `serviceId` patterns.
    #[must_use]
    pub fn as_url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        format!("{scheme}://{}/", self.host)
    }
}

fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > MAX_HOST_BYTES {
        return false;
    }
    if let Some(inner) = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    h.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !h.starts_with('.')
        && !h.starts_with('-')
}

/// The scheme and host of the first `http://` or `https://` URL in `what`
/// (case-insensitive scheme). `None` when there is none or its host is not
/// a plain DNS name or IP literal.
#[must_use]
pub fn service_of(what: &str) -> Option<ServiceHost> {
    let bytes = what.as_bytes();
    let find = |p: &[u8]| {
        bytes
            .windows(p.len())
            .position(|w| w.eq_ignore_ascii_case(p))
    };
    let (i, scheme, len) = [
        (&b"https://"[..], Scheme::Https),
        (&b"http://"[..], Scheme::Http),
    ]
    .iter()
    .filter_map(|(p, s)| find(p).map(|i| (i, *s, p.len())))
    .min_by_key(|(i, _, _)| *i)?;
    let tail = what.get(i + len..)?;
    // The URL token, then everything up to its last `@` dropped (the
    // userinfo, whatever it holds).
    let token_end = tail.bytes().position(ends_url).unwrap_or(tail.len());
    let token = tail.get(..token_end)?;
    let token = token.get(after_last_at(token)..)?;
    let stop = |b: u8| matches!(b, b'/' | b'?' | b'#' | b',' | b';' | b')' | b'}' | b'|');
    let end = token.bytes().position(stop).unwrap_or(token.len());
    let host_port = token.get(..end)?;
    let host = if host_port.starts_with('[') {
        host_port.get(..=host_port.find(']')?)?
    } else {
        host_port.split(':').next()?
    };
    valid_host(host).then(|| ServiceHost {
        scheme,
        host: host.to_ascii_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_stripped_from_urls() {
        let cases = [
            ("https://app.example.org/x", "https://app.example.org/x"),
            (
                "https://user:hunter2-SECRET@app.example.org/x?token=abc&a=b#frag",
                "https://app.example.org/x",
            ),
            (
                "^https://.*\\.example\\.org/.*",
                "^https://.*\\.example\\.org/.*",
            ),
            (
                "see https://a@b.example.org?x=1 and ldap://u:p@dir/o?q then",
                "see https://b.example.org and ldap://dir/o then",
            ),
            ("no url here", "no url here"),
            (
                "https://svc:pa/ss@h.example.org/x",
                "https://h.example.org/x",
            ),
            (
                "https://svc:p?w#d@h.example.org/x?q",
                "https://h.example.org/x",
            ),
            ("//u:p@h.example.org/a", "//h.example.org/a"),
            ("https://u%3Ap%40h.example.org/a", "https://h.example.org/a"),
            ("https://u:p%40x@h.example.org/a", "https://h.example.org/a"),
            ("://@?#", "://"),
            ("é://é@é/é?é", "é://é/é"),
        ];
        for (input, expected) in cases {
            assert_eq!(strip_credentials(input).as_str(), expected, "{input}");
        }
    }

    #[test]
    fn what_is_reduced_to_scheme_and_host() {
        let s = |w: &str| service_of(w).map(|h| h.as_url());
        assert_eq!(
            s("ST-1-FAKEfakeFAKE-cas01 for https://App.Example.org:8443/login?ticket=ST-2-x")
                .as_deref(),
            Some("https://app.example.org/")
        );
        assert_eq!(
            s("{service=http://u:hunter2-SECRET@intranet/path, principal=jdoe}").as_deref(),
            Some("http://intranet/")
        );
        assert_eq!(
            s("https://[2001:db8::1]:8443/x").as_deref(),
            Some("https://[2001:db8::1]/")
        );
        assert_eq!(
            s("ST-1 for https://svc:pa/ss@H.example.org/x").as_deref(),
            Some("https://h.example.org/")
        );
        assert_eq!(s("TGT-9-FAKEfake-cas01"), None);
        assert_eq!(s("https://exa_mple.org/"), None);
        assert_eq!(s("https://"), None);
        assert_eq!(s("https://[zz]/"), None);
    }
}
