//! URL handling (ADR-0041 decisions 4 and 7, security review M2 and L2).
//!
//! - [`strip_credentials`]: before a registry value is classified, every
//!   `scheme://` URL in it loses its userinfo (`user:password@`), its query
//!   string and its fragment, which carry credentials and tokens.
//! - [`service_of`]: the audit record's `what` is reduced to the scheme and
//!   host of the first `http(s)://` URL it holds, used only to select a
//!   registry entry; the ticket id, the path and the query string are
//!   dropped, and the host itself never leaves the agent.

use std::borrow::Cow;

/// Longest host kept, in bytes.
const MAX_HOST_BYTES: usize = 253;

/// Whether `b` ends a URL (blank or a delimiter that cannot be part of
/// one in logged text).
fn ends_url(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'`')
}

/// Removes the userinfo, query string and fragment of every `scheme://`
/// URL in `s`. Text outside URLs is kept as is. Over-stripping (a `?` of a
/// regular expression `serviceId`) is accepted.
#[must_use]
pub fn strip_credentials(s: &str) -> Cow<'_, str> {
    if !s.contains("://") {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        out.push_str("://");
        let tail = tail.get(3..).unwrap_or("");
        let bytes = tail.as_bytes();
        // Authority: up to `/`, `?`, `#` or the end of the URL.
        let auth_end = bytes
            .iter()
            .position(|b| matches!(b, b'/' | b'?' | b'#') || ends_url(*b))
            .unwrap_or(bytes.len());
        let (authority, after) = tail.split_at(auth_end);
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        out.push_str(host);
        // Path: up to `?`, `#` or the end of the URL; the query and the
        // fragment are dropped up to the end of the URL.
        let ab = after.as_bytes();
        let url_end = ab.iter().position(|b| ends_url(*b)).unwrap_or(ab.len());
        let (url_rest, text) = after.split_at(url_end);
        let path_end = url_rest
            .as_bytes()
            .iter()
            .position(|b| matches!(b, b'?' | b'#'))
            .unwrap_or(url_rest.len());
        let (path, _) = url_rest.split_at(path_end);
        out.push_str(path);
        rest = text;
    }
    out.push_str(rest);
    Cow::Owned(out)
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
    let lower = what.to_ascii_lowercase();
    let (i, scheme, len) = [("https://", Scheme::Https), ("http://", Scheme::Http)]
        .iter()
        .filter_map(|(p, s)| lower.find(p).map(|i| (i, *s, p.len())))
        .min_by_key(|(i, _, _)| *i)?;
    let tail = lower.get(i + len..)?;
    let stop =
        |b: u8| matches!(b, b'/' | b'?' | b'#' | b',' | b';' | b')' | b'}' | b'|') || ends_url(b);
    let end = tail.bytes().position(stop).unwrap_or(tail.len());
    let authority = tail.get(..end)?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if host_port.starts_with('[') {
        host_port.get(..=host_port.find(']')?)?
    } else {
        host_port.split(':').next()?
    };
    valid_host(host).then(|| ServiceHost {
        scheme,
        host: host.to_owned(),
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
            ("://@?#", "://"),
            ("é://é@é/é?é", "é://é/é"),
        ];
        for (input, expected) in cases {
            assert_eq!(strip_credentials(input), expected, "{input}");
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
        assert_eq!(s("TGT-9-FAKEfake-cas01"), None);
        assert_eq!(s("https://exa_mple.org/"), None);
        assert_eq!(s("https://"), None);
        assert_eq!(s("https://[zz]/"), None);
    }
}
