//! Redis glob matching (ADR-0052 implementation obligation "local glob
//! matcher"): `*`, `?`, `[…]` with ranges and `^` negation, `\` escapes;
//! byte-wise and case-sensitive, as the server's `stringmatchlen`. Used to
//! filter key names against the declared `redis.key_patterns` (decision 4)
//! and the `cas_stores` names, in memory only: patterns are never sent to
//! the server, the console nor the logs.

/// Whether `name` matches `pattern`. Linear in practice: `*` backtracks to
/// its last occurrence only.
pub(crate) fn matches(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if n >= name.len() {
            // The rest of the pattern must be stars.
            return pattern
                .get(p..)
                .unwrap_or_default()
                .iter()
                .all(|c| *c == b'*');
        }
        let Some(&pc) = pattern.get(p) else {
            match star {
                Some((sp, sn)) => {
                    p = sp + 1;
                    n = sn + 1;
                    star = Some((sp, sn + 1));
                    continue;
                }
                None => return false,
            }
        };
        let Some(&c) = name.get(n) else {
            return false;
        };
        let step = match pc {
            b'*' => {
                star = Some((p, n));
                p += 1;
                continue;
            }
            b'?' => Some(1),
            b'[' => class(pattern, p, c),
            b'\\' if p + 1 < pattern.len() => (pattern.get(p + 1) == Some(&c)).then_some(2),
            _ => (pc == c).then_some(1),
        };
        match step {
            Some(len) => {
                p += len;
                n += 1;
            }
            None => match star {
                Some((sp, sn)) => {
                    p = sp + 1;
                    n = sn + 1;
                    star = Some((sp, sn + 1));
                }
                None => return false,
            },
        }
    }
}

/// Matches `c` against the class starting at `pattern[start] == b'['`:
/// `Some(pattern bytes consumed)` on a match.
fn class(pattern: &[u8], start: usize, c: u8) -> Option<usize> {
    let mut i = start + 1;
    let negate = pattern.get(i) == Some(&b'^');
    if negate {
        i += 1;
    }
    let mut hit = false;
    // Unterminated: the class ends with the pattern (as the server does).
    while let Some(&b) = pattern.get(i) {
        if b == b']' {
            i += 1;
            break;
        }
        if b == b'\\' && i + 1 < pattern.len() {
            if pattern.get(i + 1) == Some(&c) {
                hit = true;
            }
            i += 2;
        } else if pattern.get(i + 1) == Some(&b'-') && i + 2 < pattern.len() {
            let (lo, hi) = (b, pattern.get(i + 2).copied().unwrap_or(b));
            let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
            if (lo..=hi).contains(&c) {
                hit = true;
            }
            i += 3;
        } else {
            if b == c {
                hit = true;
            }
            i += 1;
        }
    }
    (hit != negate).then_some(i - start)
}

/// A constant, non-empty key matching `pattern` (for `ACL DRYRUN … type
/// <key>`, decision 4), verified with [`matches`]; `None` when none is
/// found.
pub(crate) fn example(pattern: &[u8]) -> Option<Vec<u8>> {
    const CANDIDATES: &[u8] = b"a0_zZ:x9.-";
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&b) = pattern.get(i) {
        match b {
            // One byte for a run: `ACL DRYRUN` takes no empty key.
            b'*' => {
                if out.last() != Some(&b'x') || pattern.get(i.wrapping_sub(1)) != Some(&b'*') {
                    out.push(b'x');
                }
                i += 1;
            }
            b'?' => {
                out.push(b'a');
                i += 1;
            }
            b'\\' => {
                out.push(pattern.get(i + 1).copied().unwrap_or(b'\\'));
                i += 2;
            }
            b'[' => {
                let pick = CANDIDATES
                    .iter()
                    .copied()
                    .chain(0x21..0x7f)
                    .find(|c| class(pattern, i, *c).is_some())?;
                let len = class(pattern, i, pick)?;
                out.push(pick);
                i += len;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    matches(pattern, &out).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_glob_semantics() {
        assert!(matches(b"*", b""));
        assert!(matches(b"*", b"anything"));
        assert!(matches(b"user:*", b"user:42:email"));
        assert!(!matches(b"user:*", b"customer:1"));
        assert!(matches(b"h?llo", b"hello"));
        assert!(!matches(b"h?llo", b"hllo"));
        assert!(matches(b"h[ae]llo", b"hallo"));
        assert!(!matches(b"h[ae]llo", b"hillo"));
        assert!(matches(b"h[^e]llo", b"hallo"));
        assert!(!matches(b"h[^e]llo", b"hello"));
        assert!(matches(b"h[a-b]llo", b"hbllo"));
        assert!(matches(b"h[b-a]llo", b"hallo"));
        assert!(matches(b"a\\*b", b"a*b"));
        assert!(!matches(b"a\\*b", b"axb"));
        assert!(matches(b"*:*:email", b"user:42:email"));
        assert!(!matches(b"User:*", b"user:1"));
        assert!(matches(b"a*b*c", b"aXbYbZc"));
    }

    #[test]
    fn examples_match_their_pattern() {
        for p in [
            &b"user:*"[..],
            b"*",
            b"a?[bc][^x]\\*",
            b"[0-9]*",
            b"customer:[a-z]*:x",
        ] {
            let k = example(p).unwrap();
            assert!(matches(p, &k) && !k.is_empty(), "{p:?}");
        }
    }
}
