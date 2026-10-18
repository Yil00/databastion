//! Oracles of the CSV [`Splitter`] over csvlog records quoted as
//! PostgreSQL writes them (#267 review L3), shared by the property test of
//! this crate and the `core_csv_splitter` fuzz target (`agent/fuzz`).
//! Compiled for tests and the `fuzzing` feature only, never by the agent
//! binary.
//!
//! The records are those PostgreSQL writes to `csvlog` for pgaudit and for
//! `log_statement`: the statement text quoted by pgaudit inside its message
//! (wrapped in quotes, each quote doubled, when it holds a quote, a comma
//! or a line break), or at the end of a `statement: …` message; the
//! message then quoted by PostgreSQL as every non-empty text field. The
//! oracles check, for any statement texts:
//!
//! - aligned input, fed in chunks of any size: exactly the records, never a
//!   realignment, a damaged or an oversized record;
//! - a first start at any offset of the first record (after a newline or
//!   not): exactly the records after it, nothing counted as damaged;
//! - a record cut short inside a quoted field: exactly the other records,
//!   one damaged record counted (#267 review L2); with the next record
//!   written right after the cut (no newline), only records written, byte
//!   for byte (security review of #278, L3);
//! - a record bound smaller than some records, aligned or not: exactly the
//!   records that fit after the start, the others counted as oversized
//!   when the start is aligned; never a forged record.
//!
//! A failed oracle panics with counts and offsets only, never record bytes.

use zeroize::Zeroizing;

use super::{Framing, MAX_RECORD_BYTES, Splitter};

/// Most statements read from a fuzz input.
const MAX_STATEMENTS: usize = 8;

/// `field` as a quoted CSV field (quotes doubled).
fn quoted(out: &mut Vec<u8>, field: &[u8]) {
    out.push(b'"');
    for &b in field {
        if b == b'"' {
            out.push(b'"');
        }
        out.push(b);
    }
    out.push(b'"');
}

/// A `csvlog` record of statement `n`, ending with its newline: a pgaudit
/// record when `n` is even, a `log_statement` record (`statement: …`, the
/// text at the end of the message, so that its last byte comes right
/// before the closing quote) when it is odd.
#[must_use]
pub fn csvlog_record(n: usize, statement: &[u8]) -> Vec<u8> {
    let message = if n.is_multiple_of(2) {
        // pgaudit's own CSV field: quoted only when it has to be.
        let mut m = format!("AUDIT: SESSION,{n},1,READ,SELECT,TABLE,crm.t_{n},").into_bytes();
        if statement
            .iter()
            .any(|b| matches!(b, b'"' | b',' | b'\n' | b'\r'))
        {
            quoted(&mut m, statement);
        } else {
            m.extend_from_slice(statement);
        }
        m.extend_from_slice(b",<not logged>");
        m
    } else {
        let mut m = b"statement: ".to_vec();
        m.extend_from_slice(statement);
        m
    };
    let mut r = format!(
        "2026-10-18 09:00:{s:02}.{n:03} UTC,",
        s = n % 60,
        n = n % 1000
    )
    .into_bytes();
    quoted(&mut r, b"databastion");
    r.push(b',');
    quoted(&mut r, b"shop");
    r.extend_from_slice(b",4242,");
    quoted(&mut r, b"127.0.0.1:5555");
    r.extend_from_slice(format!(",6710f0a4.4d2,{n},").as_bytes());
    quoted(&mut r, b"SELECT");
    r.extend_from_slice(b",2026-10-18 08:59:00 UTC,3/45,0,LOG,00000,");
    quoted(&mut r, &message);
    r.extend_from_slice(b",,,,,,,,,");
    quoted(&mut r, b"databastion-it");
    r.push(b',');
    quoted(&mut r, b"client backend");
    r.extend_from_slice(b",,0\n");
    r
}

/// The records, without their newline (as the splitter returns them).
fn bodies(records: &[Vec<u8>]) -> Vec<&[u8]> {
    records.iter().map(|r| &r[..r.len() - 1]).collect()
}

/// Feeds `data` in chunks of `chunk` bytes (0: at once).
fn feed(s: &mut Splitter, data: &[u8], chunk: usize) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out = Vec::new();
    if chunk == 0 {
        s.feed(data, &mut out);
    } else {
        for c in data.chunks(chunk) {
            s.feed(c, &mut out);
        }
    }
    out
}

/// Whether the output is exactly `want`.
fn same(out: &[Zeroizing<Vec<u8>>], want: &[&[u8]]) -> bool {
    out.len() == want.len() && out.iter().zip(want).all(|(o, w)| o.as_slice() == *w)
}

/// Every oracle over the records of `statements` (at least three are made,
/// missing ones with a fixed text). `chunk`: feed size (0: at once); `at`:
/// selects the first-start offset in the first record; `damage`: selects
/// the damaged record and where it is cut; `max`: the record bound of the
/// oversized oracle.
///
/// # Panics
/// When an oracle fails (counts and offsets only in the message).
pub fn check(statements: &[&[u8]], chunk: usize, at: usize, damage: usize, max: usize) {
    let mut records: Vec<Vec<u8>> = statements
        .iter()
        .take(MAX_STATEMENTS)
        .enumerate()
        .map(|(n, s)| csvlog_record(n, s))
        .collect();
    while records.len() < 3 {
        records.push(csvlog_record(records.len(), b"SELECT 1"));
    }
    let all: Vec<u8> = records.concat();
    let want = bodies(&records);

    // Aligned input.
    let mut s = Splitter::new(Framing::Csv);
    let out = feed(&mut s, &all, chunk);
    assert!(
        same(&out, &want),
        "aligned: {} records out of {}",
        out.len(),
        want.len()
    );
    assert_eq!(
        (s.realigned, s.malformed, s.oversized, s.pending()),
        (0, 0, 0, 0),
        "aligned: realigned, malformed, oversized, pending"
    );
    assert!(s.aligned(), "aligned: boundary known");

    // A first start at any offset of the first record.
    let at = at % (records[0].len() + 1);
    let after_newline = at == 0 || records[0][at - 1] == b'\n';
    let mut s = Splitter::new(Framing::Csv);
    s.reset_unaligned(after_newline);
    let out = feed(&mut s, &all[at..], chunk);
    let from = usize::from(at > 0);
    assert!(
        same(&out, &want[from..]),
        "start at byte {at}: {} records out of {}",
        out.len(),
        want.len() - from
    );
    assert_eq!(
        (s.malformed, s.oversized, s.pending()),
        (0, 0, 0),
        "start at byte {at}: malformed, oversized, pending"
    );
    assert!(s.aligned(), "start at byte {at}: boundary known");

    // A record cut short inside a quoted field (an odd number of quotes
    // before the cut), then a newline: only that record is lost.
    let j = damage % (records.len() - 1);
    let odd: Vec<usize> = (1..records[j].len())
        .filter(|&p| records[j][..p].iter().filter(|&&b| b == b'"').count() % 2 == 1)
        .collect();
    let p = odd[(damage / records.len()) % odd.len()];
    let mut damaged = Vec::with_capacity(all.len());
    for (i, r) in records.iter().enumerate() {
        if i == j {
            damaged.extend_from_slice(&r[..p]);
            damaged.push(b'\n');
        } else {
            damaged.extend_from_slice(r);
        }
    }
    let kept: Vec<&[u8]> = want
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != j)
        .map(|(_, r)| *r)
        .collect();
    let mut s = Splitter::new(Framing::Csv);
    let out = feed(&mut s, &damaged, chunk);
    assert!(
        same(&out, &kept),
        "record {j} cut at byte {p}: {} records out of {}",
        out.len(),
        kept.len()
    );
    assert_eq!(
        (s.malformed, s.realigned, s.pending()),
        (1, 1, 0),
        "record {j} cut at byte {p}: malformed, realigned, pending"
    );

    // The same cut with the next record written right after it, no newline
    // in between (security review of #278, L3): the damaged record may take
    // the next one with it, but every record emitted is one of the records
    // written, byte for byte (a quoted newline of the statement before the
    // cut never becomes a record boundary), and the records after those two
    // are all read.
    let mut glued = damaged.clone();
    let newline = records[..j].iter().map(Vec::len).sum::<usize>() + p;
    glued.remove(newline);
    let mut s = Splitter::new(Framing::Csv);
    let out = feed(&mut s, &glued, chunk);
    let mut next = 0usize;
    for o in &out {
        let i = want[next..].iter().position(|w| o.as_slice() == *w);
        assert!(
            i.is_some(),
            "record {j} cut at byte {p}, glued: a record that was not written"
        );
        next += i.unwrap_or_default() + 1;
        assert_ne!(
            next - 1,
            j,
            "record {j} cut at byte {p}, glued: the damaged record"
        );
    }
    let after = &want[(j + 2).min(want.len())..];
    assert!(
        out.len() >= after.len() && same(&out[out.len() - after.len()..], after),
        "record {j} cut at byte {p}, glued: the records after it"
    );
    assert_eq!(
        s.malformed, 1,
        "record {j} cut at byte {p}, glued: malformed"
    );

    // A record bound smaller than some records: aligned, then from the
    // first-start offset.
    let max = max.clamp(64, MAX_RECORD_BYTES);
    let fits = |r: &&[u8]| r.len() <= max;
    let mut s = Splitter::with_max(Framing::Csv, max);
    let out = feed(&mut s, &all, chunk);
    let short: Vec<&[u8]> = want.iter().copied().filter(fits).collect();
    assert!(
        same(&out, &short),
        "bound {max}: {} records out of {}",
        out.len(),
        short.len()
    );
    assert_eq!(
        (s.oversized, s.realigned, s.malformed),
        ((want.len() - short.len()) as u64, 0, 0),
        "bound {max}: oversized, realigned, malformed"
    );
    let mut s = Splitter::with_max(Framing::Csv, max);
    s.reset_unaligned(after_newline);
    let out = feed(&mut s, &all[at..], chunk);
    let short: Vec<&[u8]> = want[from..].iter().copied().filter(fits).collect();
    assert!(
        same(&out, &short),
        "bound {max}, start at byte {at}: {} records out of {}",
        out.len(),
        short.len()
    );
    assert_eq!(s.malformed, 0, "bound {max}, start at byte {at}: malformed");
}

/// Fuzz entry point: `data` is `[chunk, at (2 bytes), damage (2 bytes),
/// max]` then statement texts separated by `0xFF` (at most
/// [`MAX_STATEMENTS`]); see [`check`].
pub fn splitter(data: &[u8]) {
    let Some((head, rest)) = data.split_first_chunk::<6>() else {
        return;
    };
    let chunk = usize::from(head[0]);
    let at = usize::from(u16::from_be_bytes([head[1], head[2]]));
    let damage = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let max = 64 + 4 * usize::from(head[5]);
    let statements: Vec<&[u8]> = rest.split(|&b| b == 0xFF).take(MAX_STATEMENTS).collect();
    check(&statements, chunk, at, damage, max);
}
