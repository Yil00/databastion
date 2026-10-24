//! The header pre-check in Rust (ADR-0059 decision 2, step 3), on the first
//! 100 bytes of the file read through the check descriptor. A filter, not
//! a proof: an encrypted, compressed or misplaced file, or a secret file,
//! does not reach the C library through this path; a file that passes is
//! parsed by SQLite in the sandboxed reader only.

/// Bytes of the database header.
pub const HEADER_LEN: usize = 100;
/// The magic string.
const MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// Smallest file the reader opens (decision 2: a 0-byte file would be an
/// empty database to SQLite, which deletes a `-wal`).
pub const MIN_FILE_LEN: u64 = 512;

/// What the header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The page size in bytes (512 to 65 536).
    pub page_size: u32,
    /// The file is in WAL mode (read version 2).
    pub wal: bool,
    /// The file change counter (offset 24), for the full-check trigger.
    pub change_counter: u32,
    /// The text encoding (1 UTF-8, 2 UTF-16le, 3 UTF-16be).
    pub encoding: u32,
    /// The SQLite version number that last wrote the file (offset 96).
    pub writer_version: u32,
}

fn be32(h: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 4] = h.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

fn be16(h: &[u8], at: usize) -> Option<u16> {
    let b: [u8; 2] = h.get(at..at + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(b))
}

/// Checks the header of a file of `file_len` bytes: the magic; a page size
/// that is a power of two from 512 to 65 536 (1 meaning 65 536); write and
/// read versions 1 or 2; the payload fractions 64, 32, 32; a schema format
/// number from 1 to 4 (0 only for an empty schema, page count 1); a text
/// encoding 1, 2 or 3 (0 only for an empty schema); a page count consistent
/// with the file size when the header says it is valid. `None`: refused
/// (`coverage.unrecognized_file_format`).
#[must_use]
pub fn check(h: &[u8], file_len: u64) -> Option<Header> {
    if h.len() < HEADER_LEN || file_len < MIN_FILE_LEN || h.get(..16)? != MAGIC {
        return None;
    }
    let page_size = match be16(h, 16)? {
        1 => 65_536,
        n if n >= 512 && n.is_power_of_two() => u32::from(n),
        _ => return None,
    };
    let write_version = *h.get(18)?;
    let read_version = *h.get(19)?;
    if !(1..=2).contains(&write_version) || !(1..=2).contains(&read_version) {
        return None;
    }
    // Reserved bytes per page: the usable size must stay at least 480.
    let reserved = u32::from(*h.get(20)?);
    if page_size.saturating_sub(reserved) < 480 {
        return None;
    }
    if h.get(21..24)? != [64, 32, 32] {
        return None;
    }
    let change_counter = be32(h, 24)?;
    let page_count = be32(h, 28)?;
    let version_valid_for = be32(h, 92)?;
    let schema_format = be32(h, 44)?;
    let encoding = be32(h, 56)?;
    // A fresh database whose schema was never written has 0 in both.
    let empty_schema = schema_format == 0 && encoding == 0;
    if !empty_schema && (!(1..=4).contains(&schema_format) || !(1..=3).contains(&encoding)) {
        return None;
    }
    // The in-header page count is valid when it is non-zero and the
    // "version-valid-for" number matches the change counter.
    if page_count != 0 && version_valid_for == change_counter {
        let expected = u64::from(page_count) * u64::from(page_size);
        // The file may be larger only by a WAL-mode or rollback-mode tail
        // the pager ignores; never smaller.
        if file_len < expected {
            return None;
        }
    }
    // At least one whole page.
    if file_len < u64::from(page_size) {
        return None;
    }
    Some(Header {
        page_size,
        wal: read_version == 2,
        change_counter,
        encoding,
        writer_version: be32(h, 96)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A valid header for a file of `pages` pages of 4096 bytes.
    pub(crate) fn valid(pages: u32) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_LEN];
        h[..16].copy_from_slice(MAGIC);
        h[16..18].copy_from_slice(&4096u16.to_be_bytes());
        h[18] = 1;
        h[19] = 1;
        h[21] = 64;
        h[22] = 32;
        h[23] = 32;
        h[24..28].copy_from_slice(&7u32.to_be_bytes());
        h[28..32].copy_from_slice(&pages.to_be_bytes());
        h[44..48].copy_from_slice(&4u32.to_be_bytes());
        h[56..60].copy_from_slice(&1u32.to_be_bytes());
        h[92..96].copy_from_slice(&7u32.to_be_bytes());
        h[96..100].copy_from_slice(&3_053_002u32.to_be_bytes());
        h
    }

    #[test]
    fn a_valid_header_passes() {
        let h = check(&valid(2), 8192).unwrap();
        assert_eq!(h.page_size, 4096);
        assert!(!h.wal);
        assert_eq!(h.writer_version, 3_053_002);
        let mut w = valid(2);
        w[18] = 2;
        w[19] = 2;
        assert!(check(&w, 8192).unwrap().wal);
        let mut big = valid(1);
        big[16..18].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(check(&big, 65_536).unwrap().page_size, 65_536);
    }

    #[test]
    fn anything_else_is_refused() {
        let base = valid(2);
        let cases: Vec<(usize, &[u8])> = vec![
            (0, b"SQLite format 2"),
            (16, &[0x03, 0x00]),
            (16, &[0x01, 0x00]),
            (18, &[3]),
            (19, &[3]),
            (21, &[65]),
            (44, &[0, 0, 0, 5]),
            (56, &[0, 0, 0, 4]),
        ];
        for (at, bytes) in cases {
            let mut h = base.clone();
            h[at..at + bytes.len()].copy_from_slice(bytes);
            assert_eq!(check(&h, 8192), None, "offset {at}");
        }
        // Smaller than the page count says, too short, a 0-byte file.
        assert_eq!(check(&base, 4096), None);
        assert_eq!(check(&base[..99], 8192), None);
        assert_eq!(check(&base, 0), None);
        // An encrypted file has no plain header.
        assert_eq!(check(&[0xa5; 100], 8192), None);
    }

    // The pre-check never accepts what SQLite would refuse on these
    // fields, and never panics.
    proptest! {
        #[test]
        fn never_panics(h in proptest::collection::vec(any::<u8>(), 0..120), len in any::<u64>()) {
            let _ = check(&h, len);
        }

        #[test]
        fn accepted_headers_have_valid_fields(
            ps in any::<u16>(), wv in 0u8..4, rv in 0u8..4, sf in 0u32..6, enc in 0u32..5,
        ) {
            let mut h = valid(1);
            h[16..18].copy_from_slice(&ps.to_be_bytes());
            h[18] = wv;
            h[19] = rv;
            h[44..48].copy_from_slice(&sf.to_be_bytes());
            h[56..60].copy_from_slice(&enc.to_be_bytes());
            if let Some(got) = check(&h, 1 << 20) {
                prop_assert!(got.page_size.is_power_of_two() && (512..=65_536).contains(&got.page_size));
                prop_assert!((1..=2).contains(&wv) && (1..=2).contains(&rv));
                prop_assert!((sf == 0 && enc == 0) || ((1..=4).contains(&sf) && (1..=3).contains(&enc)));
            }
        }
    }
}
