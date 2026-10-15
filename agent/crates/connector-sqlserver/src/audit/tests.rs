//! Unit tests of the stream's position rules.

use super::*;

fn pos(list: &[(&str, i64)]) -> Vec<(String, i64)> {
    list.iter().map(|(f, o)| ((*f).to_owned(), *o)).collect()
}

#[test]
fn cursor_round_trips() {
    let c = Cursor {
        file: Some("/var/opt/mssql/audit/a b_0_1.sqlaudit".to_owned()),
        offset: 53_248,
        skip: 3,
        guid: Some("B5BEF79B-88AC-4A47-91AE-0081BBD71D51".to_owned()),
        after: Some(("/x/y_0_1.sqlaudit".to_owned(), 4096)),
        history_us: Some(17),
    };
    assert_eq!(Cursor::decode(&c.encode()), Some(c));
    assert_eq!(
        Cursor::decode(&Cursor::default().encode()),
        Some(Cursor::default())
    );
    assert!(Cursor::decode(b"v2\n").is_none());
    assert!(Cursor::decode(b"v1\nfile zz\n").is_none());
    assert!(Cursor::decode(b"v1\nguid x' OR 1=1\n").is_none());
    let big = Cursor::decode(b"v1\nskip 999999\n").unwrap();
    assert_eq!(big.skip, MAX_SKIP);
}

#[test]
fn a_read_that_is_not_full_moves_to_its_last_buffer() {
    let c = Cursor::default();
    let n = advance(&c, &pos(&[("f1", 4096), ("f1", 8192), ("f2", 4096)]), 10);
    assert_eq!((n.file.as_deref(), n.offset, n.skip), (Some("f2"), 4096, 0));
    // Nothing read: unchanged.
    assert_eq!(advance(&c, &[], 10), c);
}

#[test]
fn a_full_read_reads_its_last_buffer_again() {
    let c = Cursor {
        file: Some("f1".to_owned()),
        offset: 4096,
        ..Cursor::default()
    };
    let n = advance(
        &c,
        &pos(&[("f1", 8192), ("f1", 8192), ("f1", 12288), ("f1", 12288)]),
        4,
    );
    assert_eq!((n.file.as_deref(), n.offset, n.skip), (Some("f1"), 8192, 2));
    // The whole read is one buffer: the skip grows.
    let c2 = Cursor {
        skip: 4,
        ..c.clone()
    };
    let n = advance(&c2, &pos(&[("f1", 8192); 8]), 8);
    assert_eq!(
        (n.file.as_deref(), n.offset, n.skip),
        (Some("f1"), 4096, 12)
    );
}
