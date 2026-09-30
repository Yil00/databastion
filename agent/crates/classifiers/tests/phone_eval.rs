//! Column-level recall / precision of `pii.phone` on labeled columns
//! generated in code (deterministic PRNG, fictitious numbers only).
//!
//! Written from general knowledge of national numbering plans and of how
//! applications store contact data, independently of the dev seed and of
//! any held-out corpus: national and international formats of FR, DE, UK,
//! BE, CH, ES, IT, NL, US / CA, E.164, extensions, numbers in prose, mixed
//! "e-mail or phone" contact columns, sparse columns with empty, `NULL` and
//! junk values, under opaque or misleading names; and hard negatives (dial
//! codes, extensions, IMEI, EAN, ISBN, order and tracking numbers, SIREN /
//! SIRET, IBAN, cards, timestamps, epochs, prices, signed decimals and
//! coordinates, versions, postcodes, IP addresses, UUIDs, git SHAs).
//!
//! Every case must be decided correctly. Run with `--nocapture` to see the
//! misclassified cases (labels and counts only, never a value).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::print_stderr)]
#![allow(clippy::too_many_lines)]

use databastion_classifiers::column::classify_column;
use databastion_classifiers::masking::{ClassifierId as C, RawSample};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + u32::try_from(self.next() % u64::from(hi - lo + 1)).unwrap()
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
    fn chance(&mut self, pct: u32) -> bool {
        self.range(0, 99) < pct
    }
    fn digits(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'0' + u8::try_from(self.below(10)).unwrap()))
            .collect()
    }
    fn hex(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(*self.pick(b"0123456789abcdef")))
            .collect()
    }
}

type Gen = dyn Fn(&mut Rng) -> String;

fn pairs(r: &mut Rng, n: usize, sep: &str) -> String {
    (0..n).map(|_| r.digits(2)).collect::<Vec<_>>().join(sep)
}

// ----------------------------------------------------------- Phone formats

fn fr(r: &mut Rng, fmt: usize) -> String {
    let lead = *r.pick(&["1", "2", "3", "4", "5", "6", "7", "9"]);
    let mob = *r.pick(&["6", "7"]);
    match fmt {
        0 => format!("0{lead} {}", pairs(r, 4, " ")),
        1 => format!("0{lead}.{}", pairs(r, 4, ".")),
        2 => format!("0{lead}-{}", pairs(r, 4, "-")),
        3 => format!("0{mob}{}", r.digits(8)),
        4 => format!("+33 {mob} {}", pairs(r, 4, " ")),
        5 => format!("+33 (0){mob} {}", pairs(r, 4, " ")),
        6 => format!("0033 {mob} {}", pairs(r, 4, " ")),
        7 => format!("+33{mob}{}", r.digits(8)),
        8 => format!("0033{mob}{}", r.digits(8)),
        9 => format!("+33.{lead}.{}", pairs(r, 4, ".")),
        10 => format!("+33 {lead}{}", r.digits(8)),
        _ => format!("0{lead}{}", r.digits(8)),
    }
}
const FR_FORMATS: usize = 12;

fn de(r: &mut Rng) -> String {
    match r.below(7) {
        0 => format!("+49 30 {}", r.digits(8)),
        1 => format!("030 {}", r.digits(8)),
        2 => format!("0151 {}", r.digits(8)),
        3 => format!("030/{}", r.digits(7)),
        4 => format!("0171-{}", r.digits(7)),
        5 => format!("+49 (0)89 {}", r.digits(7)),
        _ => format!("+49 171 {}", r.digits(7)),
    }
}

fn uk(r: &mut Rng) -> String {
    match r.below(6) {
        0 => format!("020 7946 {}", r.digits(4)),
        1 => format!("07700 900{}", r.digits(3)),
        2 => format!("+44 7700 900{}", r.digits(3)),
        3 => format!("+44 (0)20 7946 {}", r.digits(4)),
        4 => format!("01632 960{}", r.digits(3)),
        _ => format!("+44 20 7946 {}", r.digits(4)),
    }
}

fn be(r: &mut Rng) -> String {
    match r.below(4) {
        0 => format!("02 {} {} {}", r.digits(3), r.digits(2), r.digits(2)),
        1 => format!("0470 {}", pairs(r, 3, " ")),
        2 => format!("+32 470 {}", pairs(r, 3, " ")),
        _ => format!("+32 2 {} {} {}", r.digits(3), r.digits(2), r.digits(2)),
    }
}

fn ch(r: &mut Rng) -> String {
    match r.below(3) {
        0 => format!("044 {} {} {}", r.digits(3), r.digits(2), r.digits(2)),
        1 => format!("079 {} {} {}", r.digits(3), r.digits(2), r.digits(2)),
        _ => format!("+41 79 {} {} {}", r.digits(3), r.digits(2), r.digits(2)),
    }
}

fn es(r: &mut Rng) -> String {
    match r.below(4) {
        0 => format!("6{} {}", r.digits(2), pairs(r, 3, " ")),
        1 => format!("+34 6{} {} {}", r.digits(2), r.digits(3), r.digits(3)),
        2 => format!("+34 91 {} {} {}", r.digits(3), r.digits(2), r.digits(2)),
        _ => format!("+34 6{}{}", r.digits(2), r.digits(6)),
    }
}

fn it(r: &mut Rng) -> String {
    match r.below(4) {
        0 => format!("3{} {} {}", r.digits(2), r.digits(3), r.digits(4)),
        1 => format!("06 {} {}", r.digits(4), r.digits(4)),
        2 => format!("+39 3{} {} {}", r.digits(2), r.digits(3), r.digits(4)),
        _ => format!("02 {}", r.digits(8)),
    }
}

fn nl(r: &mut Rng) -> String {
    match r.below(4) {
        0 => format!("020-{}", r.digits(7)),
        1 => format!("06-{}", r.digits(8)),
        2 => format!("06 {}", r.digits(8)),
        _ => format!("+31 6 {}", r.digits(8)),
    }
}

fn nanp(r: &mut Rng, fmt: usize) -> String {
    let area = r.range(201, 989);
    // Fictitious and real-looking exchanges, including `555` and exchanges
    // written by test-data generators without the NANP rules.
    let exch = if r.chance(50) { 555 } else { r.range(200, 999) };
    let line = r.digits(4);
    match fmt {
        0 => format!("({area}) {exch}-{line}"),
        1 => format!("{area}-{exch}-{line}"),
        2 => format!("{area}.{exch}.{line}"),
        3 => format!("+1 {area} {exch} {line}"),
        4 => format!("1-{area}-{exch}-{line}"),
        5 => format!("+1 ({area}) {exch}-{line}"),
        6 => format!("{area} {exch} {line}"),
        7 => format!("+1-{area}-{exch}-{line}"),
        8 => format!("({area}){exch}-{line}"),
        _ => format!("{area}-{exch}-{line}x{}", r.range(1, 9999)),
    }
}
const NANP_FORMATS: usize = 10;

fn e164(r: &mut Rng) -> String {
    let (cc, n) = *r.pick(&[
        ("33", 9),
        ("44", 10),
        ("49", 11),
        ("1", 10),
        ("34", 9),
        ("39", 10),
        ("31", 9),
        ("32", 9),
        ("41", 9),
        ("351", 9),
        ("48", 9),
        ("46", 9),
    ]);
    format!("+{cc}{}", r.digits(n))
}

/// Any phone number in any of the formats above.
fn any_phone(r: &mut Rng) -> String {
    match r.below(10) {
        0 | 1 => {
            let f = r.below(FR_FORMATS);
            fr(r, f)
        }
        2 => de(r),
        3 => uk(r),
        4 => be(r),
        5 => ch(r),
        6 => {
            if r.chance(50) {
                es(r)
            } else {
                it(r)
            }
        }
        7 => nl(r),
        8 => {
            let f = r.below(NANP_FORMATS);
            nanp(r, f)
        }
        _ => e164(r),
    }
}

/// A formatted (not compact) phone number.
fn formatted_phone(r: &mut Rng) -> String {
    loop {
        let p = any_phone(r);
        if p.contains([' ', '-', '.', '(', '/']) {
            return p;
        }
    }
}

fn with_ext(r: &mut Rng) -> String {
    let p = formatted_phone(r);
    let e = r.range(1, 9999);
    match r.below(5) {
        0 => format!("{p} x{e}"),
        1 => format!("{p} ext. {e}"),
        2 => format!("{p} poste {e}"),
        3 => format!("{p} ext {e}"),
        _ => format!("{p}, ext. {e}"),
    }
}

fn email(r: &mut Rng) -> String {
    let first = *r.pick(&[
        "jean", "marie", "paul", "anna", "lucas", "emma", "noah", "lea", "tom", "sara",
    ]);
    let last = *r.pick(&[
        "martin", "dupont", "smith", "muller", "rossi", "garcia", "jansen", "peeters",
    ]);
    let dom = *r.pick(&[
        "example.com",
        "example.org",
        "mail.example.fr",
        "example.net",
    ]);
    match r.below(3) {
        0 => format!("{first}.{last}@{dom}"),
        1 => format!("{first}{}@{dom}", r.range(1, 99)),
        _ => format!("{}{last}@{dom}", &first[..1]),
    }
}

// ------------------------------------------------------------------- Prose

fn prose_with_phone(r: &mut Rng, p: &str) -> String {
    let t = *r.pick(&[
        "Customer called, call back on {} before noon.",
        "Rappeler le client au {} demain matin.",
        "Contact: {}",
        "Please reach me at {} if the parcel is late.",
        "Nouveau numéro {} (ancien supprimé).",
        "Left a voicemail on {}.",
        "Merci de me recontacter au {}.",
        "Driver can be reached on {} for delivery.",
        "Numéro : {} / disponible après 18h",
        "Bitte unter {} zurückrufen.",
        "Llamar al {} por la tarde.",
        "Text {} when you arrive",
        "{} - leave a message",
        "Mr Dupont, {}, asked for a refund.",
        "Pour toute question : {}",
        "Tél.{} (bureau)",
        "Joignable au {} le matin.",
        "Emergency contact {}, wife",
    ]);
    t.replace("{}", p)
}

fn prose_plain(r: &mut Rng) -> String {
    let n = r.range(1, 999);
    let t = *r.pick(&[
        "Parcel delivered to reception.",
        "Customer asked for an invoice copy.",
        "Commande {} expédiée le 03/05/2024.",
        "Refund of {} EUR approved.",
        "Ticket #{} closed by support.",
        "Client absent, nouvelle livraison prévue.",
        "Order {} cancelled at 14:32.",
        "RAS",
        "Payment received, thanks.",
        "Colis endommagé, photo jointe.",
        "Version 2.{}.1 installed on the terminal.",
        "Meeting moved to 2024-06-{}.",
    ]);
    t.replace("{}", &n.to_string())
}

// ----------------------------------------------------------------- Columns

struct Case {
    label: String,
    name: String,
    values: Vec<String>,
    want: bool,
}

fn column(r: &mut Rng, n: usize, junk: u32, g: &Gen) -> Vec<String> {
    (0..n)
        .map(|_| {
            if r.chance(junk) {
                (*r.pick(&["", "NULL", "n/a", "-", "  ", "?", "none", "0"])).to_owned()
            } else {
                g(r)
            }
        })
        .collect()
}

const OPAQUE: &[&str] = &["col_7", "value", "data", "info", "c3", "field_12", "attr2"];

fn positives(r: &mut Rng, cases: &mut Vec<Case>) {
    let mut add = |r: &mut Rng, label: &str, name: &str, junk: u32, g: &Gen| {
        let values = column(r, 200, junk, g);
        cases.push(Case {
            label: label.to_owned(),
            name: name.to_owned(),
            values,
            want: true,
        });
    };
    for f in 0..FR_FORMATS {
        // Compact landlines and mobiles together (format 11) cannot be told
        // from zero-led customer numbers by their values: only under a
        // phone name (known limit).
        let name = if f == 11 { "tel" } else { *r.pick(OPAQUE) };
        add(r, &format!("fr format {f}"), name, 10, &move |r| fr(r, f));
    }
    for f in 0..NANP_FORMATS {
        let name = *r.pick(OPAQUE);
        add(r, &format!("nanp format {f}"), name, 10, &move |r| {
            nanp(r, f)
        });
    }
    add(r, "de", "col_1", 5, &de);
    add(r, "uk", "col_2", 5, &uk);
    add(r, "be", "col_3", 5, &be);
    add(r, "ch", "col_4", 5, &ch);
    add(r, "es", "col_5", 5, &es);
    add(r, "it", "col_6", 5, &it);
    add(r, "nl", "col_7", 5, &nl);
    add(r, "e164", "msisdn_x", 5, &e164);
    add(r, "e164 opaque", "k", 5, &e164);
    add(r, "any formatted", "c9", 20, &formatted_phone);
    add(r, "any, sparse 60% junk", "c10", 60, &any_phone);
    add(r, "with extensions", "reach", 5, &with_ext);
    add(r, "any under phone name", "phone", 5, &any_phone);
    add(
        r,
        "any under misleading name",
        "order_ref",
        5,
        &formatted_phone,
    );
    add(r, "compact fr mobile", "c11", 5, &|r| fr(r, 3));
    // Contact columns: e-mail or phone.
    for (i, share) in [50u32, 30, 70, 20].iter().enumerate() {
        let s = *share;
        add(
            r,
            &format!("email or phone {s}%"),
            ["contact", "login", "identifier", "c12"][i],
            5,
            &move |r| {
                if r.chance(s) { any_phone(r) } else { email(r) }
            },
        );
    }
    add(r, "email or compact fr mobile", "username", 5, &|r| {
        if r.chance(40) { fr(r, 3) } else { email(r) }
    });
    add(r, "email or e164", "contact_value", 5, &|r| {
        if r.chance(40) { e164(r) } else { email(r) }
    });
    // Free text.
    for (i, share) in [40u32, 20, 12, 8].iter().enumerate() {
        let s = *share;
        add(
            r,
            &format!("prose {s}% phones"),
            ["notes", "comment", "description", "c13"][i],
            5,
            &move |r| {
                if r.chance(s) {
                    let p = formatted_phone(r);
                    prose_with_phone(r, &p)
                } else {
                    prose_plain(r)
                }
            },
        );
    }
    add(r, "prose 15% any phone", "remarks", 5, &|r| {
        if r.chance(15) {
            let p = any_phone(r);
            prose_with_phone(r, &p)
        } else {
            prose_plain(r)
        }
    });
    add(r, "prose 10% nanp", "body", 5, &|r| {
        if r.chance(10) {
            let f = r.below(NANP_FORMATS);
            let p = nanp(r, f);
            prose_with_phone(r, &p)
        } else {
            prose_plain(r)
        }
    });
    add(r, "prose 10% fr pairs", "message", 5, &|r| {
        if r.chance(10) {
            let f = r.below(3);
            let p = fr(r, f);
            prose_with_phone(r, &p)
        } else {
            prose_plain(r)
        }
    });
    add(r, "json contact", "payload", 5, &|r| {
        let p = any_phone(r);
        let e = email(r);
        format!(r#"{{"email":"{e}","phone":"{p}"}}"#)
    });
    add(r, "csv contact", "line", 5, &|r| {
        let p = formatted_phone(r);
        let e = email(r);
        format!("Dupont;{e};{p}")
    });
    add(r, "multiple phones", "numbers", 5, &|r| {
        let a = formatted_phone(r);
        let b = formatted_phone(r);
        format!("{a} / {b}")
    });
}

fn negatives(r: &mut Rng, cases: &mut Vec<Case>) {
    let mut add = |r: &mut Rng, label: &str, name: &str, g: &Gen| {
        let values = column(r, 200, 5, g);
        cases.push(Case {
            label: label.to_owned(),
            name: name.to_owned(),
            values,
            want: false,
        });
    };
    add(r, "dial codes", "dial_code", &|r| {
        format!(
            "+{}",
            r.pick(&["33", "44", "49", "1", "32", "41", "351", "420"])
        )
    });
    add(r, "dial codes opaque", "c1", &|r| {
        format!(
            "+{}",
            r.pick(&["33", "44", "49", "1", "32", "41", "351", "420"])
        )
    });
    add(r, "extensions", "phone_extension", &|r| {
        r.range(1, 9999).to_string()
    });
    add(r, "extensions x", "c2", &|r| {
        format!("x{}", r.range(1, 9999))
    });
    add(r, "country codes", "phone_country", &|r| {
        (*r.pick(&["FR", "DE", "GB", "US", "BE", "CH"])).to_owned()
    });
    add(r, "imei", "c3", &|r| format!("35{}", r.digits(13)));
    add(r, "imei spaced", "device", &|r| {
        format!("35 {} {} {}", r.digits(6), r.digits(6), r.digits(1))
    });
    add(r, "ean13", "c4", &|r| {
        format!("{}{}", r.pick(&["3", "4", "5"]), r.digits(12))
    });
    add(r, "isbn", "c5", &|r| {
        format!(
            "978-{}-{}-{}-{}",
            r.digits(1),
            r.digits(4),
            r.digits(4),
            r.digits(1)
        )
    });
    add(r, "order numbers", "c6", &|r| {
        format!("ORD-{}-{}", r.range(2019, 2026), r.digits(6))
    });
    add(r, "order numbers digits", "c7", &|r| {
        format!("{}{}", r.range(1, 9), r.digits(9))
    });
    add(r, "order numbers zero padded", "c8", &|r| {
        format!("000{}", r.digits(7))
    });
    add(r, "tracking ups", "c9", &|r| {
        format!("1Z{}{}", r.digits(6), r.digits(10))
    });
    add(r, "tracking colissimo", "c10", &|r| {
        format!("6A{}", r.digits(11))
    });
    add(r, "tracking digits", "c11", &|r| r.digits(22));
    add(r, "siren", "c12", &|r| {
        format!("{} {} {}", r.digits(3), r.digits(3), r.digits(3))
    });
    add(r, "siren compact", "c13", &|r| {
        format!("{}{}", r.range(1, 9), r.digits(8))
    });
    add(r, "siret", "c14", &|r| {
        format!(
            "{} {} {} {}",
            r.digits(3),
            r.digits(3),
            r.digits(3),
            r.digits(5)
        )
    });
    add(r, "iban-like digits", "c15", &|r| {
        format!(
            "FR76 {} {} {} {} {} {}",
            r.digits(4),
            r.digits(4),
            r.digits(4),
            r.digits(4),
            r.digits(4),
            r.digits(3)
        )
    });
    add(r, "card-like", "c16", &|r| {
        format!(
            "4{} {} {} {}",
            r.digits(3),
            r.digits(4),
            r.digits(4),
            r.digits(4)
        )
    });
    add(r, "timestamps", "c17", &|r| {
        format!(
            "2024-{:02}-{:02} {:02}:{:02}:{:02}",
            r.range(1, 12),
            r.range(1, 28),
            r.range(0, 23),
            r.range(0, 59),
            r.range(0, 59)
        )
    });
    add(r, "timestamps iso tz", "c18", &|r| {
        format!(
            "2024-{:02}-{:02}T{:02}:{:02}:00+02:00",
            r.range(1, 12),
            r.range(1, 28),
            r.range(0, 23),
            r.range(0, 59)
        )
    });
    add(r, "epoch", "c19", &|r| {
        r.range(1_400_000_000, 1_800_000_000).to_string()
    });
    add(r, "epoch ms", "c20", &|r| {
        format!("{}{}", r.range(1_400_000_000, 1_800_000_000), r.digits(3))
    });
    add(r, "prices", "c21", &|r| {
        format!("{},{:02} €", r.range(1, 99_999), r.range(0, 99))
    });
    add(r, "prices thousands", "c22", &|r| {
        format!(
            "{} {:03} {:03},{:02}",
            r.range(1, 99),
            r.range(0, 999),
            r.range(0, 999),
            r.range(0, 99)
        )
    });
    add(r, "signed amounts", "c23", &|r| {
        format!(
            "{}{}.{:02}",
            r.pick(&["+", "-"]),
            r.range(100_000, 99_999_999),
            r.range(0, 99)
        )
    });
    add(r, "signed coordinates", "c24", &|r| {
        format!(
            "+{}.{}, +{}.{}",
            r.range(10, 60),
            r.digits(6),
            r.range(1, 9),
            r.digits(6)
        )
    });
    add(r, "signed latitudes", "c25", &|r| {
        format!("+{}.{}", r.range(10, 89), r.digits(7))
    });
    add(r, "versions", "c26", &|r| {
        format!("{}.{}.{}", r.range(0, 20), r.range(0, 99), r.range(0, 999))
    });
    add(r, "postcodes fr", "c27", &|r| {
        format!("{:05}", r.range(1000, 95999))
    });
    add(r, "postcodes with city", "c28", &|r| {
        format!("{:05} Paris", r.range(75001, 75020))
    });
    add(r, "ip addresses", "c29", &|r| {
        format!(
            "{}.{}.{}.{}",
            r.range(1, 223),
            r.range(0, 255),
            r.range(0, 255),
            r.range(1, 254)
        )
    });
    add(r, "uuids", "c30", &|r| {
        format!(
            "{}-{}-4{}-a{}-{}",
            r.hex(8),
            r.hex(4),
            r.hex(3),
            r.hex(3),
            r.hex(12)
        )
    });
    add(r, "git shas", "c31", &|r| r.hex(40));
    add(r, "short shas", "c32", &|r| r.hex(7));
    add(r, "dates fr", "c33", &|r| {
        format!(
            "{:02}/{:02}/{}",
            r.range(1, 28),
            r.range(1, 12),
            r.range(1990, 2026)
        )
    });
    add(r, "dates dotted", "c34", &|r| {
        format!(
            "{:02}.{:02}.{}",
            r.range(1, 28),
            r.range(1, 12),
            r.range(1990, 2026)
        )
    });
    add(r, "invoice refs", "c35", &|r| {
        format!("INV {} {}", r.range(2019, 2026), r.digits(5))
    });
    add(r, "sort codes", "c36", &|r| {
        format!("{}-{}-{}", r.digits(2), r.digits(2), r.digits(2))
    });
    add(r, "ssn-like", "c37", &|r| {
        format!("{}-{}-{}", r.digits(3), r.digits(2), r.digits(4))
    });
    add(r, "account numbers", "c38", &|r| {
        format!("0{}", r.digits(10))
    });
    add(r, "log lines", "c39", &|r| {
        format!(
            "2024-05-{:02} {:02}:{:02}:{:02} INFO request {} took {} ms",
            r.range(1, 28),
            r.range(0, 23),
            r.range(0, 59),
            r.range(0, 59),
            r.hex(8),
            r.range(1, 5000)
        )
    });
    add(r, "prose without phones", "notes", &prose_plain);
    add(r, "emails only", "c40", &email);
    add(r, "durations", "c41", &|r| {
        format!(
            "{:02}:{:02}:{:02}",
            r.range(0, 99),
            r.range(0, 59),
            r.range(0, 59)
        )
    });
    add(r, "mac addresses", "c42", &|r| {
        (0..6).map(|_| r.hex(2)).collect::<Vec<_>>().join(":")
    });
    add(r, "quantities", "c43", &|r| {
        r.range(0, 1_000_000).to_string()
    });
    add(r, "phone models", "c44", &|r| {
        format!(
            "{} {}",
            r.pick(&["iPhone", "Galaxy S", "Pixel", "Xperia"]),
            r.range(5, 24)
        )
    });
    add(r, "spaced ids 4-4-4", "c45", &|r| {
        format!("{} {} {}", r.digits(4), r.digits(4), r.digits(4))
    });
    add(r, "barcode spaced", "c46", &|r| {
        format!("3 {} {}", r.digits(6), r.digits(6))
    });
    add(r, "numbered lists", "c47", &|r| {
        format!(
            "Items {}, {}, {} and {}",
            r.range(1, 99),
            r.range(1, 99),
            r.range(1, 99),
            r.range(1, 99)
        )
    });
    add(r, "hs codes", "c48", &|r| {
        format!("{}.{}.{}", r.digits(4), r.digits(2), r.digits(2))
    });
    add(r, "part numbers", "c49", &|r| {
        format!("0{}-{}-{}", r.digits(2), r.digits(3), r.digits(3))
    });
    add(r, "prose with codes and amounts", "comment", &|r| {
        let n = r.digits(6);
        let t = *r.pick(&[
            "Commande n° 2024-{} expédiée.",
            "SIRET 552 100 554 {} vérifié.",
            "Colis 6A{}12345 remis au transporteur.",
            "Montant 1 234,56 EUR réglé, facture {}.",
            "Réf. 0{}123 à rappeler au service compta.",
            "Build 4.2.{} deployed on 10.0.12.34 at 12:34:56.",
            "Livraison le 03 05 2024, ticket {}.",
            "Batch {} processed in 1234 ms, 567 890 rows.",
            "IBAN FR76 3000 6000 0112 3456 7890 189 enregistré ({}).",
            "Lot {} - 2 x 250 g - DLC 12/06/2025",
        ]);
        t.replace("{}", &n)
    });
    add(r, "emails or user ids", "login", &|r| {
        if r.chance(50) {
            email(r)
        } else {
            format!("u{}", r.digits(6))
        }
    });
    add(r, "emails or zero-led ids", "c50", &|r| {
        if r.chance(50) {
            email(r)
        } else {
            format!("0{}", r.digits(9))
        }
    });
    add(r, "hex with x", "c51", &|r| format!("0x{}", r.hex(8)));
    add(r, "gtin14", "c52", &|r| format!("000{}", r.digits(11)));
    add(r, "gtin14 in text", "c53", &|r| {
        format!("Item 000{} restocked (lot {}).", r.digits(11), r.digits(4))
    });
    add(r, "serials in text", "c54", &|r| {
        format!(
            "S/N 0{} {} {} returned under warranty",
            r.digits(3),
            r.digits(4),
            r.digits(2)
        )
    });
    add(r, "schedules in text", "c55", &|r| {
        format!(
            "Ouvert de {:02} {:02} à {:02} {:02}, le {:02} {:02} {}",
            r.range(7, 9),
            r.range(0, 59),
            r.range(12, 19),
            r.range(0, 59),
            r.range(1, 28),
            r.range(1, 12),
            r.range(2020, 2026)
        )
    });
    add(r, "appellations", "c56", &|r| {
        format!("Appellation contrôlée, lot 0{}", r.digits(9))
    });
    add(r, "isbn10", "c57", &|r| {
        format!("0-{}-{}-{}", r.digits(3), r.digits(5), r.digits(1))
    });
    add(r, "numbers in reports", "c58", &|r| {
        format!(
            "Q{} revenue {} {:03} {:03} EUR, {} customers, {}% growth",
            r.range(1, 4),
            r.range(1, 99),
            r.range(0, 999),
            r.range(0, 999),
            r.range(100, 99_999),
            r.range(1, 40)
        )
    });
    add(r, "phone verified flags", "phone_verified", &|r| {
        (*r.pick(&["true", "false"])).to_owned()
    });
}

#[test]
fn phone_columns_are_decided_correctly() {
    let mut r = Rng(0x5eed_0bad_f00d_0001);
    let mut cases = Vec::new();
    positives(&mut r, &mut cases);
    negatives(&mut r, &mut cases);
    let mut wrong = Vec::new();
    let (mut tp, mut fneg, mut fpos, mut tn) = (0, 0, 0, 0);
    for c in &cases {
        let raws: Vec<RawSample<'_>> = c.values.iter().map(|v| RawSample::new(v)).collect();
        let found = classify_column(&c.name, &raws);
        let phone = found.iter().find(|f| f.classifier() == C::Phone);
        let got = phone.is_some();
        match (c.want, got) {
            (true, true) => tp += 1,
            (true, false) => fneg += 1,
            (false, true) => fpos += 1,
            (false, false) => tn += 1,
        }
        if got != c.want {
            wrong.push(format!(
                "{} {} (name {}, matched {})",
                if c.want { "MISSED" } else { "FALSE+" },
                c.label,
                c.name,
                phone.map_or(0, |f| f.matched())
            ));
        }
    }
    eprintln!("pii.phone: tp {tp} fn {fneg} fp {fpos} tn {tn}");
    for w in &wrong {
        eprintln!("  {w}");
    }
    assert!(wrong.is_empty(), "{} misclassified columns", wrong.len());
}
