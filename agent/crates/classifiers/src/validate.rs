//! Checksum and structure validators used by the detectors.
//!
//! Pure functions on already-extracted candidates; they never log and never
//! keep their input.

/// Luhn check on a string of ASCII digits.
#[must_use]
pub fn luhn_valid(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, b) in digits.bytes().rev().enumerate() {
        let mut d = u32::from(b - b'0');
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

/// Whether a card number (ASCII digits) has a plausible length and a known
/// issuer prefix (Visa, Mastercard, American Express, Discover, JCB,
/// Diners Club, UnionPay, Maestro). Random 13–19 digit numbers that happen
/// to pass Luhn but start with another prefix (e.g. `9…` references) are
/// rejected.
#[must_use]
pub fn card_prefix_valid(digits: &str) -> bool {
    let len = digits.len();
    if !(13..=19).contains(&len) {
        return false;
    }
    let p = |n: usize| digits.get(..n).and_then(|s| s.parse::<u32>().ok());
    let (Some(p1), Some(p2), Some(p3), Some(p4), Some(p6)) = (p(1), p(2), p(3), p(4), p(6)) else {
        return false;
    };
    match p1 {
        // Visa
        4 => matches!(len, 13 | 16 | 19),
        // Mastercard 51-55, 2221-2720
        5 if (51..=55).contains(&p2) => len == 16,
        2 if (2221..=2720).contains(&p4) => len == 16,
        // Maestro 50, 56-58
        5 if p2 == 50 || (56..=58).contains(&p2) => len >= 12,
        // Amex 34 / 37
        3 if p2 == 34 || p2 == 37 => len == 15,
        // JCB 3528-3589
        3 if (3528..=3589).contains(&p4) => len >= 16,
        // Diners 300-305, 36, 38, 39
        3 if (300..=305).contains(&p3) || matches!(p2, 36 | 38 | 39) => len >= 14,
        // Discover 6011, 644-649, 65; UnionPay 62; Maestro 6304, 67
        6 => {
            p4 == 6011
                || (644..=649).contains(&p3)
                || p2 == 65
                || p2 == 62
                || p2 == 67
                || p4 == 6304
                || (622_126..=622_925).contains(&p6)
        }
        _ => false,
    }
}

/// IBAN length per country (ISO 13616 registry, SWIFT release 2024).
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BR", 29),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NL", 18),
    ("NO", 15),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("SA", 24),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VG", 24),
    ("XK", 20),
];

/// Expected IBAN length for a country code, if the country uses IBANs.
#[must_use]
pub fn iban_length(country: &str) -> Option<usize> {
    IBAN_LENGTHS
        .iter()
        .find(|(c, _)| *c == country)
        .map(|(_, l)| *l)
}

/// Full IBAN check on a compact, uppercase candidate: country length and
/// ISO 7064 mod 97-10.
#[must_use]
pub fn iban_valid(compact: &str) -> bool {
    let b = compact.as_bytes();
    if b.len() < 15
        || !b
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        || !b[..2].iter().all(u8::is_ascii_uppercase)
        || !b[2..4].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let Some(country) = compact.get(..2) else {
        return false;
    };
    if iban_length(country) != Some(b.len()) {
        return false;
    }
    let mut rem = 0u32;
    for &c in b[4..].iter().chain(&b[..4]) {
        let v = if c.is_ascii_digit() {
            u32::from(c - b'0')
        } else {
            u32::from(c - b'A') + 10
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

/// French NIR check on a compact candidate (15 characters: 13 digits, with
/// `2A` / `2B` allowed for Corsica, then a 2-digit key):
/// sex `1` / `2`, a plausible month, and key `97 - (n mod 97)`.
#[must_use]
pub fn nir_valid(compact: &str) -> bool {
    let b = compact.as_bytes();
    if b.len() != 15 || !compact.is_ascii() || !matches!(b[0], b'1' | b'2') {
        return false;
    }
    let Ok(month) = compact[3..5].parse::<u32>() else {
        return false;
    };
    // 01-12, 20-42 (unknown month codes) and 50-99 (provisional registration).
    if !((1..=12).contains(&month) || (20..=42).contains(&month) || month >= 50) {
        return false;
    }
    // Corsica: 2A -> 19, 2B -> 18 for the key computation.
    let dept = &compact[5..7];
    let body = match dept {
        "2A" => format!("{}19{}", &compact[..5], &compact[7..13]),
        "2B" => format!("{}18{}", &compact[..5], &compact[7..13]),
        _ => compact[..13].to_owned(),
    };
    if !body.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let (Ok(n), Ok(key)) = (body.parse::<u64>(), compact[13..].parse::<u64>()) else {
        return false;
    };
    (1..=97).contains(&key) && 97 - n % 97 == key
}

/// Whether `(year, month, day)` is a real calendar date within the
/// plausible birth range `1900-01-01..=2030-12-31`. Fixed bounds keep the
/// classifier deterministic; they are revised with [`crate::id::CLASSIFIERS_VERSION`].
#[must_use]
pub fn birth_date_valid(year: u32, month: u32, day: u32) -> bool {
    if !(1900..=2030).contains(&year) || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= max
}

/// Structural e-mail check on an extracted candidate: one `@`, local part
/// 1..=64 without leading / trailing / double dots, domain labels 1..=63
/// without leading / trailing hyphen, alphabetic TLD of 2+ characters,
/// total length ≤ 254.
#[must_use]
pub fn email_valid(candidate: &str) -> bool {
    if candidate.len() > 254 {
        return false;
    }
    let Some((local, domain)) = candidate.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.contains('@')
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let labels_ok = labels
        .iter()
        .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'));
    let tld_ok = labels
        .last()
        .is_some_and(|t| t.chars().count() >= 2 && t.chars().all(char::is_alphabetic));
    labels_ok && tld_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn() {
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("5555555555554444"));
        assert!(luhn_valid("378282246310005"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid(""));
        assert!(!luhn_valid("4111a11111111111"));
    }

    #[test]
    fn card_prefixes() {
        assert!(card_prefix_valid("4111111111111111"));
        assert!(card_prefix_valid("5555555555554444"));
        assert!(card_prefix_valid("2223003122003222"));
        assert!(card_prefix_valid("378282246310005"));
        assert!(card_prefix_valid("6011111111111117"));
        assert!(!card_prefix_valid("9111111111111111"));
        assert!(!card_prefix_valid("1111111111111111"));
        assert!(!card_prefix_valid("411111111111"));
        assert!(!card_prefix_valid("37828224631000"));
    }

    #[test]
    fn iban() {
        assert!(iban_valid("FR7630006000011234567890189"));
        assert!(iban_valid("DE89370400440532013000"));
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(iban_valid("NO9386011117947"));
        // Wrong check digits, wrong length, unknown country, lowercase.
        assert!(!iban_valid("FR7630006000011234567890180"));
        assert!(!iban_valid("DE8937040044053201300"));
        assert!(!iban_valid("ZZ89370400440532013000"));
        assert!(!iban_valid("fr7630006000011234567890189"));
        assert!(!iban_valid("DE"));
    }

    #[test]
    fn nir() {
        // Key = 97 - (1850578006048 mod 97) = 38... computed below.
        let body = "1850578006048";
        let key = 97 - body.parse::<u64>().unwrap_or(0) % 97;
        let valid = format!("{body}{key:02}");
        assert!(nir_valid(&valid));
        let wrong = format!("{body}{:02}", (key % 97) + 1);
        assert!(!nir_valid(&wrong));
        // Corsica.
        let body = "18505";
        let rest = "006048";
        let n: u64 = format!("{body}19{rest}").parse().unwrap_or(0);
        let corsica = format!("{body}2A{rest}{:02}", 97 - n % 97);
        assert!(nir_valid(&corsica));
        // Sex digit, month, length.
        assert!(!nir_valid(&format!("3{}", &valid[1..])));
        assert!(!nir_valid(&format!("{}13{}", &valid[..3], &valid[5..])));
        assert!(!nir_valid("18505"));
    }

    #[test]
    fn birth_dates() {
        assert!(birth_date_valid(1980, 2, 29));
        assert!(birth_date_valid(2000, 2, 29));
        assert!(!birth_date_valid(1900, 2, 29));
        assert!(!birth_date_valid(1981, 2, 29));
        assert!(!birth_date_valid(1980, 4, 31));
        assert!(!birth_date_valid(1899, 12, 31));
        assert!(!birth_date_valid(2031, 1, 1));
        assert!(!birth_date_valid(1980, 13, 1));
        assert!(!birth_date_valid(1980, 1, 0));
    }

    #[test]
    fn emails() {
        assert!(email_valid("jane.doe@example.com"));
        assert!(email_valid("aiden.garcía@example.org"));
        assert!(email_valid("a+tag@sub.example.co"));
        assert!(!email_valid(".jane@example.com"));
        assert!(!email_valid("jane..doe@example.com"));
        assert!(!email_valid("jane@example"));
        assert!(!email_valid("jane@-example.com"));
        assert!(!email_valid("jane@example.c0m"));
        assert!(!email_valid("jane@@example.com"));
    }
}
