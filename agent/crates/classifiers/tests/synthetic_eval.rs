//! Column-level recall / precision on synthetic labeled columns generated
//! in code (deterministic PRNG, fake values only): every classifier in many
//! value formats and column-name styles (descriptive, camelCase,
//! PascalCase, UPPER, flat, innocent, opaque, misleading), sparse columns,
//! placeholders, free text, and hard negatives (values that look sensitive
//! but are not).
//!
//! Independent of the dev seed: the pools below are general knowledge of
//! naming and formatting conventions. Run with `--nocapture` to see the
//! per-classifier table and the misclassified cases (case labels only).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::print_stderr)]
#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;

use databastion_classifiers::column::classify_column;
use databastion_classifiers::masking::{ClassifierId as C, RawSample};
use unicode_normalization::UnicodeNormalization;

// ------------------------------------------------------------------ PRNG

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
    fn chars(&mut self, n: usize, set: &[u8]) -> String {
        (0..n).map(|_| char::from(*self.pick(set))).collect()
    }
}

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALNUM_UP: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const CRYPT: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";

// ------------------------------------------------------------- Checksums

fn luhn_complete(partial: &str) -> String {
    (0..10)
        .map(|d| format!("{partial}{d}"))
        .find(|n| {
            let mut sum = 0;
            for (i, b) in n.bytes().rev().enumerate() {
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
        })
        .unwrap()
}

fn mod97(s: &str) -> u32 {
    let mut r = 0u32;
    for c in s.chars() {
        let v = c.to_digit(36).unwrap();
        r = if v >= 10 {
            (r * 100 + v) % 97
        } else {
            (r * 10 + v) % 97
        };
    }
    r
}

fn iban(rng: &mut Rng, valid: bool) -> String {
    let (cc, bban) = match rng.below(14) {
        0 => ("FR", format!("{}{}", rng.digits(10), rng.digits(13))),
        1 => ("DE", rng.digits(18)),
        2 => ("GB", format!("{}{}", rng.chars(4, UPPER), rng.digits(14))),
        3 => ("ES", rng.digits(20)),
        4 => ("IT", format!("{}{}", rng.chars(1, UPPER), rng.digits(22))),
        5 => ("NL", format!("{}{}", rng.chars(4, UPPER), rng.digits(10))),
        6 => ("BE", rng.digits(12)),
        7 => ("CH", rng.digits(17)),
        8 => ("PT", rng.digits(21)),
        9 => ("AT", rng.digits(16)),
        10 => ("PL", rng.digits(24)),
        11 => ("IE", format!("{}{}", rng.chars(4, UPPER), rng.digits(14))),
        12 => (
            "LU",
            format!("{}{}", rng.digits(3), rng.chars(13, ALNUM_UP)),
        ),
        _ => ("SE", rng.digits(20)),
    };
    let check = 98 - mod97(&format!("{bban}{cc}00"));
    let check = if valid {
        check
    } else {
        (check + 1 + rng.range(0, 90)) % 97 + 2
    };
    format!("{cc}{check:02}{bban}")
}

fn group(s: &str, n: usize, sep: &str) -> String {
    s.as_bytes()
        .chunks(n)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(sep)
}

fn nir(rng: &mut Rng, valid: bool) -> String {
    let sex = rng.range(1, 2);
    let yy = rng.range(0, 99);
    let mm = rng.range(1, 12);
    let dept = if rng.chance(8) {
        if rng.chance(50) { "2A" } else { "2B" }.to_owned()
    } else {
        format!("{:02}", rng.range(1, 95))
    };
    let rest = format!("{}{}", rng.digits(3), rng.digits(3));
    let numeric_dept = match dept.as_str() {
        "2A" => "19".to_owned(),
        "2B" => "18".to_owned(),
        d => d.to_owned(),
    };
    let body: u64 = format!("{sex}{yy:02}{mm:02}{numeric_dept}{rest}")
        .parse()
        .unwrap();
    let key = 97 - body % 97;
    let key = if valid { key } else { key % 97 + 1 };
    format!("{sex}{yy:02}{mm:02}{dept}{rest}{key:02}")
}

fn card(rng: &mut Rng) -> String {
    match rng.below(9) {
        0 | 1 => luhn_complete(&format!("4{}", rng.digits(14))),
        2 => luhn_complete(&format!("5{}{}", rng.range(1, 5), rng.digits(13))),
        3 => luhn_complete(&format!("{}{}", rng.range(2221, 2720), rng.digits(11))),
        4 => luhn_complete(&format!(
            "3{}{}",
            if rng.chance(50) { 4 } else { 7 },
            rng.digits(12)
        )),
        5 => luhn_complete(&format!("6011{}", rng.digits(11))),
        6 => luhn_complete(&format!("35{}{}", rng.range(28, 89), rng.digits(11))),
        7 => luhn_complete(&format!("62{}", rng.digits(16))),
        _ => luhn_complete(&format!("4{}", rng.digits(17))),
    }
}

// ----------------------------------------------------------- Name pools

const FIRST: &[&str] = &[
    "Jean",
    "Marie",
    "Pierre",
    "Sophie",
    "Nicolas",
    "Camille",
    "Julien",
    "Chloé",
    "Antoine",
    "Manon",
    "Thomas",
    "Léa",
    "Hugo",
    "Inès",
    "Émile",
    "Margaux",
    "Baptiste",
    "Océane",
    "James",
    "Mary",
    "Robert",
    "Patricia",
    "Michael",
    "Linda",
    "William",
    "Barbara",
    "David",
    "Susan",
    "Joseph",
    "Jessica",
    "Charles",
    "Sarah",
    "Daniel",
    "Karen",
    "Matthew",
    "Nancy",
    "Lukas",
    "Anna",
    "Felix",
    "Hannah",
    "Jonas",
    "Lena",
    "Maximilian",
    "Katharina",
    "Moritz",
    "Giulia",
    "Luca",
    "Francesca",
    "Matteo",
    "Chiara",
    "Alessandro",
    "Sofia",
    "Lorenzo",
    "Carlos",
    "Lucía",
    "Javier",
    "Carmen",
    "Alejandro",
    "Pilar",
    "Diego",
    "Isabel",
    "Mateo",
    "Sven",
    "Ingrid",
    "Lars",
    "Astrid",
    "Piotr",
    "Katarzyna",
    "Tomasz",
    "Agnieszka",
    "Mohamed",
    "Fatima",
    "Youssef",
    "Amina",
    "Karim",
    "Leila",
    "Mehmet",
    "Ayşe",
    "Arjun",
    "Priya",
    "Wei",
    "Mei",
    "Hiroshi",
    "Yuki",
    "Oluwaseun",
    "Chiamaka",
    "Siobhan",
    "Ciarán",
    "Bartholomew",
    "Gwendolyn",
    "Thaddeus",
    "Philippa",
    "Leopold",
    "Rosalind",
    "Cornelius",
    "Evangeline",
    "Aurélien",
    "Clothilde",
    "Gaëtan",
    "Ségolène",
    "Wolfgang",
    "Brunhilde",
    "Ottavio",
    "Rocío",
];

const LAST: &[&str] = &[
    "Martin",
    "Bernard",
    "Dubois",
    "Durand",
    "Lefebvre",
    "Moreau",
    "Laurent",
    "Fournier",
    "Girard",
    "Rousseau",
    "Blanchard",
    "Chevalier",
    "Faure",
    "Mercier",
    "Leclerc",
    "Gauthier",
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Miller",
    "Davis",
    "Wilson",
    "Anderson",
    "Taylor",
    "Thompson",
    "Harris",
    "Clark",
    "Lewis",
    "Robinson",
    "Walker",
    "Mitchell",
    "Müller",
    "Schmidt",
    "Schneider",
    "Fischer",
    "Weber",
    "Wagner",
    "Becker",
    "Hoffmann",
    "Rossi",
    "Russo",
    "Ferrari",
    "Esposito",
    "Bianchi",
    "Romano",
    "Colombo",
    "Ricci",
    "García",
    "Fernández",
    "González",
    "Rodríguez",
    "López",
    "Martínez",
    "Sánchez",
    "Pérez",
    "Andersson",
    "Johansson",
    "Nilsson",
    "Kowalski",
    "Nowak",
    "Wiśniewska",
    "Novák",
    "Papadopoulos",
    "Popescu",
    "Ivanova",
    "Petrov",
    "Yılmaz",
    "Kaya",
    "Nguyen",
    "Tran",
    "Wang",
    "Li",
    "Tanaka",
    "Suzuki",
    "Sharma",
    "Patel",
    "Okafor",
    "O'Brien",
    "McDonald",
    "Van der Berg",
    "De Vries",
    "Da Silva",
    "Pereira",
    "Ferreira",
    "Haddad",
    "Benali",
    "Kowalczyk",
    "Lindqvist",
    "Fitzgerald",
    "Vasquez",
    "Delacroix",
    "Beaumont",
    "Villeneuve",
    "Thibodeaux",
    "Kerouac",
    "Abernathy",
    "Winterbottom",
    "Throckmorton",
    "Quackenbush",
];

const RARE_FIRST: &[&str] = &[
    "Ottoline",
    "Peregrine",
    "Zebulon",
    "Ignatia",
    "Florizel",
    "Amaranthe",
    "Quirin",
    "Ysolde",
    "Barnaby",
    "Clementine",
    "Leocadie",
    "Ambroise",
    "Philibert",
    "Eulalie",
    "Anatole",
    "Hortense",
    "Casimir",
    "Honorine",
    "Evariste",
    "Radegonde",
    "Tancrède",
    "Wilhelmina",
    "Isidore",
    "Octavie",
];
const RARE_LAST: &[&str] = &[
    "Pemberton",
    "Ravenscroft",
    "Oakenshield",
    "Blackwood-Tate",
    "Castellane",
    "Montgolfier",
    "Vauquelin",
    "Brassens",
    "Lagardère",
    "Quenneville",
    "Trouvé",
    "Achterberg",
    "Zwanziger",
    "Kleinschmidt",
    "Ostrowski",
    "Balthazar",
    "Esterházy",
    "Fairweather",
    "Hollingsworth",
    "Marchetti",
    "Villalobos",
    "Arrieta",
    "Sundqvist",
    "Haraldsen",
];

const PARTICLE_LAST: &[&str] = &[
    "de la Fontaine",
    "de Villiers",
    "van den Bosch",
    "von Stein",
    "di Stefano",
    "del Rio",
    "d'Arcy",
    "Le Gall",
    "de Oliveira",
    "da Costa",
];

fn person(rng: &mut Rng, fmt: usize) -> String {
    // One name in four from pools no lexicon is likely to hold.
    let f = if rng.chance(25) {
        *rng.pick(RARE_FIRST)
    } else {
        *rng.pick(FIRST)
    };
    let l = if rng.chance(25) {
        *rng.pick(RARE_LAST)
    } else {
        *rng.pick(LAST)
    };
    match fmt {
        0 => format!("{f} {l}"),
        1 => format!("{} {f}", l.to_uppercase()),
        2 => format!("{l}, {f}"),
        3 => format!("{f} {l}").to_uppercase(),
        4 => f.to_owned(),
        5 => l.to_owned(),
        6 => {
            let m = *rng.pick(FIRST);
            if rng.chance(50) {
                format!("{f} {}. {l}", m.chars().next().unwrap_or('J'))
            } else {
                format!("{f}-{m} {l}")
            }
        }
        7 => {
            let t = *rng.pick(&["Mr.", "Mrs.", "Ms.", "Dr", "M.", "Mme", "Mlle", "Prof."]);
            format!("{t} {f} {l}")
        }
        8 => format!("{f} {}", rng.pick(PARTICLE_LAST)),
        _ => format!("{f} {l}-{}", rng.pick(LAST)),
    }
}

// --------------------------------------------------------- Birth dates

const MONTHS_EN: &[&str] = &[
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const MONTHS_FR: &[&str] = &[
    "janvier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "décembre",
];

fn ymd(rng: &mut Rng, y0: u32, y1: u32) -> (u32, u32, u32) {
    let y = rng.range(y0, y1);
    let m = rng.range(1, 12);
    let d = rng.range(1, 28);
    (y, m, d)
}

fn date_fmt(fmt: usize, (y, m, d): (u32, u32, u32), rng: &mut Rng) -> String {
    match fmt {
        0 => format!("{y}-{m:02}-{d:02}"),
        1 => format!("{d:02}/{m:02}/{y}"),
        2 => format!("{m:02}/{d:02}/{y}"),
        3 => format!("{d:02}.{m:02}.{y}"),
        4 => {
            let mn = MONTHS_EN[m as usize - 1];
            if rng.chance(50) {
                format!("{d} {mn} {y}")
            } else {
                format!("{mn} {d}, {y}")
            }
        }
        5 => format!("{d} {} {y}", MONTHS_FR[m as usize - 1]),
        6 => match rng.below(3) {
            0 => format!("{y}-{m:02}-{d:02} 00:00:00"),
            1 => format!("{y}-{m:02}-{d:02}T00:00:00Z"),
            _ => format!("{y}-{m:02}-{d:02}T00:00:00.000+00:00"),
        },
        7 => format!("{y}{m:02}{d:02}"),
        8 => format!("{d:02}-{m:02}-{y}"),
        9 => format!("{y}/{m:02}/{d:02}"),
        10 => format!("{d}-{}-{y}", &MONTHS_EN[m as usize - 1][..3]),
        11 => format!("{m}/{d}/{y}"),
        12 => format!(
            "{}, {} {d}, {y}",
            rng.pick(&["Monday", "Tuesday", "Saturday"]),
            MONTHS_EN[m as usize - 1]
        ),
        13 => format!("{y}-{m:02}-{d:02}T00:00:00+0200"),
        14 => format!(
            "{y}-{m:02}-{d:02} {:02}:{:02}:{:02}",
            rng.range(0, 23),
            rng.range(0, 59),
            rng.range(0, 59)
        ),
        _ => format!("{d}/{m}/{y}"),
    }
}

// ------------------------------------------------------------ Addresses

const FR_STREETS: &[&str] = &[
    "rue de la Paix",
    "avenue Victor Hugo",
    "bd Haussmann",
    "boulevard Voltaire",
    "allée des Tilleuls",
    "impasse du Moulin",
    "chemin des Vignes",
    "place de la République",
    "quai de la Tournelle",
    "route de Lyon",
    "av. Jean Jaurès",
    "rue du Faubourg Saint-Antoine",
    "cours Mirabeau",
    "rue Pasteur",
    "square Montholon",
];
const FR_CITIES: &[(&str, &str)] = &[
    ("75002", "Paris"),
    ("69003", "Lyon"),
    ("13006", "Marseille"),
    ("31000", "Toulouse"),
    ("33000", "Bordeaux"),
    ("59000", "Lille"),
    ("44000", "Nantes"),
    ("67000", "Strasbourg"),
];
const EN_STREETS: &[&str] = &[
    "Main St",
    "Oak Avenue",
    "Maple Street",
    "Elm Rd",
    "Park Lane",
    "Baker Street",
    "Sunset Blvd",
    "Cedar Drive",
    "Highland Ave",
    "Church Road",
    "Mill Lane",
    "5th Avenue",
    "Pine Court",
    "Lakeview Terrace",
    "King's Road",
];
const US_CITIES: &[(&str, &str, &str)] = &[
    ("Springfield", "IL", "62701"),
    ("Austin", "TX", "73301"),
    ("Denver", "CO", "80202"),
    ("Portland", "OR", "97201"),
    ("Boston", "MA", "02108"),
    ("Seattle", "WA", "98101"),
];
const UK: &[(&str, &str)] = &[
    ("London", "NW1 6XE"),
    ("Manchester", "M1 1AE"),
    ("Leeds", "LS1 4AP"),
    ("Bristol", "BS1 5TR"),
];
const DE_STREETS: &[&str] = &[
    "Hauptstraße",
    "Bahnhofstr.",
    "Gartenweg",
    "Schillerplatz",
    "Lindenallee",
    "Goethestraße",
    "Kirchgasse",
];
const DE_CITIES: &[(&str, &str)] = &[
    ("10115", "Berlin"),
    ("80331", "München"),
    ("20095", "Hamburg"),
    ("50667", "Köln"),
];
const NL_STREETS: &[&str] = &[
    "Kerkstraat",
    "Dorpsstraat",
    "Stationsweg",
    "Molenlaan",
    "Prinsengracht",
];
const LATIN_STREETS: &[&str] = &[
    "Via Roma",
    "Via Garibaldi",
    "Corso Italia",
    "Piazza Navona",
    "Calle Mayor",
    "Avenida de la Constitución",
    "Calle de Alcalá",
    "Rua Augusta",
    "Paseo de Gracia",
];

fn address(rng: &mut Rng, fmt: usize) -> String {
    let no = rng.range(1, 250);
    match fmt {
        0 => format!("{no} {}", rng.pick(FR_STREETS)),
        1 => {
            let (pc, c) = *rng.pick(FR_CITIES);
            let bis = if rng.chance(20) { " bis" } else { "" };
            format!("{no}{bis} {}, {pc} {c}", rng.pick(FR_STREETS))
        }
        2 => {
            let (pc, c) = *rng.pick(FR_CITIES);
            format!("{no} {}\n{pc} {}", rng.pick(FR_STREETS), c.to_uppercase())
        }
        3 => {
            let (c, s, z) = *rng.pick(US_CITIES);
            let apt = if rng.chance(30) {
                format!(" Apt {}", rng.range(1, 30))
            } else {
                String::new()
            };
            format!("{no} {}{apt}, {c}, {s} {z}", rng.pick(EN_STREETS))
        }
        4 => {
            let (c, pc) = *rng.pick(UK);
            format!(
                "{no}{} {}, {c} {pc}",
                if rng.chance(30) { "B" } else { "" },
                rng.pick(EN_STREETS)
            )
        }
        5 => {
            let (pc, c) = *rng.pick(DE_CITIES);
            format!("{} {no}, {pc} {c}", rng.pick(DE_STREETS))
        }
        6 => format!(
            "{} {no}, {} {} Amsterdam",
            rng.pick(NL_STREETS),
            rng.range(1000, 1099),
            rng.chars(2, UPPER)
        ),
        7 => format!(
            "{} {no}, {} {}",
            rng.pick(LATIN_STREETS),
            rng.digits(5),
            rng.pick(&["Roma", "Madrid", "Milano", "Sevilla"])
        ),
        8 => {
            if rng.chance(50) {
                let (c, s, z) = *rng.pick(US_CITIES);
                format!("PO Box {}, {c}, {s} {z}", rng.range(10, 9999))
            } else {
                let (pc, c) = *rng.pick(FR_CITIES);
                format!("BP {} {pc} {c}", rng.range(10, 999))
            }
        }
        9 => {
            let (pc, c) = *rng.pick(FR_CITIES);
            format!("{no} {}${pc} {c}", rng.pick(FR_STREETS))
        }
        10 => format!("{no} {}", rng.pick(EN_STREETS)),
        11 => format!("Apt {}, {no} {}", rng.range(1, 40), rng.pick(EN_STREETS)),
        12 => format!("{no}, {}", rng.pick(FR_STREETS)),
        13 => format!(
            "{}, {no}, {} {}",
            rng.pick(&["Via Roma", "Via Dante", "Corso Vittorio Emanuele"]),
            rng.digits(5),
            rng.pick(&["Roma", "Torino"])
        ),
        14 => format!(
            "C/ {} {no}, {} Madrid",
            rng.pick(&["Mayor", "Serrano", "Gran Vía"]),
            rng.digits(5)
        ),
        15 => {
            let (pc, c) = *rng.pick(FR_CITIES);
            format!("{no} {} {pc} {}", rng.pick(FR_STREETS), c).to_uppercase()
        }
        16 => format!(
            "Flat {}, {no} {}, {}",
            rng.range(1, 20),
            rng.pick(&["Queen's Road", "High Street", "Station Road"]),
            rng.pick(&["Leeds LS1 4AP", "Bristol BS1 5TR"])
        ),
        _ => format!(
            "{no} Rue Sainte-Catherine O, Montréal, QC H2X {}{}{}",
            rng.range(1, 9),
            rng.chars(1, UPPER),
            rng.range(1, 9)
        ),
    }
}

// --------------------------------------------------------------- Phones

fn phone(rng: &mut Rng, fmt: usize) -> String {
    let two = |r: &mut Rng| format!("{:02}", r.range(0, 99));
    match fmt {
        0 => format!(
            "0{} {} {} {} {}",
            rng.range(1, 9),
            two(rng),
            two(rng),
            two(rng),
            two(rng)
        ),
        1 => format!("0{}{}", rng.range(6, 7), rng.digits(8)),
        2 => format!(
            "+33 {} {} {} {} {}",
            rng.range(1, 9),
            two(rng),
            two(rng),
            two(rng),
            two(rng)
        ),
        3 => format!("+33{}{}", rng.range(6, 7), rng.digits(8)),
        4 => format!("({}) 555-{}", rng.range(201, 989), rng.digits(4)),
        5 => format!("{}-555-{}", rng.range(201, 989), rng.digits(4)),
        6 => format!("+1 {} 555 {}", rng.range(201, 989), rng.digits(4)),
        7 => {
            if rng.chance(50) {
                format!("020 7946 {}", rng.digits(4))
            } else {
                format!("+44 7700 {}", rng.digits(6))
            }
        }
        8 => {
            if rng.chance(50) {
                format!("+49 30 {}", rng.digits(8))
            } else {
                format!("0151 {}", rng.digits(8))
            }
        }
        9 => format!(
            "+1 {}-555-{} ext. {}",
            rng.range(201, 989),
            rng.digits(4),
            rng.range(10, 999)
        ),
        10 => format!(
            "0{}.{}.{}.{}.{}",
            rng.range(1, 9),
            two(rng),
            two(rng),
            two(rng),
            two(rng)
        ),
        11 => match rng.below(3) {
            0 => format!("+39 06 {} {}", rng.digits(4), rng.digits(4)),
            1 => format!(
                "+34 {} {} {}",
                rng.range(600, 799),
                rng.digits(3),
                rng.digits(3)
            ),
            _ => format!(
                "+32 4{} {} {} {}",
                rng.digits(2),
                two(rng),
                two(rng),
                two(rng)
            ),
        },
        12 => format!("3{} {} {}", rng.digits(2), rng.digits(3), rng.digits(4)),
        13 => format!("6{} {} {} {}", rng.digits(2), two(rng), two(rng), two(rng)),
        14 => format!("+44 (0)20 7946 {}", rng.digits(4)),
        _ => format!("tel:+33{}{}", rng.range(1, 9), rng.digits(8)),
    }
}

// --------------------------------------------------------------- Emails

const DOMAINS: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "mail.example.fr",
    "corp.example.de",
    "example.co.uk",
];

fn email(rng: &mut Rng, fmt: usize) -> String {
    let f = deaccent(&rng.pick(FIRST).to_lowercase());
    let l = deaccent(&rng.pick(LAST).to_lowercase().replace([' ', '\''], ""));
    let d = *rng.pick(DOMAINS);
    match fmt {
        0 => format!("{f}.{l}@{d}"),
        1 => format!("{}{l}{}@{d}", &f[..1], rng.range(1, 99)),
        2 => format!("{}.{}@{}", capital(&f), capital(&l), d.to_uppercase()),
        3 => format!("{f}+news@{d}"),
        4 => format!("{} {} <{f}.{l}@{d}>", capital(&f), capital(&l)),
        5 => format!("Contact: {f}_{l}@{d}"),
        6 => format!("{f}{l}@{d}"),
        7 => format!(
            "{f}.{l}@{d}; {}@{d}",
            deaccent(&rng.pick(FIRST).to_lowercase())
        ),
        8 => format!("?to={f}.{l}@{d}&subject=hello"),
        _ => format!(
            "{}.{}@{}",
            f.to_uppercase(),
            l.to_uppercase(),
            d.to_uppercase()
        ),
    }
}

fn deaccent(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'à' | 'â' | 'ä' => 'a',
            'í' | 'ï' | 'î' | 'ı' => 'i',
            'ó' | 'ö' | 'ô' => 'o',
            'ú' | 'ü' | 'û' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            'ś' => 's',
            'ş' => 's',
            c => c,
        })
        .collect()
}

fn capital(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

// ---------------------------------------------------------- Secrets

fn aws_id(rng: &mut Rng) -> String {
    format!(
        "{}{}",
        if rng.chance(70) { "AKIA" } else { "ASIA" },
        rng.chars(16, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    )
}

fn aws_secret(rng: &mut Rng) -> String {
    loop {
        let s = rng.chars(40, B64);
        if s.chars().any(|c| c.is_ascii_digit())
            && s.chars().any(|c| c.is_ascii_uppercase())
            && s.chars().any(|c| c.is_ascii_lowercase())
        {
            return s;
        }
    }
}

fn password_hash(rng: &mut Rng, fmt: usize) -> String {
    match fmt {
        0 => format!("$2b$12${}", rng.chars(53, CRYPT)),
        1 => format!("$2a$10${}", rng.chars(53, CRYPT)),
        2 => format!("$2y$11${}", rng.chars(53, CRYPT)),
        3 => format!(
            "$argon2id$v=19$m=65536,t=3,p=4${}${}",
            rng.chars(22, B62),
            rng.chars(43, B62)
        ),
        4 => format!(
            "$argon2i$v=19$m=4096,t=3,p=1${}${}",
            rng.chars(16, B62),
            rng.chars(32, B62)
        ),
        5 => format!(
            "$scrypt$ln=16,r=8,p=1${}${}",
            rng.chars(22, B62),
            rng.chars(43, B62)
        ),
        6 => format!(
            "pbkdf2_sha256$600000${}${}=",
            rng.chars(22, B62),
            rng.chars(43, B62)
        ),
        7 => format!(
            "$pbkdf2-sha256$29000${}${}",
            rng.chars(22, CRYPT),
            rng.chars(43, CRYPT)
        ),
        8 => format!(
            "pbkdf2:sha256:600000${}${}",
            rng.chars(16, B62),
            rng.chars(64, HEX)
        ),
        9 => format!(
            "$6$rounds=5000${}${}",
            rng.chars(16, CRYPT),
            rng.chars(86, CRYPT)
        ),
        10 => format!("$5${}${}", rng.chars(16, CRYPT), rng.chars(43, CRYPT)),
        11 => format!("$1${}${}", rng.chars(8, CRYPT), rng.chars(22, CRYPT)),
        12 => format!("{{SSHA}}{}==", rng.chars(30, B62)),
        13 => format!("{{SHA}}{}=", rng.chars(27, B62)),
        14 => format!("*{}", rng.chars(40, b"0123456789ABCDEF")),
        _ => format!("md5{}", rng.chars(32, HEX)),
    }
}

// ------------------------------------------------------------- Harness

struct Case {
    label: String,
    name: String,
    values: Vec<String>,
    want: Vec<C>,
}

/// Name styles for a descriptive base (`["date", "of", "birth"]`).
fn name_styles(words: &[&str]) -> Vec<String> {
    let snake = words.join("_");
    let camel: String = words
        .iter()
        .enumerate()
        .map(|(i, w)| if i == 0 { (*w).to_owned() } else { capital(w) })
        .collect();
    let pascal: String = words.iter().map(|w| capital(w)).collect();
    vec![
        snake.clone(),
        camel,
        pascal,
        snake.to_uppercase(),
        words.concat(),
    ]
}

const INNOCENT: &[&str] = &[
    "value",
    "data",
    "info",
    "field1",
    "attr_x",
    "col_17",
    "f3",
    "c42",
    "val",
    "text1",
    "x_2",
    "column_9",
    "misc",
    "extra",
    "details",
    "ref",
    "label",
    "code",
    "notes",
    "payload",
    "COL_4",
    "Field12",
    "attrX",
    "f_07",
    "zz_legacy",
    "tmp",
    "old_value",
    "import_col_3",
    // misleading
    "status",
    "type",
    "city",
    "category",
    "created",
    "amount",
    "comment",
];

/// Values of a column: `n` generated values, some empty or placeholders.
fn column(
    rng: &mut Rng,
    n: usize,
    sparse: bool,
    mut make: impl FnMut(&mut Rng) -> String,
) -> Vec<String> {
    (0..n)
        .map(|_| {
            if sparse && rng.chance(65) {
                if rng.chance(70) {
                    String::new()
                } else {
                    (*rng.pick(&["N/A", "null", "-", "unknown"])).to_owned()
                }
            } else {
                make(rng)
            }
        })
        .collect()
}

fn push_positive(
    cases: &mut Vec<Case>,
    rng: &mut Rng,
    what: &str,
    want: &[C],
    names: &[String],
    formats: usize,
    make: &dyn Fn(&mut Rng, usize) -> String,
) {
    // Every format under a hinted name and under an innocent / opaque name.
    for fmt in 0..formats {
        for hinted in [true, false] {
            let name = if hinted {
                rng.pick(names).clone()
            } else {
                (*rng.pick(INNOCENT)).to_owned()
            };
            let n = rng.range(30, 200) as usize;
            let sparse = rng.chance(25);
            let values = column(rng, n, sparse, |r| make(r, fmt));
            cases.push(Case {
                label: format!(
                    "{what} fmt{fmt} {}{}",
                    if hinted { "hinted" } else { "opaque" },
                    if sparse { " sparse" } else { "" }
                ),
                name,
                values,
                want: want.to_vec(),
            });
        }
    }
}

fn negative(
    cases: &mut Vec<Case>,
    rng: &mut Rng,
    what: &str,
    name: &str,
    n: usize,
    make: &dyn Fn(&mut Rng) -> String,
) {
    let values = (0..n).map(|_| make(rng)).collect();
    cases.push(Case {
        label: format!("NEG {what}"),
        name: name.to_owned(),
        values,
        want: Vec::new(),
    });
}

fn build() -> Vec<Case> {
    let mut rng = Rng(0x5eed_2026_0928);
    let r = &mut rng;
    let mut cases = Vec::new();

    // ------------------------------------------------------- positives
    let mut bd_names = name_styles(&["date", "of", "birth"]);
    bd_names.extend(name_styles(&["birth", "date"]));
    bd_names.extend(
        [
            "dob",
            "DOB",
            "date_naissance",
            "dateNaissance",
            "geburtsdatum",
            "birthday",
            "fecha_nacimiento",
            "born_on",
        ]
        .map(str::to_owned),
    );
    push_positive(
        &mut cases,
        r,
        "birth_date",
        &[C::BirthDate],
        &bd_names,
        16,
        &|r, f| {
            let age = r.range(18, 92);
            let (_, m, d) = ymd(r, 2000, 2000);
            date_fmt(f, (2026 - age, m, d), r)
        },
    );

    let mut pn_names = name_styles(&["first", "name"]);
    pn_names.extend(name_styles(&["last", "name"]));
    pn_names.extend(name_styles(&["full", "name"]));
    pn_names.extend(name_styles(&["customer", "name"]));
    pn_names.extend(
        [
            "prenom",
            "nom",
            "surname",
            "givenName",
            "sn",
            "cn",
            "Vorname",
            "nachname",
            "apellido",
            "holder",
            "contact_name",
        ]
        .map(str::to_owned),
    );
    push_positive(
        &mut cases,
        r,
        "person_name",
        &[C::PersonName],
        &pn_names,
        10,
        &person,
    );

    let mut ad_names = name_styles(&["postal", "address"]);
    ad_names.extend(name_styles(&["street", "address"]));
    ad_names.extend(
        [
            "adresse",
            "addr",
            "address_line1",
            "homeAddress",
            "ADDRESS",
            "anschrift",
            "direccion",
            "shipping_address",
        ]
        .map(str::to_owned),
    );
    push_positive(
        &mut cases,
        r,
        "postal_address",
        &[C::PostalAddress],
        &ad_names,
        18,
        &address,
    );

    let mut ph_names = name_styles(&["phone", "number"]);
    ph_names.extend(
        [
            "tel",
            "mobile",
            "telephone",
            "gsm",
            "PHONE",
            "phoneNumber",
            "cell",
            "fax",
            "telefon",
            "contact_phone",
        ]
        .map(str::to_owned),
    );
    push_positive(&mut cases, r, "phone", &[C::Phone], &ph_names, 16, &phone);

    let mut em_names = name_styles(&["email", "address"]);
    em_names
        .extend(["email", "mail", "courriel", "EMAIL", "userEmail", "e_mail"].map(str::to_owned));
    push_positive(&mut cases, r, "email", &[C::Email], &em_names, 10, &email);

    let iban_names: Vec<String> = [
        "iban",
        "IBAN",
        "bank_account",
        "rib",
        "accountIban",
        "payout_iban",
    ]
    .map(str::to_owned)
    .to_vec();
    push_positive(
        &mut cases,
        r,
        "iban",
        &[C::Iban],
        &iban_names,
        6,
        &|r, f| {
            let v = iban(r, true);
            match f {
                0 => v,
                1 => group(&v, 4, " "),
                2 => group(&v, 4, " ").to_lowercase(),
                3 => group(&v, 4, "-"),
                4 => format!("IBAN: {}", group(&v, 4, " ")),
                _ => v.to_lowercase(),
            }
        },
    );

    let nir_names: Vec<String> = [
        "nir",
        "num_secu",
        "ssn",
        "insee",
        "NIR",
        "numeroSecuriteSociale",
    ]
    .map(str::to_owned)
    .to_vec();
    push_positive(&mut cases, r, "nir", &[C::Nir], &nir_names, 5, &|r, f| {
        let v = nir(r, true);
        match f {
            0 => v,
            1 => format!(
                "{} {} {} {} {} {} {}",
                &v[..1],
                &v[1..3],
                &v[3..5],
                &v[5..7],
                &v[7..10],
                &v[10..13],
                &v[13..]
            ),
            2 => format!("{} {}", &v[..13], &v[13..]),
            3 => format!(
                "{}-{}-{}-{}-{}-{}-{}",
                &v[..1],
                &v[1..3],
                &v[3..5],
                &v[5..7],
                &v[7..10],
                &v[10..13],
                &v[13..]
            ),
            _ => format!(
                "{}.{}.{}.{}.{}.{}.{}",
                &v[..1],
                &v[1..3],
                &v[3..5],
                &v[5..7],
                &v[7..10],
                &v[10..13],
                &v[13..]
            ),
        }
    });

    let card_names: Vec<String> = [
        "card_number",
        "pan",
        "cc_num",
        "creditCard",
        "CARD_NO",
        "carte",
    ]
    .map(str::to_owned)
    .to_vec();
    push_positive(
        &mut cases,
        r,
        "card",
        &[C::CardNumber],
        &card_names,
        6,
        &|r, f| {
            let v = card(r);
            match f {
                0 => v,
                1 if v.len() == 16 => group(&v, 4, " "),
                1 => v,
                2 if v.len() == 16 => group(&v, 4, "-"),
                2 => v,
                3 if v.len() == 15 => format!("{} {} {}", &v[..4], &v[4..10], &v[10..]),
                3 | 4 => group(&v, 4, " "),
                _ => format!(
                    "Paid with card {} on order",
                    if v.len() == 16 { group(&v, 4, " ") } else { v }
                ),
            }
        },
    );

    let aws_names: Vec<String> = ["aws_access_key_id", "accessKeyId", "AWS_KEY", "access_key"]
        .map(str::to_owned)
        .to_vec();
    push_positive(
        &mut cases,
        r,
        "aws_id",
        &[C::AwsKey],
        &aws_names,
        2,
        &|r, f| {
            let id = aws_id(r);
            if f == 0 {
                id
            } else {
                format!(
                    "aws_access_key_id={id}\naws_secret_access_key={}",
                    aws_secret(r)
                )
            }
        },
    );
    let secret_names: Vec<String> = [
        "aws_secret_access_key",
        "secretAccessKey",
        "SECRET_KEY",
        "aws_secret",
    ]
    .map(str::to_owned)
    .to_vec();
    push_positive(
        &mut cases,
        r,
        "aws_secret",
        &[C::AwsKey],
        &secret_names,
        2,
        &|r, f| {
            let s = aws_secret(r);
            if f == 0 {
                s
            } else {
                format!(
                    r#"{{"AccessKeyId": "{}", "SecretAccessKey": "{s}"}}"#,
                    aws_id(r)
                )
            }
        },
    );

    let pw_names: Vec<String> = [
        "password",
        "password_hash",
        "pwd",
        "passwd",
        "userPassword",
        "mdp",
        "pw_hash",
        "hashed_password",
    ]
    .map(str::to_owned)
    .to_vec();
    push_positive(
        &mut cases,
        r,
        "password_hash",
        &[C::PasswordHash],
        &pw_names,
        16,
        &password_hash,
    );
    // Raw digests under a password name.
    for (i, len) in [32usize, 40, 64, 64].iter().enumerate() {
        let values = column(r, 80, false, |r| r.chars(*len, HEX));
        cases.push(Case {
            label: format!("password_hash raw hex {i}"),
            name: pw_names[i].clone(),
            values,
            want: vec![C::PasswordHash],
        });
    }

    // Free text mixing tokens.
    for i in 0..6 {
        let values = column(r, 120, false, |r| match r.below(3) {
            0 => {
                let f = r.below(12);
                format!("Customer called from {} about the invoice.", phone(r, f))
            }
            1 => format!("Please answer to {} before Friday.", email(r, 0)),
            _ => format!("Ticket {} closed.", r.digits(6)),
        });
        cases.push(Case {
            label: format!("free text phone+email {i}"),
            name: (*r.pick(&["note", "comment", "body", "description", "col_3", "message"]))
                .to_owned(),
            values,
            want: vec![C::Email, C::Phone],
        });
    }
    for i in 0..4 {
        let values = column(r, 100, false, |r| match r.below(3) {
            0 => format!("Refund to IBAN {} please", group(&iban(r, true), 4, " ")),
            1 => format!(
                "Card {} was declined",
                group(&luhn_complete(&format!("4{}", r.digits(14))), 4, " ")
            ),
            _ => "Thanks for your patience".to_owned(),
        });
        cases.push(Case {
            label: format!("free text iban+card {i}"),
            name: "body".to_owned(),
            values,
            want: vec![C::CardNumber, C::Iban],
        });
    }
    for i in 0..3 {
        let values = column(r, 80, false, |r| {
            if r.chance(40) {
                let age = r.range(20, 80);
                let (f, m, d) = (r.below(6), r.range(1, 12), r.range(1, 28));
                format!(
                    "Patient born {} , follow-up in 3 months",
                    date_fmt(f, (2026 - age, m, d), r)
                )
            } else {
                "Routine visit, no change".to_owned()
            }
        });
        cases.push(Case {
            label: format!("free text labelled birth dates {i}"),
            name: "clinical_note".to_owned(),
            values,
            want: vec![C::BirthDate],
        });
    }

    // Name columns of one culture, one token, under opaque names. Pools
    // include less common names on purpose.
    const CULTURE_GIVEN: &[&[&str]] = &[
        &[
            "Zofia",
            "Bartosz",
            "Kacper",
            "Wiktoria",
            "Grzegorz",
            "Aleksandra",
            "Radosław",
            "Małgorzata",
            "Jakub",
            "Dobromir",
            "Bożena",
            "Zbigniew",
        ],
        &[
            "Mehmet",
            "Elif",
            "Emre",
            "Zeynep",
            "Burak",
            "Ayşegül",
            "Cem",
            "Selin",
            "Oğuz",
            "Gökhan",
            "Deniz",
            "Yasemin",
        ],
        &[
            "Arjun",
            "Priya",
            "Rohan",
            "Ananya",
            "Vikram",
            "Deepika",
            "Siddharth",
            "Lakshmi",
            "Harsha",
            "Nandini",
            "Karthik",
            "Meenakshi",
        ],
        &[
            "Haruto", "Yui", "Sota", "Hina", "Kenta", "Aoi", "Ren", "Misaki", "Daichi", "Sakura",
            "Shun", "Kaede",
        ],
        &[
            "Chinedu", "Ngozi", "Kwame", "Abena", "Tunde", "Folake", "Emeka", "Adaeze", "Kofi",
            "Yaa", "Babajide", "Olamide",
        ],
        &[
            "Astrid", "Magnus", "Sigrid", "Leif", "Ingrid", "Bjørn", "Solveig", "Torben", "Freja",
            "Håkon", "Liv", "Eskil",
        ],
        &[
            "João",
            "Beatriz",
            "Gonçalo",
            "Inês",
            "Rui",
            "Leonor",
            "Tiago",
            "Mafalda",
            "Duarte",
            "Constança",
            "Vasco",
            "Lara",
        ],
        &[
            "Youssef", "Salma", "Amine", "Imane", "Hamza", "Khadija", "Othmane", "Zineb", "Anas",
            "Houda", "Ilyas", "Soukaina",
        ],
    ];
    const CULTURE_LAST: &[&[&str]] = &[
        &[
            "Kowalczyk",
            "Zieliński",
            "Wójcik",
            "Kamińska",
            "Lewandowski",
            "Szymańska",
            "Dąbrowski",
            "Kaczmarek",
            "Mazur",
            "Krawczyk",
            "Grabowska",
            "Pawlak",
        ],
        &[
            "Yılmaz", "Kaya", "Demir", "Şahin", "Çelik", "Öztürk", "Aydın", "Arslan", "Doğan",
            "Koç", "Kurt", "Özdemir",
        ],
        &[
            "Sharma",
            "Iyer",
            "Reddy",
            "Banerjee",
            "Nair",
            "Chatterjee",
            "Kulkarni",
            "Deshpande",
            "Menon",
            "Pillai",
            "Venkatesan",
            "Rao",
        ],
        &[
            "Takahashi",
            "Watanabe",
            "Nakamura",
            "Kobayashi",
            "Yamaguchi",
            "Matsumoto",
            "Inoue",
            "Hayashi",
            "Shimizu",
            "Fujiwara",
            "Kondo",
            "Morimoto",
        ],
        &[
            "Okonkwo", "Adeyemi", "Mensah", "Boateng", "Mwangi", "Okafor", "Nwosu", "Asante",
            "Diallo", "Traoré", "Ndiaye", "Kamara",
        ],
        &[
            "Lindqvist",
            "Johansson",
            "Bergström",
            "Nyström",
            "Halvorsen",
            "Pedersen",
            "Sørensen",
            "Virtanen",
            "Korhonen",
            "Eriksen",
            "Holmberg",
            "Sandvik",
        ],
        &[
            "Carvalho",
            "Ribeiro",
            "Gonçalves",
            "Figueiredo",
            "Magalhães",
            "Antunes",
            "Loureiro",
            "Pinheiro",
            "Sequeira",
            "Quintela",
            "Mourão",
            "Valente",
        ],
        &[
            "Benali",
            "El Amrani",
            "Bennani",
            "Alaoui",
            "Tazi",
            "Berrada",
            "Chraibi",
            "Haddad",
            "Khoury",
            "Mansour",
            "Saleh",
            "Belkacem",
        ],
    ];
    for (k, pool) in CULTURE_GIVEN.iter().chain(CULTURE_LAST.iter()).enumerate() {
        for upper in [false, true] {
            let values = column(r, 90, false, |r| {
                let v = (*r.pick(pool)).to_owned();
                if upper { v.to_uppercase() } else { v }
            });
            cases.push(Case {
                label: format!("names culture {k} upper={upper}"),
                name: format!("col_{}", 100 + k),
                values,
                want: vec![C::PersonName],
            });
        }
    }
    for (i, fmt) in [(0, "particles"), (1, "compound"), (2, "upper last first")].into_iter() {
        let values = column(r, 90, false, |r| match i {
            0 => format!("{} {}", r.pick(FIRST), r.pick(PARTICLE_LAST)),
            1 => format!(
                "{}-{} {}-{}",
                r.pick(FIRST),
                r.pick(FIRST),
                r.pick(LAST),
                r.pick(LAST)
            ),
            _ => format!("{} {}", r.pick(LAST).to_uppercase(), r.pick(FIRST)),
        });
        cases.push(Case {
            label: format!("names {fmt}"),
            name: "f9".to_owned(),
            values,
            want: vec![C::PersonName],
        });
    }

    // Decomposed values (NFD: base letter + combining mark), as written by
    // macOS and some ETLs.
    let nfd = |v: String| v.nfd().collect::<String>();
    const ACCENTED_FIRST: &[&str] = &[
        "Élodie",
        "Chloé",
        "Anaïs",
        "Raphaël",
        "Noémie",
        "Hélène",
        "Zoé",
        "Inès",
        "Jérôme",
        "Frédéric",
        "Séverine",
        "Benoît",
        "Loïc",
        "Maëlle",
        "Gaëtan",
        "Clémence",
    ];
    const ACCENTED_LAST: &[&str] = &[
        "Lefèvre",
        "Béranger",
        "Mérieux",
        "Chénier",
        "Pétain",
        "Géraud",
        "Hébert",
        "Lemaître",
        "Dupré",
        "Frérot",
        "Müller",
        "Gómez",
        "Sánchez",
        "Núñez",
        "Björk",
        "Łukasiewicz",
    ];
    for (i, name) in ["col_120", "given_name", "f_121", "NOM"]
        .into_iter()
        .enumerate()
    {
        let values = column(r, 90, false, |r| {
            nfd(match i % 2 {
                0 => format!("{} {}", r.pick(ACCENTED_FIRST), r.pick(ACCENTED_LAST)),
                _ => (*r.pick(ACCENTED_FIRST)).to_owned(),
            })
        });
        cases.push(Case {
            label: format!("names NFD {i}"),
            name: name.to_owned(),
            values,
            want: vec![C::PersonName],
        });
    }
    for (i, name) in ["col_122", "adresse"].into_iter().enumerate() {
        let values = column(r, 90, false, |r| {
            let (pc, c) = *r.pick(&[
                ("13006", "Marseille"),
                ("69003", "Lyon"),
                ("97400", "Saint-Denis"),
                ("59000", "Lille"),
            ]);
            nfd(format!(
                "{} {} {}, {pc} {c}",
                r.range(1, 200),
                r.pick(&["allée", "impasse", "chemin", "rue"]),
                r.pick(&[
                    "des Écoles",
                    "de l'Église",
                    "Hélène Boucher",
                    "du Château",
                    "des Pâquerettes"
                ])
            ))
        });
        cases.push(Case {
            label: format!("addresses NFD {i}"),
            name: name.to_owned(),
            values,
            want: vec![C::PostalAddress],
        });
    }
    for (i, name) in ["col_123", "date_naissance"].into_iter().enumerate() {
        let values = column(r, 90, false, |r| {
            let age = r.range(20, 90);
            let (m, d) = (r.range(1, 12), r.range(1, 28));
            nfd(format!("{d} {} {}", MONTHS_FR[m as usize - 1], 2026 - age))
        });
        cases.push(Case {
            label: format!("french months NFD {i}"),
            name: name.to_owned(),
            values,
            want: vec![C::BirthDate],
        });
    }
    for (i, name) in ["col_124", "courriel"].into_iter().enumerate() {
        let values = column(r, 90, false, |r| {
            nfd(format!(
                "{}.{}@exemple.fr",
                r.pick(ACCENTED_FIRST).to_lowercase(),
                r.pick(ACCENTED_LAST).to_lowercase()
            ))
        });
        cases.push(Case {
            label: format!("emails NFD {i}"),
            name: name.to_owned(),
            values,
            want: vec![C::Email],
        });
    }
    // A person qualifier wins over an object word.
    let values = column(r, 90, false, |r| person(r, 0));
    cases.push(Case {
        label: "pet owner names".to_owned(),
        name: "petOwnerName".to_owned(),
        values,
        want: vec![C::PersonName],
    });

    // Mixed columns: 75 % values, the rest free text placeholders.
    for (i, (want, name)) in [
        (C::BirthDate, "col_50"),
        (C::PersonName, "col_51"),
        (C::PostalAddress, "col_52"),
        (C::Phone, "col_53"),
    ]
    .into_iter()
    .enumerate()
    {
        let values = column(r, 120, false, |r| {
            if r.chance(25) {
                (*r.pick(&["not provided", "see file", "refused", "?"])).to_owned()
            } else {
                match want {
                    C::BirthDate => {
                        let (y, m, d) = ymd(r, 1940, 2005);
                        date_fmt(0, (y, m, d), r)
                    }
                    C::PersonName => person(r, 0),
                    C::PostalAddress => address(r, 1),
                    _ => phone(r, 0),
                }
            }
        });
        cases.push(Case {
            label: format!("mixed 75% {i}"),
            name: name.to_owned(),
            values,
            want: vec![want],
        });
    }
    // Low prevalence in free text (8 %).
    for i in 0..4 {
        let values = column(r, 150, false, |r| {
            if r.chance(8) {
                format!("Forwarded by {}", email(r, 0))
            } else {
                "Status updated".to_owned()
            }
        });
        cases.push(Case {
            label: format!("email low prevalence {i}"),
            name: "history".to_owned(),
            values,
            want: vec![C::Email],
        });
    }
    // Tiny tables.
    for i in 0..4 {
        let values: Vec<String> = (0..3).map(|_| email(r, 0)).collect();
        cases.push(Case {
            label: format!("email tiny {i}"),
            name: "c1".to_owned(),
            values,
            want: vec![C::Email],
        });
    }

    // --------------------------------------------------- hard negatives
    // Dates that are not birth dates.
    negative(
        &mut cases,
        r,
        "created_at timestamps",
        "created_at",
        150,
        &|r| {
            let (y, m, d) = ymd(r, 2019, 2026);
            format!(
                "{y}-{m:02}-{d:02} {:02}:{:02}:{:02}",
                r.range(0, 23),
                r.range(0, 59),
                r.range(0, 59)
            )
        },
    );
    negative(&mut cases, r, "order dates", "col_5", 150, &|r| {
        let (y, m, d) = ymd(r, 2016, 2026);
        format!("{d:02}/{m:02}/{y}")
    });
    negative(&mut cases, r, "expiry dates", "valid_until", 120, &|r| {
        let (y, m, d) = ymd(r, 2026, 2030);
        format!("{y}-{m:02}-{d:02}")
    });
    negative(&mut cases, r, "hire dates", "start", 120, &|r| {
        let (y, m, d) = ymd(r, 1995, 2025);
        format!("{y}-{m:02}-{d:02}")
    });
    negative(&mut cases, r, "event timestamps iso", "ts", 150, &|r| {
        let (y, m, d) = ymd(r, 2020, 2026);
        format!(
            "{y}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
            r.range(0, 23),
            r.range(0, 59),
            r.range(0, 59),
            r.range(0, 999)
        )
    });
    negative(&mut cases, r, "billing periods", "period", 100, &|r| {
        let (y, m, _) = ymd(r, 2010, 2025);
        format!("{y}-{m:02}-01")
    });
    negative(&mut cases, r, "8-digit ids", "batch_ref", 150, &|r| {
        r.digits(8)
    });
    negative(&mut cases, r, "unix epochs", "updated", 150, &|r| {
        format!("{}", r.range(1_500_000_000, 1_790_000_000))
    });

    // Names that are not person names.
    const CITIES: &[&str] = &[
        "Paris",
        "Lyon",
        "Marseille",
        "Toulouse",
        "Nice",
        "Nantes",
        "Strasbourg",
        "Montpellier",
        "Bordeaux",
        "Lille",
        "Rennes",
        "Reims",
        "Berlin",
        "Munich",
        "Hamburg",
        "Madrid",
        "Barcelona",
        "Rome",
        "Milan",
        "London",
        "Manchester",
        "Dublin",
        "Amsterdam",
        "Brussels",
        "Vienna",
        "Zurich",
        "Geneva",
        "Lisbon",
        "Porto",
        "Prague",
        "Warsaw",
        "Stockholm",
        "Oslo",
        "Helsinki",
        "Chicago",
        "Houston",
        "Phoenix",
        "Dallas",
        "San Diego",
        "Seattle",
        "Boston",
        "Denver",
        "Austin",
        "Charlotte",
        "Florence",
        "Victoria",
        "Nancy",
        "Orléans",
        "Grenoble",
        "Dijon",
    ];
    const COUNTRIES: &[&str] = &[
        "France",
        "Germany",
        "Spain",
        "Italy",
        "Portugal",
        "Belgium",
        "Netherlands",
        "Switzerland",
        "Austria",
        "Poland",
        "Sweden",
        "Norway",
        "Denmark",
        "Finland",
        "Ireland",
        "United Kingdom",
        "United States",
        "Canada",
        "Mexico",
        "Brazil",
        "Argentina",
        "Chile",
        "Japan",
        "China",
        "India",
        "Morocco",
        "Tunisia",
        "Senegal",
        "Egypt",
        "Kenya",
        "Jordan",
        "Georgia",
    ];
    const PRODUCTS: &[&str] = &[
        "Blue Widget",
        "Red Chair",
        "Oak Table",
        "Desk Lamp",
        "Wireless Mouse",
        "USB Cable",
        "Coffee Mug",
        "Green Tea",
        "Leather Bag",
        "Running Shoes",
        "Winter Jacket",
        "Garden Hose",
        "Steel Kettle",
        "Yoga Mat",
        "Phone Charger",
        "Paper Towels",
        "Olive Oil",
        "Dark Chocolate",
        "Cotton Shirt",
        "Glass Vase",
        "Standing Desk",
        "Pro Headset",
        "Mini Speaker",
        "Smart Watch",
    ];
    const COMPANIES: &[&str] = &[
        "Acme Corp",
        "Globex Inc",
        "Initech LLC",
        "Umbrella Group",
        "Stark Industries",
        "Wayne Enterprises",
        "Contoso Ltd",
        "Northwind Traders",
        "Fabrikam SA",
        "Tailspin Toys",
        "Soylent GmbH",
        "Hooli Technologies",
        "Vandelay Industries",
        "Pied Piper Software",
        "Cyberdyne Systems",
        "Aperture Labs",
        "Massive Dynamic",
        "Oceanic Airlines",
        "Blue Sun Corporation",
        "Duff Brewing Company",
    ];
    const TITLES: &[&str] = &[
        "Software Engineer",
        "Sales Manager",
        "Account Executive",
        "Data Analyst",
        "Product Owner",
        "HR Assistant",
        "Chief Financial Officer",
        "Customer Support Agent",
        "Marketing Director",
        "Operations Lead",
        "Office Manager",
        "Senior Consultant",
        "Junior Developer",
        "Nurse",
        "Driver",
        "Teacher",
        "Accountant",
        "Warehouse Operator",
    ];
    const DEPTS: &[&str] = &[
        "Human Resources",
        "Finance",
        "Marketing",
        "Sales",
        "Engineering",
        "Legal",
        "Operations",
        "Customer Success",
        "Research and Development",
        "Procurement",
        "Logistics",
        "Quality Assurance",
    ];
    const COLORS: &[&str] = &[
        "Red", "Blue", "Green", "Yellow", "Black", "White", "Purple", "Orange", "Pink", "Brown",
        "Gray", "Silver", "Gold", "Navy", "Beige", "Teal", "Maroon", "Olive", "Ivory", "Coral",
    ];
    const STATUSES: &[&str] = &[
        "Active",
        "Inactive",
        "Pending",
        "Approved",
        "Rejected",
        "Closed",
        "Open",
        "Draft",
        "Archived",
        "Cancelled",
    ];
    for (what, pool, name) in [
        ("cities", CITIES, "city"),
        ("cities opaque", CITIES, "col_12"),
        ("countries", COUNTRIES, "c4"),
        ("products", PRODUCTS, "name"),
        ("products opaque", PRODUCTS, "label"),
        ("companies", COMPANIES, "company"),
        ("companies opaque", COMPANIES, "f7"),
        ("job titles", TITLES, "title"),
        ("departments", DEPTS, "value"),
        ("colors", COLORS, "attr_2"),
        ("statuses", STATUSES, "state"),
    ] {
        negative(&mut cases, r, what, name, 120, &|r| {
            (*r.pick(pool)).to_owned()
        });
    }
    negative(&mut cases, r, "usernames", "login", 120, &|r| {
        format!(
            "{}{}",
            deaccent(&r.pick(FIRST).to_lowercase())[..1].to_owned(),
            deaccent(&r.pick(LAST).to_lowercase().replace([' ', '\''], ""))
        )
    });
    // A street line without a number is part of an address under an
    // address name; without the name it cannot be told from a label.
    let values = (0..80).map(|_| (*r.pick(FR_STREETS)).to_owned()).collect();
    cases.push(Case {
        label: "street lines hinted".to_owned(),
        name: "street".to_owned(),
        values,
        want: vec![C::PostalAddress],
    });

    // Addresses: non-addresses with numbers and street-like words.
    negative(&mut cases, r, "order lines", "line", 120, &|r| {
        format!("{} x {}", r.range(1, 12), r.pick(PRODUCTS))
    });
    negative(&mut cases, r, "rooms", "location", 100, &|r| {
        format!("Room {}, Building {}", r.range(1, 400), r.chars(1, UPPER))
    });
    negative(&mut cases, r, "city with postcode", "col_8", 100, &|r| {
        let (pc, c) = *r.pick(FR_CITIES);
        format!("{pc} {c}")
    });
    negative(&mut cases, r, "free text notes", "comment", 120, &|r| {
        (*r.pick(&[
            "Call back tomorrow morning",
            "Customer happy with the service",
            "Sent via email 3 times",
            "Delivered to the front desk",
            "Drive 15 minutes to the depot",
            "Meeting moved to Place de la Bourse office",
            "Upgrade to plan 2 requested",
        ]))
        .to_owned()
    });
    negative(&mut cases, r, "urls", "link", 100, &|r| {
        format!("https://www.example.com/rue/{}", r.range(1, 999))
    });

    // Phones: numbers that are not phones.
    negative(&mut cases, r, "order numbers", "order_no", 150, &|r| {
        format!("{}{}", r.range(1, 9), r.digits(9))
    });
    negative(&mut cases, r, "zero padded ids", "id", 150, &|r| {
        format!("00{}", r.digits(8))
    });
    negative(&mut cases, r, "amounts", "amount", 150, &|r| {
        format!(
            "{} {:03},{:02}",
            r.range(1, 999),
            r.range(0, 999),
            r.range(0, 99)
        )
    });
    negative(&mut cases, r, "ip addresses", "client_ip", 150, &|r| {
        format!(
            "{}.{}.{}.{}",
            r.range(1, 223),
            r.range(0, 255),
            r.range(0, 255),
            r.range(1, 254)
        )
    });
    negative(&mut cases, r, "versions", "version", 100, &|r| {
        format!("{}.{}.{}", r.range(0, 20), r.range(0, 99), r.range(0, 999))
    });
    negative(&mut cases, r, "us ssn-like", "tax_ref", 100, &|r| {
        format!(
            "{:03}-{:02}-{:04}",
            r.range(100, 899),
            r.range(1, 99),
            r.range(1, 9999)
        )
    });
    negative(&mut cases, r, "zip codes", "zip", 100, &|r| r.digits(5));
    negative(&mut cases, r, "quantities", "col_2", 150, &|r| {
        format!("{}", r.range(0, 100_000))
    });
    negative(&mut cases, r, "dates dotted with time", "at", 150, &|r| {
        let (y, m, d) = ymd(r, 2020, 2026);
        format!(
            "{d:02}.{m:02}.{y} {:02}:{:02}",
            r.range(0, 23),
            r.range(0, 59)
        )
    });

    // E-mail look-alikes.
    negative(&mut cases, r, "git remotes", "repo", 100, &|r| {
        format!(
            "git@github.com:{}/{}.git",
            r.chars(6, B62).to_lowercase(),
            r.chars(8, B62).to_lowercase()
        )
    });
    negative(
        &mut cases,
        r,
        "urls with user info",
        "endpoint",
        100,
        &|r| {
            format!(
                "https://{}@git.example.com/org/repo.git",
                r.chars(6, B62).to_lowercase()
            )
        },
    );
    negative(&mut cases, r, "db uris", "dsn", 100, &|r| {
        format!(
            "postgres://app{}@db{}.example.com:5432/app",
            r.range(1, 9),
            r.range(1, 20)
        )
    });
    negative(&mut cases, r, "message ids", "message_id", 150, &|r| {
        format!("<{}.{}@mail.example.com>", r.digits(14), r.chars(12, HEX))
    });
    negative(&mut cases, r, "message ids uuid", "col_9", 150, &|r| {
        format!(
            "<{}-{}-{}-{}-{}@mx.example.org>",
            r.chars(8, HEX),
            r.chars(4, HEX),
            r.chars(4, HEX),
            r.chars(4, HEX),
            r.chars(12, HEX)
        )
    });
    negative(&mut cases, r, "package specs", "dependency", 100, &|r| {
        format!(
            "{}@{}.{}.{}",
            r.pick(&[
                "lodash",
                "react",
                "express",
                "@types/node",
                "left-pad",
                "vue"
            ]),
            r.range(0, 20),
            r.range(0, 30),
            r.range(0, 40)
        )
    });
    negative(&mut cases, r, "retina assets", "asset", 100, &|r| {
        format!("{}@2x.png", r.pick(&["logo", "icon", "banner", "avatar"]))
    });
    negative(
        &mut cases,
        r,
        "noreply sender constant",
        "sender",
        100,
        &|_| "noreply@shop.example.com".to_owned(),
    );
    negative(
        &mut cases,
        r,
        "system mailboxes",
        "from_address",
        100,
        &|r| {
            format!(
                "{}@example.com",
                r.pick(&[
                    "no-reply",
                    "mailer-daemon",
                    "postmaster",
                    "notifications",
                    "donotreply"
                ])
            )
        },
    );
    negative(
        &mut cases,
        r,
        "support constant",
        "support_email",
        100,
        &|_| "support@example.com".to_owned(),
    );
    negative(&mut cases, r, "ssh commands", "cmd", 100, &|r| {
        format!("ssh://deploy@host{}.example.net", r.range(1, 50))
    });

    // Card look-alikes.
    negative(&mut cases, r, "random 16-digit ids", "col_14", 150, &|r| {
        format!("{}{}", r.range(1, 9), r.digits(15))
    });
    negative(
        &mut cases,
        r,
        "luhn ids random prefix",
        "account_ref",
        150,
        &|r| luhn_complete(&format!("{}{}", r.range(1, 9), r.digits(14))),
    );
    negative(&mut cases, r, "imei", "imei", 120, &|r| {
        luhn_complete(&format!(
            "{}{}",
            r.pick(&["35", "86", "01", "99"]),
            r.digits(12)
        ))
    });
    negative(&mut cases, r, "imei opaque", "device", 120, &|r| {
        luhn_complete(&format!(
            "{}{}",
            r.pick(&["35", "86", "01", "99"]),
            r.digits(12)
        ))
    });
    negative(&mut cases, r, "siret", "siret", 120, &|r| {
        luhn_complete(&r.digits(13))
    });
    negative(&mut cases, r, "siret opaque", "col_20", 120, &|r| {
        luhn_complete(&r.digits(13))
    });
    negative(&mut cases, r, "ean-13 barcodes", "barcode", 120, &|r| {
        format!("{}{}", r.range(30, 50), r.digits(11))
    });
    negative(&mut cases, r, "tracking numbers", "tracking", 120, &|r| {
        format!("9400{}", r.digits(18))
    });
    negative(
        &mut cases,
        r,
        "order ids luhn visa-like",
        "order_number",
        120,
        &|r| luhn_complete(&format!("4{}", r.digits(14))),
    );

    // IBAN / NIR look-alikes.
    negative(&mut cases, r, "invalid ibans", "col_21", 120, &|r| {
        iban(r, false)
    });
    negative(&mut cases, r, "bic codes", "bic", 120, &|r| {
        format!(
            "{}{}{}",
            r.chars(4, UPPER),
            r.pick(&["FR", "DE", "GB"]),
            r.chars(5, ALNUM_UP)
        )
    });
    negative(
        &mut cases,
        r,
        "random 15-digit numbers",
        "col_22",
        150,
        &|r| format!("{}{}", r.range(1, 2), r.digits(14)),
    );
    negative(&mut cases, r, "invalid nirs", "matricule", 150, &|r| {
        nir(r, false)
    });

    // AWS look-alikes.
    negative(&mut cases, r, "sha1 hex", "commit", 120, &|r| {
        r.chars(40, HEX)
    });
    negative(&mut cases, r, "uuids", "uuid", 120, &|r| {
        format!(
            "{}-{}-{}-{}-{}",
            r.chars(8, HEX),
            r.chars(4, HEX),
            r.chars(4, HEX),
            r.chars(4, HEX),
            r.chars(12, HEX)
        )
    });
    negative(
        &mut cases,
        r,
        "session tokens",
        "session_token",
        120,
        &|r| r.chars(40, B62),
    );
    negative(&mut cases, r, "api tokens 32", "col_30", 120, &|r| {
        r.chars(32, B62)
    });
    negative(
        &mut cases,
        r,
        "aws unique ids (not keys)",
        "principal",
        120,
        &|r| {
            format!(
                "{}{}",
                r.pick(&["AIDA", "AROA", "ANPA"]),
                r.chars(17, ALNUM_UP)
            )
        },
    );

    // Password hash look-alikes.
    negative(&mut cases, r, "file checksums", "checksum", 120, &|r| {
        r.chars(64, HEX)
    });
    negative(&mut cases, r, "file hashes", "file_hash", 120, &|r| {
        r.chars(64, HEX)
    });
    negative(&mut cases, r, "md5 etags", "col_31", 120, &|r| {
        r.chars(32, HEX)
    });
    negative(
        &mut cases,
        r,
        "plaintext passwords",
        "password",
        100,
        &|r| {
            format!(
                "{}{}!",
                capital(&r.chars(6, b"abcdefghijklmnopqrstuvwxyz")),
                r.digits(3)
            )
        },
    );
    negative(&mut cases, r, "prices", "price", 100, &|r| {
        format!("${}.{:02}", r.range(1, 999), r.range(0, 99))
    });
    negative(&mut cases, r, "jwts", "token", 100, &|r| {
        format!(
            "eyJ{}.eyJ{}.{}",
            r.chars(30, B62),
            r.chars(60, B62),
            r.chars(43, B62)
        )
    });

    negative(&mut cases, r, "siren grouped", "col_60", 120, &|r| {
        format!("{} {} {}", r.range(300, 999), r.digits(3), r.digits(3))
    });
    negative(&mut cases, r, "french amounts", "total", 120, &|r| {
        format!(
            "{} {:03} {:03}",
            r.range(1, 99),
            r.range(0, 999),
            r.range(0, 999)
        )
    });
    negative(&mut cases, r, "street label opaque", "col_40", 80, &|r| {
        (*r.pick(FR_STREETS)).to_owned()
    });
    negative(&mut cases, r, "recent registrations", "col_61", 150, &|r| {
        let (y, m, d) = ymd(r, 2012, 2026);
        format!("{d:02}.{m:02}.{y}")
    });
    negative(&mut cases, r, "pet names", "species", 60, &|r| {
        (*r.pick(&["Dog", "Cat", "Rabbit", "Hamster", "Parrot", "Goldfish"])).to_owned()
    });
    negative(&mut cases, r, "hex colors", "col_62", 100, &|r| {
        format!("#{}", r.chars(6, HEX))
    });
    negative(&mut cases, r, "file paths", "path", 100, &|r| {
        format!("/var/lib/app/{}/{}.log", r.chars(6, HEX), r.range(1, 999))
    });
    negative(&mut cases, r, "coordinates", "geo", 100, &|r| {
        format!(
            "{}.{} , {}.{}",
            r.range(40, 50),
            r.digits(6),
            r.range(0, 9),
            r.digits(6)
        )
    });
    negative(&mut cases, r, "sku codes", "col_63", 100, &|r| {
        format!("SKU-{}-{}", r.chars(3, UPPER), r.digits(5))
    });
    negative(&mut cases, r, "percentages", "col_64", 100, &|r| {
        format!("{}.{}%", r.range(0, 99), r.range(0, 9))
    });
    for (what, pool) in [
        (
            "car brands",
            &[
                "Ford", "Mercedes", "Lincoln", "Ferrari", "Renault", "Peugeot", "Citroen", "Tesla",
                "Porsche", "Toyota", "Honda", "Nissan", "Volvo", "Fiat", "Dacia", "Skoda", "Audi",
                "Opel", "Mazda", "Kia",
            ][..],
        ),
        (
            "languages",
            &[
                "Java", "Python", "Rust", "Go", "Ruby", "Kotlin", "Swift", "Scala", "Haskell",
                "Julia", "Elixir", "Perl", "Dart", "Lua", "Crystal", "Clojure", "Erlang", "Pascal",
                "Ada", "Nim",
            ][..],
        ),
        (
            "us cities",
            &[
                "Austin",
                "Jackson",
                "Madison",
                "Charlotte",
                "Lincoln",
                "Aurora",
                "Savannah",
                "Tyler",
                "Irving",
                "Warren",
                "Henderson",
                "Houston",
                "Dallas",
                "Phoenix",
                "Denver",
                "Chester",
                "Cleveland",
                "Clinton",
                "Franklin",
                "Hamilton",
                "Arlington",
                "Columbus",
                "Orlando",
                "Tampa",
                "Miami",
                "Memphis",
                "Nashville",
            ][..],
        ),
        (
            "football clubs",
            &[
                "Paris Saint-Germain",
                "Real Madrid",
                "Manchester United",
                "Olympique de Marseille",
                "Bayern Munich",
                "Juventus",
                "Ajax",
                "Celtic",
                "Benfica",
                "Porto",
            ][..],
        ),
        (
            "car models",
            &[
                "Clio", "Megane", "Zoe", "Captur", "Kadjar", "Twingo", "Scenic", "Laguna",
                "Espace", "Kangoo",
            ][..],
        ),
        (
            "isbn",
            &[
                "978-2-07-036822-8",
                "978-0-306-40615-7",
                "978-3-16-148410-0",
                "979-10-90636-07-1",
            ][..],
        ),
        (
            "plates",
            &["AB-123-CD", "EF-456-GH", "XY-789-ZA", "GT-012-KL"][..],
        ),
        (
            "vin",
            &[
                "1HGCM82633A004352",
                "WVWZZZ1JZXW000001",
                "VF1AB000123456789",
                "JH4KA7660MC012345",
            ][..],
        ),
        (
            "mac addresses",
            &[
                "00:1A:2B:3C:4D:5E",
                "3C:22:FB:12:34:56",
                "F0:18:98:AA:BB:CC",
            ][..],
        ),
        (
            "vat numbers",
            &[
                "FR12345678901",
                "DE123456789",
                "GB999999973",
                "IT12345678901",
                "ESX12345678",
            ][..],
        ),
        (
            "invoice numbers",
            &[
                "FA-2024-00123",
                "FA-2024-00124",
                "INV/2025/000871",
                "CN-2023-0042",
            ][..],
        ),
        (
            "siren compact",
            &[
                "732829320",
                "552100554",
                "443061841",
                "542065479",
                "572015246",
            ][..],
        ),
        (
            "french rib",
            &[
                "30006000011234567890189",
                "10278060760002020470123",
                "20041010050500013M02606",
            ][..],
        ),
    ] {
        negative(&mut cases, r, what, "col_70", 60, &|r| {
            (*r.pick(pool)).to_owned()
        });
    }
    // Numeric identifiers and codes that are not phones (opaque names).
    negative(
        &mut cases,
        r,
        "customer numbers compact",
        "col_80",
        150,
        &|r| format!("0{}{}", r.range(1, 9), r.digits(8)),
    );
    negative(
        &mut cases,
        r,
        "account numbers 9 digits",
        "col_81",
        150,
        &|r| format!("0{}", r.digits(8)),
    );
    negative(
        &mut cases,
        r,
        "reference numbers dashed",
        "col_82",
        150,
        &|r| format!("0{}-{}-{}", r.digits(3), r.digits(3), r.digits(3)),
    );
    negative(
        &mut cases,
        r,
        "account numbers grouped",
        "col_83",
        150,
        &|r| format!("0{} {} {}", r.digits(3), r.digits(4), r.digits(2)),
    );
    negative(&mut cases, r, "dotted codes", "col_84", 150, &|r| {
        format!(
            "0{}.0{}.0{}.0{}",
            r.digits(2),
            r.digits(2),
            r.digits(2),
            r.digits(2)
        )
    });
    negative(&mut cases, r, "siret spaced", "col_85", 150, &|r| {
        format!(
            "{} {} {} {}",
            r.range(100, 999),
            r.digits(3),
            r.digits(3),
            r.digits(5)
        )
    });
    negative(&mut cases, r, "epoch milliseconds", "col_86", 150, &|r| {
        format!("{}{}", r.range(1_500_000_000, 1_790_000_000), r.digits(3))
    });
    negative(&mut cases, r, "zip+4", "col_87", 150, &|r| {
        format!("{}-{}", r.digits(5), r.digits(4))
    });
    negative(&mut cases, r, "padded quantities", "col_88", 150, &|r| {
        format!("{:06}", r.range(0, 99_999))
    });
    negative(&mut cases, r, "codes with prefixes", "col_89", 150, &|r| {
        format!("REF-0{}-{}", r.digits(4), r.digits(5))
    });
    negative(&mut cases, r, "decimal amounts", "col_90", 150, &|r| {
        format!("0{},{:02}", r.digits(9), r.range(0, 99))
    });
    negative(&mut cases, r, "tracking dashed", "col_91", 150, &|r| {
        format!("0{}-{}", r.digits(4), r.digits(6))
    });
    negative(&mut cases, r, "mixed ids", "col_92", 200, &|r| {
        if r.chance(15) {
            format!("0{}{}", r.range(1, 9), r.digits(8))
        } else {
            let n = r.range(4, 12) as usize;
            r.digits(n)
        }
    });
    for (what, pool) in [
        (
            "european cities",
            &[
                "Lyon", "Bordeaux", "Florence", "Porto", "Valencia", "Bruges", "Salzburg",
                "Krakow", "Seville", "Nancy", "Annecy", "Toulouse", "Geneva", "Munich", "Bologna",
                "Antwerp", "Gdansk", "Brno", "Dresden", "Lille",
            ][..],
        ),
        (
            "us states",
            &[
                "Georgia",
                "Virginia",
                "Carolina",
                "Florida",
                "Texas",
                "Nevada",
                "Montana",
                "Dakota",
                "Indiana",
                "Kentucky",
                "Maryland",
                "Louisiana",
                "Arizona",
                "Oregon",
                "Vermont",
            ][..],
        ),
        (
            "fashion houses",
            &[
                "Hugo Boss",
                "Ralph Lauren",
                "Calvin Klein",
                "Christian Dior",
                "Giorgio Armani",
                "Tom Ford",
                "Marc Jacobs",
                "Michael Kors",
                "Pierre Cardin",
                "Jean Paul Gaultier",
            ][..],
        ),
    ] {
        negative(&mut cases, r, what, "col_71", 80, &|r| {
            (*r.pick(pool)).to_owned()
        });
    }
    // Names of things other than persons: the name says so, the values
    // look like person names.
    const PET_NAMES: &[&str] = &[
        "Max", "Bella", "Luna", "Charlie", "Lucy", "Cooper", "Daisy", "Rocky", "Milo", "Oscar",
        "Coco", "Rosie", "Toby", "Lola", "Oliver", "Chloe", "Leo", "Sophie", "Jack", "Molly",
    ];
    for name in [
        "pet_name",
        "petName",
        "PetName",
        "PET_NAME",
        "petname",
        "dog_name",
        "catName",
        "ANIMAL_NAME",
        "pets.name",
        "nom_chien",
    ] {
        negative(
            &mut cases,
            r,
            &format!("pet names {name}"),
            name,
            80,
            &|r| (*r.pick(PET_NAMES)).to_owned(),
        );
    }
    for (name, pool) in [
        (
            "ship_name",
            &[
                "Queen Mary",
                "Mary Rose",
                "Victoria",
                "Elizabeth",
                "Santa Maria",
                "Marie Galante",
                "Charles de Gaulle",
                "Jean Bart",
            ][..],
        ),
        (
            "horseName",
            &[
                "Seabiscuit",
                "Secretariat",
                "Jolly Jumper",
                "Ourasi",
                "Frankel",
                "Pégase",
                "Arthur",
                "Samson",
            ][..],
        ),
        (
            "product_name",
            &[
                "Victoria Sofa",
                "Emma Mattress",
                "Oscar Lamp",
                "Clara Chair",
                "Hugo Desk",
                "Lucie Mug",
            ][..],
        ),
        (
            "TEAM_NAME",
            &[
                "Les Bleus",
                "Jean Moulin",
                "Marie Curie",
                "Ada Lovelace",
                "Alan Turing",
                "Grace Hopper",
            ][..],
        ),
        (
            "projectName",
            &[
                "Apollo", "Gemini", "Athena", "Hermes", "Artemis", "Juno", "Diana", "Selene",
            ][..],
        ),
        (
            "hostname",
            &["athena", "zeus", "hera", "apollo", "hermes", "diana"][..],
        ),
        (
            "server_name",
            &[
                "Athena", "Zeus", "Hera", "Apollo", "Hermes", "Diana", "Minerva", "Juno",
            ][..],
        ),
        (
            "file_name",
            &["Jean Dupont", "Marie Curie", "Paul Martin", "Lucie Bernard"][..],
        ),
        (
            "company_name",
            &[
                "Martin Dubois",
                "Bernard Fils",
                "Laurent Petit",
                "Durand Moreau",
                "Johnson Wilson",
                "Smith Brown",
            ][..],
        ),
        (
            "city_name",
            &[
                "Charlotte",
                "Madison",
                "Florence",
                "Victoria",
                "Lincoln",
                "Austin",
                "Jackson",
                "Nancy",
            ][..],
        ),
        (
            "modelName",
            &["Clio", "Zoé", "Megane", "Laguna", "Juke", "Leaf", "Micra"][..],
        ),
    ] {
        negative(
            &mut cases,
            r,
            &format!("object names {name}"),
            name,
            80,
            &|r| (*r.pick(pool)).to_owned(),
        );
    }
    negative(&mut cases, r, "log lines", "message", 150, &|r| {
        let (y, m, d) = ymd(r, 2023, 2026);
        format!(
            "{y}-{m:02}-{d:02} {:02}:{:02}:{:02} INFO GET /api/v1/orders/{} 200 in {} ms from 10.{}.{}.{}",
            r.range(0, 23),
            r.range(0, 59),
            r.range(0, 59),
            r.digits(6),
            r.range(1, 900),
            r.range(0, 255),
            r.range(0, 255),
            r.range(1, 254)
        )
    });
    negative(&mut cases, r, "user agents", "ua", 100, &|r| {
        format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.{}.{} Safari/537.36",
            r.range(100, 130),
            r.range(1000, 6999),
            r.range(10, 200)
        )
    });
    negative(&mut cases, r, "json settings", "settings", 100, &|r| {
        format!(
            r#"{{"theme": "dark", "page_size": {}, "locale": "fr_FR", "beta": true, "last_sync": "2025-0{}-1{}T10:0{}:00Z"}}"#,
            r.range(10, 100),
            r.range(1, 9),
            r.range(0, 9),
            r.range(0, 9)
        )
    });
    negative(&mut cases, r, "html snippets", "body_html", 100, &|r| {
        format!(
            "<div class=\"card\"><h2>Offer {}</h2><p>Save {}% on Blue Widget until Friday</p></div>",
            r.digits(4),
            r.range(5, 50)
        )
    });
    negative(&mut cases, r, "product reviews", "review", 120, &|r| {
        (*r.pick(&[
            "Great product, works as described.",
            "Arrived late but the quality is good.",
            "Would buy again, five stars.",
            "The color is darker than on the picture.",
            "Customer service answered quickly.",
            "Not worth the price in my opinion.",
        ]))
        .to_owned()
    });

    cases
}

#[derive(Default)]
struct Counts {
    tp: u32,
    fp: u32,
    fn_: u32,
}

#[test]
fn synthetic_columns_meet_the_target() {
    let cases = build();
    let mut counts: BTreeMap<C, Counts> = BTreeMap::new();
    let mut errors = Vec::new();
    for case in &cases {
        let raws: Vec<RawSample<'_>> = case.values.iter().map(|v| RawSample::new(v)).collect();
        let got: Vec<C> = classify_column(&case.name, &raws)
            .iter()
            .map(|f| f.classifier())
            .collect();
        for c in C::ALL {
            let e = counts.entry(c).or_default();
            match (got.contains(&c), case.want.contains(&c)) {
                (true, true) => e.tp += 1,
                (true, false) => {
                    e.fp += 1;
                    errors.push(format!("FP {c} in [{}] named {}", case.label, case.name));
                }
                (false, true) => {
                    e.fn_ += 1;
                    errors.push(format!("FN {c} in [{}] named {}", case.label, case.name));
                }
                (false, false) => {}
            }
        }
    }
    eprintln!("synthetic columns: {}", cases.len());
    eprintln!(
        "{:<22} {:>4} {:>4} {:>4} {:>8} {:>10}",
        "classifier", "TP", "FP", "FN", "recall", "precision"
    );
    let mut failed = Vec::new();
    for (c, k) in &counts {
        let recall = f64::from(k.tp) / f64::from((k.tp + k.fn_).max(1));
        let precision = f64::from(k.tp) / f64::from((k.tp + k.fp).max(1));
        eprintln!(
            "{:<22} {:>4} {:>4} {:>4} {:>7.1}% {:>9.1}%",
            c.as_str(),
            k.tp,
            k.fp,
            k.fn_,
            recall * 100.0,
            precision * 100.0
        );
        if recall < 0.95 || precision < 0.95 {
            failed.push(c.as_str());
        }
    }
    for e in &errors {
        eprintln!("{e}");
    }
    assert!(
        failed.is_empty(),
        "below target: {failed:?}\n{}",
        errors.join("\n")
    );
}
