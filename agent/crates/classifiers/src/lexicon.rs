//! Word lists used by the value-based detectors: common given names and
//! surnames (multi-cultural), month names, street types, titles and words
//! that rule a value out as a person name.
//!
//! Every list is lowercase and ASCII-folded ([`fold`]): lookups fold the
//! word first, so `Anaïs`, `ANAIS` and `anais` are the same entry. The lists
//! are general knowledge of naming conventions (frequent given names and
//! surnames per country), not data taken from any target.

use std::collections::HashSet;
use std::sync::LazyLock;

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

/// Lowercase ASCII-folded form of a word: accents removed (NFD, combining
/// marks dropped), `ß` -> `ss`, `æ` -> `ae`, `œ` -> `oe`, `ø` -> `o`,
/// `ł` -> `l`, `đ` -> `d`, apostrophes removed.
#[must_use]
pub(crate) fn fold(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    for c in word.nfd() {
        if is_combining_mark(c) || matches!(c, '\'' | '’' | '`' | 'ʼ') {
            continue;
        }
        match c {
            'ß' => out.push_str("ss"),
            'æ' | 'Æ' => out.push_str("ae"),
            'œ' | 'Œ' => out.push_str("oe"),
            'ø' | 'Ø' => out.push('o'),
            'ł' | 'Ł' => out.push('l'),
            'đ' | 'Đ' => out.push('d'),
            'ı' => out.push('i'),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

fn set(words: &'static [&'static str]) -> HashSet<&'static str> {
    words.iter().copied().collect()
}

static GIVEN: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [GIVEN_NAMES, GIVEN_NAMES_MORE, GIVEN_NAMES_WORLD]
        .iter()
        .flat_map(|l| l.iter().copied())
        .collect()
});
static FAMILY: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [SURNAMES, SURNAMES_MORE, SURNAMES_WORLD]
        .iter()
        .flat_map(|l| l.iter().copied())
        .collect()
});
static ENTITY: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(ENTITIES));
static NOT_NAME: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(NOT_NAME_WORDS));

/// Whether a folded word is a common given name.
pub(crate) fn is_given_name(folded: &str) -> bool {
    GIVEN.contains(folded)
}

/// Whether a folded word is a common surname.
pub(crate) fn is_surname(folded: &str) -> bool {
    FAMILY.contains(folded)
}

/// Whether a folded word ends like a surname of a known family
/// (`-sson`, `-ski`, `-ović`, `-escu`, `-poulos`…). At least 5 letters.
pub(crate) fn has_surname_suffix(folded: &str) -> bool {
    folded.len() >= 5
        && folded.chars().all(|c| c.is_ascii_lowercase())
        && SURNAME_SUFFIXES
            .iter()
            .any(|s| folded.len() > s.len() + 1 && folded.ends_with(s))
}

/// Whether a whole value names a well-known place or brand (`Austin`,
/// `New York`, `Hugo Boss`): case, accents, hyphens and repeated spaces
/// ignored.
pub(crate) fn is_entity(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v.len() > 64 {
        return false;
    }
    let folded = fold(v).replace(['-', '.'], " ");
    let joined = folded.split_whitespace().collect::<Vec<_>>().join(" ");
    ENTITY.contains(joined.as_str())
}

/// Whether a folded word rules a value out as a person name (company
/// forms, places, products, roles, statuses…).
pub(crate) fn is_not_name_word(folded: &str) -> bool {
    NOT_NAME.contains(folded)
}

/// Lowercase particles allowed inside a person name.
#[rustfmt::skip]
pub(crate) const PARTICLES: &[&str] = &[
    "de", "du", "des", "la", "le", "les", "van", "von", "der", "den", "di", "da", "del", "della",
    "dello", "dos", "das", "do", "ben", "bin", "bint", "al", "el", "y", "e", "ter", "ten", "zu",
    "af", "av", "st", "ste", "saint", "sainte", "ibn", "abu", "mac", "vander", "vanden", "dela",
];

/// Titles and honorifics that may precede a name (folded, without the
/// trailing dot).
#[rustfmt::skip]
pub(crate) const TITLES: &[&str] = &[
    "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "m", "mme", "mlle", "me", "pr", "herr", "frau",
    "sr", "sra", "srta", "sig", "sigra", "dott", "dssa", "ing", "sir", "dame", "lord", "lady",
    "rev", "fr", "monsieur", "madame", "mademoiselle", "doctor", "docteur",
];

/// Suffixes that may follow a name.
pub(crate) const NAME_SUFFIXES: &[&str] = &["jr", "sr", "ii", "iii", "iv", "phd", "md", "esq"];

/// Month names and abbreviations (EN, FR, DE, ES, IT, NL, PT), folded,
/// with their month number.
pub(crate) const MONTHS: &[(&str, u32)] = &[
    ("january", 1),
    ("jan", 1),
    ("janvier", 1),
    ("janv", 1),
    ("januar", 1),
    ("janner", 1),
    ("enero", 1),
    ("ene", 1),
    ("gennaio", 1),
    ("gen", 1),
    ("januari", 1),
    ("janeiro", 1),
    ("february", 2),
    ("feb", 2),
    ("fevrier", 2),
    ("fev", 2),
    ("fevr", 2),
    ("februar", 2),
    ("febrero", 2),
    ("febbraio", 2),
    ("februari", 2),
    ("fevereiro", 2),
    ("fevereiro", 2),
    ("march", 3),
    ("mar", 3),
    ("mars", 3),
    ("marz", 3),
    ("maerz", 3),
    ("marzo", 3),
    ("maart", 3),
    ("marco", 3),
    ("mrt", 3),
    ("april", 4),
    ("apr", 4),
    ("avril", 4),
    ("avr", 4),
    ("abril", 4),
    ("abr", 4),
    ("aprile", 4),
    ("may", 5),
    ("mai", 5),
    ("mayo", 5),
    ("maggio", 5),
    ("mag", 5),
    ("mei", 5),
    ("maio", 5),
    ("june", 6),
    ("jun", 6),
    ("juin", 6),
    ("juni", 6),
    ("junio", 6),
    ("giugno", 6),
    ("giu", 6),
    ("junho", 6),
    ("july", 7),
    ("jul", 7),
    ("juillet", 7),
    ("juil", 7),
    ("juli", 7),
    ("julio", 7),
    ("luglio", 7),
    ("lug", 7),
    ("julho", 7),
    ("august", 8),
    ("aug", 8),
    ("aout", 8),
    ("agosto", 8),
    ("ago", 8),
    ("augustus", 8),
    ("september", 9),
    ("sep", 9),
    ("sept", 9),
    ("septembre", 9),
    ("septiembre", 9),
    ("setiembre", 9),
    ("settembre", 9),
    ("set", 9),
    ("setembro", 9),
    ("october", 10),
    ("oct", 10),
    ("octobre", 10),
    ("oktober", 10),
    ("okt", 10),
    ("octubre", 10),
    ("ottobre", 10),
    ("ott", 10),
    ("outubro", 10),
    ("out", 10),
    ("november", 11),
    ("nov", 11),
    ("novembre", 11),
    ("noviembre", 11),
    ("novembro", 11),
    ("december", 12),
    ("dec", 12),
    ("decembre", 12),
    ("dezember", 12),
    ("dez", 12),
    ("diciembre", 12),
    ("dic", 12),
    ("dicembre", 12),
    ("dezembro", 12),
];

/// Month number of a folded month name or abbreviation.
pub(crate) fn month(folded: &str) -> Option<u32> {
    MONTHS.iter().find(|(m, _)| *m == folded).map(|(_, n)| *n)
}

/// Weekday names and abbreviations (EN, FR, DE, ES, IT), folded.
#[rustfmt::skip]
pub(crate) const WEEKDAYS: &[&str] = &[
    "monday", "mon", "tuesday", "tue", "tues", "wednesday", "wed", "thursday", "thu", "thur",
    "thurs", "friday", "fri", "saturday", "sat", "sunday", "sun", "lundi", "mardi", "mercredi",
    "jeudi", "vendredi", "samedi", "dimanche", "lun", "mer", "jeu", "ven", "sam", "dim", "montag",
    "dienstag", "mittwoch", "donnerstag", "freitag", "samstag", "sonntag", "lunes", "martes",
    "miercoles", "jueves", "viernes", "sabado", "domingo", "lunedi", "martedi", "mercoledi",
    "giovedi", "venerdi", "sabato", "domenica",
];

/// Street types written **before** the street name (FR, EN usage with the
/// house number first: `10 rue des Lilas`, `221B Baker Street`), folded,
/// without trailing dot.
#[rustfmt::skip]
pub(crate) const STREET_TYPES_NUMBER_FIRST: &[&str] = &[
    // FR
    "rue", "avenue", "av", "ave", "boulevard", "bd", "bld", "blvd", "boul", "allee", "impasse",
    "imp", "chemin", "chem", "place", "pl", "quai", "route", "rte", "cours", "square", "sq",
    "passage", "faubourg", "fbg", "sentier", "ruelle", "voie", "residence", "cite", "hameau",
    "lieu-dit", "lieudit", "lotissement", "promenade", "prom", "esplanade", "parvis", "rond-point",
    "carrefour", "montee", "traverse", "venelle", "villa",
    // EN
    "street", "st", "road", "rd", "lane", "ln", "drive", "dr", "way", "court", "ct", "crescent",
    "cres", "terrace", "terr", "close", "gardens", "gdns", "grove", "highway", "hwy", "parkway",
    "pkwy", "circle", "cir", "trail", "trl", "mews", "broadway", "alley", "plaza", "boulevard",
];

/// Street types followed by the street name and then the house number
/// (`Via Roma 10`, `Calle Mayor 5`, `ul. Długa 5`), folded, without dot.
#[rustfmt::skip]
pub(crate) const STREET_TYPES_NUMBER_LAST: &[&str] = &[
    // IT
    "c/", "via", "viale", "piazza", "piazzale", "corso", "vicolo", "largo", "strada", "contrada",
    "lungomare", "borgo",
    // ES / PT
    "calle", "avenida", "avda", "avd", "plaza", "pza", "paseo", "carrera", "cra", "camino",
    "carretera", "ctra", "ronda", "travesia", "rua", "travessa", "praca", "estrada", "largo",
    "alameda", "rambla",
    // PL / CZ / others
    "ul", "ulica", "aleja", "osiedle", "ulice", "strasse", "str", "weg", "platz", "gasse", "allee",
    "damm", "chaussee", "straat", "laan", "plein", "gracht", "kade", "singel", "dreef", "steenweg",
];

/// Street-type endings of compound street names (`Musterstraße`,
/// `Kerkstraat`, `Storgatan`, `Nørregade`), folded.
#[rustfmt::skip]
pub(crate) const STREET_SUFFIXES: &[&str] = &[
    "strasse", "str", "weg", "platz", "gasse", "allee", "damm", "ufer", "chaussee", "steig",
    "pfad", "markt", "straat", "laan", "plein", "gracht", "kade", "singel", "dreef", "steenweg",
    "dijk", "gatan", "vagen", "gata", "vej", "veien", "veg", "gata", "katu", "utca", "ulica",
];

/// Words in a value that rule out a person name: legal forms, place and
/// organization words, products, roles, statuses, placeholders.
#[rustfmt::skip]
const NOT_NAME_WORDS: &[&str] = &[
    // legal forms and organizations
    "inc", "ltd", "llc", "llp", "plc", "gmbh", "ag", "sa", "sas", "sasu", "sarl", "eurl", "srl",
    "spa", "bv", "nv", "oy", "ab", "as", "corp", "corporation", "company", "co", "group",
    "holding", "holdings", "partners", "associates", "bank", "banque", "foundation", "fondation",
    "association", "institute", "institut", "university", "universite", "college", "school",
    "ecole", "academy", "hospital", "hopital", "clinic", "clinique", "hotel", "restaurant", "cafe",
    "bar", "store", "shop", "boutique", "market", "supermarket", "pharmacy", "pharmacie",
    "services", "service", "solutions", "systems", "technologies", "technology", "tech",
    "consulting", "conseil", "software", "labs", "lab", "studio", "studios", "media", "agency",
    "agence", "international", "global", "industries", "industry", "enterprises", "logistics",
    "transport", "transports", "construction", "energy", "motors", "airlines", "insurance",
    "assurance", "assurances", "capital", "finance", "ventures", "trust", "club", "team",
    "department", "dept", "division", "office", "bureau", "ministry", "ministere", "council",
    "committee", "church", "eglise", "museum", "musee", "library", "center", "centre", "park",
    "parc", "garden", "jardin", "airport", "aeroport", "station", "gare", "port", "stadium", "the",
    "and", "of", "for", "et", "und", "pour", "avec", "with", "from",
    // addresses and places
    "street", "road", "avenue", "boulevard", "rue", "lane", "drive", "route", "chemin", "impasse",
    "allee", "quai", "city", "ville", "county", "state", "province", "region", "district", "north",
    "south", "east", "west", "nord", "sud", "est", "ouest", "upper", "lower", "new", "old",
    "mount", "lake", "river", "island", "beach", "valley", "bay", "saint-denis",
    // roles and jobs
    "manager", "engineer", "developer", "director", "directeur", "directrice", "assistant",
    "assistante", "officer", "analyst", "consultant", "specialist", "coordinator", "administrator",
    "admin", "technician", "technicien", "operator", "supervisor", "president", "chief", "head",
    "lead", "senior", "junior", "intern", "stagiaire", "sales", "marketing", "support",
    "accounting", "comptable", "finance", "legal", "operations", "product", "project", "customer",
    "client", "user", "users", "guest", "owner", "staff", "employee", "member", "vendor",
    "supplier", "fournisseur", "partner", "contact", "account", "human", "resources", "research",
    "development", "security", "quality", "executive", "representative", "agent", "clerk", "nurse",
    "driver", "chauffeur", "teacher", "professor", "doctor", "infirmier", "infirmiere", "vendeur",
    "vendeuse", "responsable", "chef", "charge", "chargee", "gestionnaire",
    // products and things
    "widget", "gadget", "chair", "table", "desk", "lamp", "sofa", "bed", "shirt", "shoes", "dress",
    "jacket", "bag", "box", "pack", "kit", "set", "bundle", "cable", "charger", "phone", "laptop",
    "tablet", "screen", "monitor", "keyboard", "mouse", "printer", "camera", "watch", "coffee",
    "tea", "juice", "water", "wine", "beer", "pizza", "burger", "salad", "bread", "cheese",
    "chocolate", "cake", "cream", "oil", "soap", "shampoo", "paper", "pen", "book", "edition",
    "premium", "deluxe", "classic", "standard", "basic", "pro", "plus", "lite", "mini", "ultra",
    "large", "small", "medium", "xl", "xxl", "size", "pcs", "unit", "units", "item", "items",
    "model", "version", "series", "collection", "original", "organic", "bio", "extra", "super",
    "light", "dark", "red", "blue", "yellow", "orange", "purple", "pink", "silver", "gold",
    "steel", "wooden", "plastic", "glass", "cotton", "leather", "wireless", "digital", "electric",
    "smart", "portable", "outdoor", "indoor", "kitchen", "bathroom", "office",
    // statuses, placeholders, generic
    "active", "inactive", "pending", "approved", "rejected", "cancelled", "canceled", "closed",
    "open", "done", "new", "draft", "published", "archived", "deleted", "enabled", "disabled",
    "true", "false", "yes", "no", "oui", "non", "none", "null", "unknown", "inconnu", "test",
    "default", "sample", "example", "demo", "dummy", "todo", "misc", "other", "autre", "various",
    "general", "public", "private", "internal", "external", "total", "error", "warning", "info",
    "debug", "high", "low", "normal", "urgent", "critical", "monday", "tuesday", "wednesday",
    "thursday", "friday", "saturday", "sunday", "january", "february", "march", "april", "june",
    "july", "august", "september", "october", "november", "december",
    // countries and nationalities often written in name-like form
    "france", "germany", "allemagne", "spain", "espagne", "italy", "italie", "belgium", "belgique",
    "switzerland", "suisse", "netherlands", "united", "kingdom", "states", "america", "canada",
    "china", "japan", "india", "brazil", "mexico", "russia", "australia", "europe", "africa",
    "asia", "french", "english", "german", "spanish", "italian", "american",
];

/// Surname endings typical of a language family (folded).
#[rustfmt::skip]
const SURNAME_SUFFIXES: &[&str] = &[
    "sson", "ssen", "sen", "son", "ez", "ski", "ska", "sky", "cki", "cka", "dzki", "wicz", "owicz",
    "ewicz", "ovic", "evic", "ovich", "evich", "escu", "eanu", "poulos", "opoulou", "akis", "idis",
    "iadis", "yan", "enko", "chuk", "czuk", "ova", "eva", "ov", "ev", "off", "ini", "elli", "etti",
    "otti", "ucci", "azzi", "ieri", "mann", "stein", "berg", "feld", "baum", "meyer", "meier",
    "mayer", "maier", "hardt", "brecht", "oglu", "quist", "strom", "gaard", "haug", "rud",
    "dottir", "sdottir", "kova",
];

/// Common given names (FR, EN, DE, ES, IT, NL, PT, PL, CZ, RU, Nordic,
/// Irish, Arabic, Turkish, Indian, East Asian romanizations), folded.
#[rustfmt::skip]
const GIVEN_NAMES: &[&str] = &[
    // English
    "james", "john", "robert", "michael", "william", "david", "richard", "joseph", "thomas",
    "charles", "christopher", "daniel", "matthew", "anthony", "donald", "steven", "stephen",
    "paul", "andrew", "joshua", "kenneth", "kevin", "brian", "george", "timothy", "ronald",
    "edward", "jason", "jeffrey", "ryan", "jacob", "gary", "nicholas", "eric", "jonathan", "larry",
    "justin", "scott", "brandon", "benjamin", "samuel", "gregory", "alexander", "frank", "patrick",
    "raymond", "jack", "dennis", "jerry", "tyler", "aaron", "jose", "adam", "nathan", "henry",
    "douglas", "zachary", "peter", "kyle", "ethan", "walter", "noah", "jeremy", "christian",
    "keith", "roger", "terry", "gerald", "harold", "sean", "austin", "carl", "arthur", "lawrence",
    "dylan", "jesse", "jordan", "bryan", "billy", "joe", "bruce", "gabriel", "logan", "albert",
    "willie", "alan", "juan", "wayne", "elijah", "randy", "roy", "vincent", "ralph", "eugene",
    "russell", "bobby", "mason", "philip", "phillip", "louis", "liam", "oliver", "lucas", "aiden",
    "aidan", "jackson", "sebastian", "mateo", "owen", "luke", "leo", "julian", "levi", "isaac",
    "grayson", "hudson", "lincoln", "asher", "theodore", "carter", "hunter", "connor", "eli",
    "ezra", "caleb", "landon", "wyatt", "jaxon", "nolan", "cameron", "colton", "evan", "easton",
    "micah", "ian", "jace", "declan", "harrison", "harry", "charlie", "alfie", "freddie", "archie",
    "theo", "finley", "reuben", "toby", "oscar", "jake", "callum", "lewis", "jamie", "alex", "sam",
    "chris", "tom", "tony", "steve", "mike", "dave", "jim", "bob", "ben", "dan", "nick", "matt",
    "rob", "ted", "fred", "stanley", "leonard", "howard", "francis", "martin", "craig", "shawn",
    "travis", "marcus", "derek", "troy", "curtis", "neil", "glenn", "clifford", "dustin", "trevor",
    "spencer", "grant", "blake", "cole", "garrett", "wesley", "bradley", "dean", "victor", "edwin",
    "gordon", "allen", "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "susan",
    "jessica", "sarah", "karen", "lisa", "nancy", "betty", "margaret", "sandra", "ashley",
    "kimberly", "emily", "donna", "michelle", "carol", "amanda", "dorothy", "melissa", "deborah",
    "stephanie", "rebecca", "sharon", "laura", "cynthia", "kathleen", "amy", "angela", "shirley",
    "anna", "brenda", "pamela", "emma", "nicole", "helen", "samantha", "katherine", "christine",
    "debra", "rachel", "carolyn", "janet", "catherine", "maria", "heather", "diane", "ruth",
    "julie", "olivia", "joyce", "virginia", "victoria", "kelly", "lauren", "christina", "joan",
    "evelyn", "judith", "megan", "andrea", "cheryl", "hannah", "jacqueline", "martha", "gloria",
    "teresa", "ann", "sara", "madison", "frances", "kathryn", "janice", "jean", "abigail", "alice",
    "judy", "sophia", "grace", "denise", "amber", "doris", "marilyn", "danielle", "beverly",
    "isabella", "theresa", "diana", "natalie", "brittany", "charlotte", "marie", "kayla", "alexis",
    "lori", "ava", "mia", "amelia", "harper", "ella", "avery", "sofia", "camila", "aria",
    "scarlett", "chloe", "lily", "layla", "riley", "zoey", "nora", "hazel", "ellie", "violet",
    "aurora", "savannah", "audrey", "brooklyn", "bella", "claire", "skylar", "lucy", "paisley",
    "everly", "caroline", "nova", "emilia", "maya", "naomi", "aaliyah", "elena", "ariana",
    "gabriella", "stella", "penelope", "sadie", "eleanor", "isla", "poppy", "evie", "sophie",
    "freya", "daisy", "phoebe", "ruby", "florence", "matilda", "rosie", "millie", "imogen",
    "holly", "jane", "susie", "kate", "katie", "jenny", "molly", "abby", "beth", "emma", "grace",
    "julia", "tiffany", "crystal", "erin", "tracy", "dawn", "wendy", "tina", "rose", "anne",
    "joanne", "vanessa", "valerie", "leah", "hailey", "zoe", "rachael", "jasmine", "courtney",
    "chelsea", "whitney", "lindsay", "morgan", "taylor", "paige", "brooke", "sydney", "alyssa",
    "destiny", "mackenzie", "kaylee", "peyton", "jocelyn", "addison", "allison", "gianna",
    "adeline", "clara", "ivy", "iris", "ruby", "pierre", "michel", "andre", "philippe", "rene",
    "alain", "jacques", "bernard", "marcel", "claude", "henri", "georges", "nicolas", "francois",
    "gerard", "christophe", "julien", "maurice", "laurent", "frederic", "stephane", "pascal",
    "sebastien", "alexandre", "thierry", "olivier", "antoine", "dominique", "lucien", "emile",
    "jules", "leon", "marius", "gilbert", "yves", "didier", "franck", "bruno", "serge", "romain",
    "maxime", "quentin", "guillaume", "mathieu", "matthieu", "damien", "cedric", "ludovic",
    "arnaud", "fabrice", "jerome", "xavier", "yannick", "hugo", "enzo", "mathis", "clement",
    "baptiste", "raphael", "timeo", "sacha", "axel", "valentin", "victor", "simon", "aurelien",
    "adrien", "remi", "loic", "mickael", "sylvain", "herve", "gael", "noe", "nael", "mael",
    "gaspard", "augustin", "corentin", "florian", "benoit", "thibault", "thibaut", "jean-pierre",
    "jean-luc", "jean-paul", "jean-claude", "jean-marc", "jean-francois", "jean-michel",
    "jean-louis", "jean-baptiste", "marie-claire", "marie-france", "marie-christine", "anne-marie",
    "marie-therese", "jeanne", "francoise", "monique", "nathalie", "isabelle", "jacqueline",
    "sylvie", "martine", "madeleine", "suzanne", "helene", "marguerite", "christiane", "yvonne",
    "valerie", "brigitte", "chantal", "sandrine", "veronique", "celine", "emilie", "aurelie",
    "camille", "pauline", "manon", "lea", "ines", "jade", "louise", "lina", "ambre", "juliette",
    "elodie", "lucie", "mathilde", "clemence", "marion", "amandine", "melanie", "virginie",
    "genevieve", "agnes", "josette", "odette", "simone", "paulette", "colette", "therese",
    "germaine", "gisele", "lucienne", "andree", "annie", "beatrice", "elise", "margaux", "oceane",
    "justine", "romane", "noemie", "morgane", "anais", "maeva", "lola", "louna", "eloise",
    "capucine", "apolline", "agathe", "adele", "celia", "charlene", "coralie", "estelle", "fanny",
    "gaelle", "laetitia", "laure", "maelle", "mireille", "muriel", "nadine", "noelle", "ophelie",
    "perrine", "solene", "sylviane", "yvette", "zelie", "berenice", "cecile", "danielle",
    "delphine", "severine", "karine", "corinne", "patricia", "sabine", "florence",
    // German, Dutch, Nordic
    "lukas", "leon", "luca", "finn", "jonas", "elias", "ben", "felix", "maximilian", "luis",
    "emil", "anton", "jakob", "matteo", "niklas", "tim", "jan", "moritz", "philipp", "fabian",
    "tobias", "andreas", "stefan", "markus", "wolfgang", "klaus", "jurgen", "juergen", "uwe",
    "dieter", "hans", "gunter", "guenter", "karl", "heinz", "werner", "helmut", "horst", "manfred",
    "torsten", "jens", "sven", "dirk", "kai", "lars", "nils", "ralf", "rainer", "johannes",
    "friedrich", "wilhelm", "ernst", "otto", "kurt", "gerhard", "bernd", "holger", "volker",
    "matthias", "christoph", "florian", "sabine", "susanne", "petra", "monika", "ursula", "renate",
    "karin", "gabriele", "birgit", "claudia", "stefanie", "jana", "franziska", "ingrid", "helga",
    "gertrud", "erika", "elke", "heike", "anja", "silke", "kerstin", "tanja", "katrin", "annika",
    "nina", "greta", "ida", "frieda", "paula", "mila", "lena", "leonie", "johanna", "katharina",
    "lara", "hanna", "marlene", "charlotte", "cornelis", "hendrik", "pieter", "willem", "gerrit",
    "jacobus", "daan", "sem", "milan", "bram", "thijs", "ruben", "stijn", "joost", "bas", "sander",
    "niels", "koen", "wouter", "maarten", "jeroen", "bart", "tess", "noor", "fenna", "eva",
    "lotte", "lieke", "anouk", "femke", "sanne", "fleur", "marieke", "esther", "anders", "erik",
    "johan", "olof", "magnus", "oskar", "astrid", "sigrid", "maja", "elsa", "ebba", "freja",
    "alma", "saga", "linnea", "ingrid", "henrik", "mikkel", "rasmus", "soren", "bjorn", "gustav",
    "ole", "knut", "mette", "kirsten", "birgitte", "hanne",
    // Spanish, Portuguese, Italian
    "antonio", "manuel", "francisco", "javier", "jesus", "carlos", "miguel", "alejandro", "rafael",
    "pedro", "angel", "pablo", "sergio", "fernando", "jorge", "alberto", "alvaro", "diego",
    "adrian", "raul", "enrique", "ramon", "ignacio", "andres", "ruben", "mario", "marco",
    "santiago", "gonzalo", "iker", "hector", "joaquin", "emilio", "rodrigo", "esteban", "felipe",
    "guillermo", "ricardo", "roberto", "eduardo", "luis", "carmen", "josefa", "isabel", "dolores",
    "pilar", "rosa", "cristina", "francisca", "antonia", "mercedes", "lucia", "marta", "raquel",
    "manuela", "rocio", "beatriz", "silvia", "alba", "valeria", "daniela", "carla", "noa",
    "claudia", "irene", "martina", "lorena", "nuria", "alicia", "veronica", "ximena", "guadalupe",
    "consuelo", "esperanza", "inmaculada", "montserrat", "joao", "matheus", "gustavo", "guilherme",
    "tiago", "diogo", "luiz", "vitor", "leonor", "mariana", "carolina", "francisca", "juliana",
    "larissa", "leticia", "fernanda", "luana", "bianca", "gabriela", "giuseppe", "giovanni",
    "luigi", "francesco", "angelo", "vincenzo", "pietro", "salvatore", "carlo", "franco",
    "domenico", "paolo", "michele", "giorgio", "aldo", "luciano", "alessandro", "lorenzo",
    "leonardo", "riccardo", "tommaso", "edoardo", "federico", "davide", "simone", "stefano",
    "massimo", "fabio", "emanuele", "giacomo", "filippo", "enrico", "gianluca", "matteo",
    "giuseppina", "angela", "giovanna", "carmela", "caterina", "francesca", "antonietta", "rita",
    "giulia", "ginevra", "giorgia", "chiara", "valentina", "federica", "alessandra", "roberta",
    "monica", "elisa", "serena", "ilaria", "sofia",
    // Central / Eastern Europe
    "jakub", "kacper", "szymon", "filip", "mateusz", "bartosz", "piotr", "krzysztof", "tomasz",
    "pawel", "marcin", "michal", "andrzej", "grzegorz", "stanislaw", "wojciech", "lukasz", "dawid",
    "kamil", "marek", "katarzyna", "malgorzata", "agnieszka", "krystyna", "elzbieta", "zofia",
    "magdalena", "joanna", "aleksandra", "natalia", "oliwia", "zuzanna", "petr", "jiri", "josef",
    "pavel", "tomas", "jaroslav", "vaclav", "hana", "lenka", "tereza", "ivan", "dmitri", "dmitry",
    "sergei", "sergey", "alexei", "alexey", "vladimir", "nikolai", "mikhail", "andrei", "andrey",
    "olga", "tatiana", "irina", "svetlana", "anastasia", "ekaterina", "yulia", "ksenia", "daria",
    "oksana", "iryna", "yuri", "igor", "oleg", "boris", "anatoly", "viktor", "bogdan", "nikola",
    "dragan", "milos", "stefan", "ana", "ivana", "jelena", "marija", "vesna", "laszlo", "zoltan",
    "istvan", "gabor", "eszter", "katalin", "zsofia", "andras", "attila", "mihai", "ionut",
    "andreea", "ioana", "elena", "dimitrios", "georgios", "konstantinos", "nikos", "eleni",
    "katerina",
    // Irish, Scottish, Welsh
    "ciaran", "niamh", "siobhan", "aoife", "cian", "oisin", "padraig", "fionn", "saoirse",
    "roisin", "eilidh", "hamish", "angus", "fraser", "mhairi", "rhys", "dafydd", "gareth", "sian",
    "cerys", "bethan",
    // Arabic, Turkish, Persian
    "mohamed", "mohammed", "muhammad", "mohammad", "ahmed", "ahmad", "ali", "omar", "hassan",
    "hussein", "youssef", "yusuf", "ibrahim", "khalid", "karim", "mehdi", "amine", "rachid",
    "said", "samir", "nabil", "hamza", "bilal", "ayoub", "ilyes", "rayan", "yassine", "walid",
    "mustafa", "mustapha", "abdel", "abdullah", "abdallah", "tarik", "tariq", "sofiane", "farid",
    "reda", "anis", "adel", "nassim", "yanis", "fatima", "aicha", "aisha", "khadija", "meryem",
    "mariam", "maryam", "yasmine", "yasmina", "leila", "nadia", "samira", "salma", "amina",
    "imane", "nour", "rania", "sonia", "malika", "zineb", "hind", "houda", "sarah", "mehmet",
    "ahmet", "huseyin", "ismail", "murat", "emre", "burak", "omer", "fatma", "ayse", "emine",
    "hatice", "zeynep", "elif", "merve", "reza", "hossein", "parisa", "neda",
    // Indian, East Asian, African
    "raj", "rahul", "amit", "ankit", "arjun", "vikram", "sanjay", "rohit", "vijay", "suresh",
    "ramesh", "anil", "sunil", "deepak", "rajesh", "priya", "pooja", "anjali", "neha", "sneha",
    "divya", "kavita", "sunita", "anita", "aditya", "arnav", "ravi", "krishna", "lakshmi", "wei",
    "ming", "jing", "hui", "yan", "jun", "lei", "fang", "hong", "xin", "jie", "tao", "feng", "mei",
    "ling", "xiaoming", "yong", "hiroshi", "takashi", "kenji", "yuki", "haruto", "yuto", "sota",
    "ren", "akira", "kenta", "daiki", "satoshi", "yui", "hina", "aoi", "sakura", "yuna", "akiko",
    "keiko", "yoko", "minjun", "seojun", "jiwoo", "seoyeon", "jiho", "minji", "kwame", "kofi",
    "ama", "chinedu", "ngozi", "oluwaseun", "abebe", "amara", "moussa", "mamadou", "fatou",
    "aminata", "ousmane", "ibrahima", "abdoulaye", "awa",
];

/// Common surnames (FR, EN, DE, ES, IT, NL, PT, PL, Nordic, Irish, and
/// others), folded. Surnames that are also everyday English words
/// (`black`, `king`, `hill`, `stone`…) are left out on purpose.
#[rustfmt::skip]
const SURNAMES: &[&str] = &[
    // English
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez",
    "martinez", "hernandez", "lopez", "gonzalez", "wilson", "anderson", "thomas", "taylor",
    "moore", "jackson", "martin", "lee", "perez", "thompson", "harris", "sanchez", "clark",
    "ramirez", "lewis", "robinson", "walker", "allen", "wright", "scott", "torres", "nguyen",
    "flores", "adams", "nelson", "rivera", "campbell", "mitchell", "carter", "roberts", "gomez",
    "phillips", "evans", "turner", "diaz", "parker", "cruz", "edwards", "collins", "reyes",
    "stewart", "morris", "morales", "murphy", "rogers", "gutierrez", "ortiz", "morgan", "cooper",
    "peterson", "bailey", "reed", "kelly", "howard", "ramos", "kim", "cox", "richardson", "watson",
    "brooks", "chavez", "james", "bennett", "mendoza", "ruiz", "hughes", "alvarez", "castillo",
    "sanders", "patel", "myers", "ross", "foster", "jimenez", "powell", "jenkins", "perry",
    "russell", "sullivan", "coleman", "butler", "henderson", "barnes", "gonzales", "fisher",
    "vasquez", "simmons", "romero", "jordan", "patterson", "alexander", "hamilton", "graham",
    "reynolds", "griffin", "wallace", "moreno", "cole", "hayes", "bryant", "herrera", "gibson",
    "ellis", "tran", "medina", "aguilar", "stevens", "murray", "ford", "castro", "marshall",
    "owens", "harrison", "fernandez", "mcdonald", "woods", "washington", "kennedy", "vargas",
    "henry", "chen", "freeman", "webb", "tucker", "guzman", "burns", "crawford", "olson",
    "simpson", "porter", "hunter", "gordon", "mendez", "silva", "shaw", "snyder", "mason", "dixon",
    "munoz", "hicks", "palmer", "wagner", "robertson", "boyd", "salazar", "warren", "meyer",
    "schmidt", "garza", "daniels", "ferguson", "nichols", "stephens", "soto", "weaver", "ryan",
    "gardner", "payne", "grant", "dunn", "kelley", "spencer", "hawkins", "arnold", "pierce",
    "vazquez", "hansen", "peters", "santos", "hart", "bradley", "elliott", "cunningham", "duncan",
    "armstrong", "hudson", "carroll", "riley", "andrews", "alvarado", "delgado", "perkins",
    "hoffman", "johnston", "matthews", "pena", "richards", "contreras", "willis", "carpenter",
    "lawrence", "sandoval", "davies", "clarke", "khan", "wilkinson", "chapman", "singh", "begum",
    "hussain", "owen", "lloyd", "barker", "harvey", "oconnor", "obrien", "oneill", "macdonald",
    "mckenzie", "mackenzie", "fraser", "griffiths", "morrison", "watts", "gill", "reid", "kaur",
    "doherty", "mcgregor", "mclean", "sutherland", "douglas", "kerr", "paterson", "henderson",
    "ross", "cameron", "hamilton", "burke", "walsh", "byrne", "osullivan", "oreilly", "doyle",
    "mccarthy", "gallagher", "odoherty", "lynch", "quinn", "connolly", "daly", "oconnell", "dunne",
    "brennan", "farrell", "fitzgerald", "maguire", "nolan", "flynn", "callaghan", "odonnell",
    "duffy", "mahony", "boyle", "healy", "sweeney", "kavanagh", "mcgrath", "moran", "brady",
    "casey", "foley", "fitzpatrick", "oleary", "mcmahon", "donnelly", "regan", "donovan",
    "flanagan", "cullen", "keane", "maher", "mckenna", "hogan", "mcnamara", "mcdermott", "moloney",
    "buckley", "dwyer", "evans", "jenkins", "morgan", "powell", "pritchard", "vaughan",
    // French
    "bernard", "petit", "robert", "richard", "durand", "dubois", "moreau", "laurent", "simon",
    "michel", "lefebvre", "leroy", "roux", "david", "bertrand", "morel", "fournier", "girard",
    "bonnet", "dupont", "lambert", "fontaine", "rousseau", "vincent", "muller", "lefevre", "faure",
    "andre", "mercier", "blanc", "guerin", "boyer", "garnier", "chevalier", "francois", "legrand",
    "gauthier", "perrin", "robin", "clement", "morin", "nicolas", "roussel", "mathieu", "gautier",
    "masson", "marchand", "duval", "denis", "dumont", "marie", "lemaire", "noel", "dufour",
    "meunier", "brun", "blanchard", "giraud", "joly", "riviere", "lucas", "brunet", "gaillard",
    "barbier", "arnaud", "gerard", "roche", "renard", "schmitt", "roy", "leroux", "colin", "vidal",
    "caron", "picard", "roger", "fabre", "aubert", "lemoine", "renaud", "dumas", "lacroix",
    "olivier", "philippe", "bourgeois", "pierre", "benoit", "rey", "leclerc", "payet", "rolland",
    "leclercq", "guillaume", "lecomte", "jean", "dupuis", "guillot", "hubert", "berger",
    "carpentier", "moulin", "louis", "deschamps", "huet", "vasseur", "boucher", "fleury", "royer",
    "klein", "jacquet", "adam", "poirier", "marty", "aubry", "guyot", "carre", "charles",
    "renault", "charpentier", "menard", "maillard", "baron", "bertin", "bailly", "herve",
    "schneider", "gall", "collet", "leger", "bouvier", "julien", "prevost", "millet", "perrot",
    "daniel", "cousin", "germain", "breton", "besson", "langlois", "remy", "goff", "pelletier",
    "leveque", "perrier", "leblanc", "barre", "lebrun", "marchal", "weber", "mallet", "hamon",
    "boulanger", "jacob", "monnier", "michaud", "guichard", "gillet", "etienne", "grondin",
    "poulain", "tessier", "chevallier", "collin", "chauvin", "bouchet", "lemaitre", "benard",
    "marechal", "humbert", "reynaud", "antoine", "hoarau", "perret", "barthelemy", "cordier",
    "pichon", "lejeune", "gilbert", "lamy", "delaunay", "pasquier", "carlier", "laporte",
    "gauthier", "dupre", "tanguy", "jourdan", "rolland", "bouvet", "delorme", "lebon", "texier",
    "guillon", "raynaud", "camus", "martel", "gros", "hardy", "valette", "marion", "dupuy",
    "coulon", "rigaud", "fontaine", "lenoir", "vallee", "hebert", "neveu", "blondel", "labbe",
    "leconte", "petitjean", "rossignol", "giraud", "sauvage", "bouchard", "lefort", "fabre",
    "tissot", "clavel", "chartier", "richer", "dumoulin",
    // German
    "mueller", "schmidt", "schneider", "fischer", "weber", "meyer", "wagner", "becker", "schulz",
    "hoffmann", "schafer", "schaefer", "koch", "bauer", "richter", "klein", "schroder",
    "schroeder", "neumann", "schwarz", "zimmermann", "braun", "kruger", "krueger", "hofmann",
    "hartmann", "lange", "schmitt", "werner", "schmitz", "krause", "meier", "lehmann", "schmid",
    "schulze", "maier", "kohler", "koehler", "herrmann", "konig", "koenig", "walter", "mayer",
    "huber", "kaiser", "fuchs", "peters", "scholz", "moller", "moeller", "weiss", "jung", "hahn",
    "schubert", "vogel", "friedrich", "keller", "gunther", "berger", "winkler", "roth", "beck",
    "lorenz", "baumann", "franke", "albrecht", "schuster", "ludwig", "bohm", "boehm", "winter",
    "kraus", "schumacher", "kramer", "vogt", "jager", "jaeger", "otto", "sommer", "gross",
    "seidel", "heinrich", "brandt", "haas", "schreiber", "graf", "schulte", "dietrich", "ziegler",
    "kuhn", "pohl", "engel", "horn", "busch", "bergmann", "voigt", "sauer", "wolff", "pfeiffer",
    "hauser", "ebert", "kessler", "lindner", "brenner", "frey", "gruber", "hofer", "steiner",
    "moser", "leitner", "pichler", "wimmer", "egger", "lechner", "eder",
    // Spanish, Portuguese
    "gonzalez", "sanchez", "gomez", "martin", "jimenez", "alonso", "navarro", "dominguez", "gil",
    "serrano", "blanco", "molina", "suarez", "ortega", "rubio", "marin", "sanz", "nunez",
    "iglesias", "garrido", "cortes", "lozano", "guerrero", "cano", "prieto", "calvo", "gallego",
    "leon", "marquez", "cabrera", "campos", "vega", "fuentes", "carrasco", "diez", "caballero",
    "nieto", "pascual", "santana", "herrero", "lorenzo", "montero", "hidalgo", "gimenez", "ibanez",
    "ferrer", "duran", "benitez", "mora", "arias", "carmona", "crespo", "roman", "pastor", "saez",
    "velasco", "moya", "soler", "parra", "esteban", "bravo", "gallardo", "rojas", "ferreira",
    "pereira", "oliveira", "costa", "rodrigues", "martins", "sousa", "fernandes", "goncalves",
    "gomes", "lopes", "marques", "alves", "almeida", "ribeiro", "pinto", "carvalho", "teixeira",
    "moreira", "correia", "mendes", "nunes", "soares", "vieira", "monteiro", "cardoso", "rocha",
    "neves", "coelho", "cunha", "pires", "simoes", "antunes", "matos", "fonseca", "machado",
    "araujo", "barbosa", "tavares", "lourenco", "figueiredo", "azevedo", "freitas", "batista",
    "barros", "dias", "melo", "cavalcanti",
    // Italian
    "rossi", "russo", "ferrari", "esposito", "bianchi", "romano", "colombo", "ricci", "marino",
    "greco", "bruno", "gallo", "conti", "luca", "mancini", "costa", "giordano", "rizzo",
    "lombardi", "moretti", "barbieri", "fontana", "santoro", "mariani", "rinaldi", "caruso",
    "ferrara", "galli", "martini", "leone", "longo", "gentile", "martinelli", "vitale", "lombardo",
    "serra", "coppola", "santis", "angelo", "marchetti", "parisi", "villa", "conte", "ferraro",
    "ferri", "fabbri", "bianco", "marini", "grasso", "valentini", "messina", "sala", "angelis",
    "gatti", "pellegrini", "palumbo", "sanna", "farina", "rizzi", "monti", "cattaneo", "morelli",
    "amato", "silvestri", "mazza", "testa", "grassi", "pellegrino", "carbone", "giuliani",
    "benedetti", "barone", "rossetti", "caputo", "montanari", "guerra", "palmieri", "bernardi",
    "martino", "fiore", "rosa", "ferretti", "bellini", "basile", "riva", "donati", "piras",
    "vitali", "battaglia", "sartori", "neri", "costantini", "milani", "pagano", "ruggiero",
    "sorrentino", "amico", "orlando", "damico", "negri", "deluca", "desantis", "dangelo", "derosa",
    // Dutch, Belgian
    "jong", "jansen", "vries", "berg", "dijk", "bakker", "janssen", "visser", "smit", "meijer",
    "boer", "groot", "bos", "vos", "hendriks", "leeuwen", "dekker", "brouwer", "wit", "dijkstra",
    "smits", "graaf", "meer", "linden", "kok", "jacobs", "haan", "vermeulen", "heuvel", "veen",
    "broek", "bruijn", "bruin", "heijden", "schouten", "beek", "willems", "vliet", "ven",
    "hoekstra", "maas", "verhoeven", "koster", "dam", "wal", "prins", "blom", "huisman", "peeters",
    "maes", "mertens", "claes", "goossens", "wouters", "smet", "dejong", "devries", "vandenberg",
    "vandijk", "vanderberg", "vanleeuwen", "vandermeer", "janssens", "dubois",
    // Polish, Czech, Slavic, Hungarian, Romanian, Greek
    "nowak", "kowalski", "wisniewski", "wojcik", "kowalczyk", "kaminski", "lewandowski",
    "zielinski", "szymanski", "wozniak", "dabrowski", "kozlowski", "jankowski", "mazur",
    "wojciechowski", "kwiatkowski", "krawczyk", "kaczmarek", "piotrowski", "grabowski", "zajac",
    "pawlowski", "michalski", "krol", "wieczorek", "jablonski", "wrobel", "majewski", "olszewski",
    "malinowski", "jaworski", "adamczyk", "dudek", "nowicki", "pawlak", "gorski", "witkowski",
    "walczak", "sikora", "baran", "rutkowski", "michalak", "szewczyk", "ostrowski", "tomaszewski",
    "pietrzak", "zalewski", "kowalska", "nowakowa", "novak", "svoboda", "novotny", "dvorak",
    "cerny", "prochazka", "kucera", "vesely", "horak", "nemec", "horvat", "kovacevic", "babic",
    "maric", "juric", "petrovic", "jovanovic", "nikolic", "markovic", "djordjevic", "stojanovic",
    "ilic", "ivanov", "smirnov", "kuznetsov", "popov", "vasiliev", "petrov", "sokolov",
    "mikhailov", "novikov", "fedorov", "morozov", "volkov", "alekseev", "lebedev", "semenov",
    "egorov", "pavlov", "kozlov", "stepanov", "nikolaev", "ivanova", "smirnova", "petrova",
    "shevchenko", "kovalenko", "bondarenko", "tkachenko", "nagy", "kovacs", "toth", "szabo",
    "horvath", "varga", "molnar", "nemeth", "farkas", "balogh", "popescu", "ionescu", "popa",
    "pop", "radu", "dumitru", "stan", "stoica", "gheorghe", "matei", "ciobanu", "papadopoulos",
    "papadakis", "georgiou", "nikolaou", "dimitriou", "konstantinou", "ioannou", "pappas",
    // Nordic
    "johansen", "olsen", "larsen", "andersen", "pedersen", "nielsen", "kristiansen", "jensen",
    "karlsen", "andersson", "johansson", "karlsson", "nilsson", "eriksson", "larsson", "olsson",
    "persson", "svensson", "gustafsson", "pettersson", "jonsson", "christensen", "sorensen",
    "rasmussen", "jorgensen", "petersen", "madsen", "kristensen", "virtanen", "korhonen",
    "nieminen", "makinen", "hamalainen", "lindqvist", "lindberg", "lindstrom", "berglund",
    // Arabic, Turkish, Persian
    "benali", "bensaid", "haddad", "khalil", "mansour", "nasser", "saleh", "hamdi", "amrani",
    "belkacem", "boukhari", "cherif", "djebbar", "benyoussef", "bouzid", "mahmoud", "hassan",
    "ibrahim", "abdallah", "mohamed", "ahmed", "ali", "omar", "youssef", "benali", "belaid",
    "bouaziz", "brahimi", "chaoui", "saidi", "rahmani", "mebarki", "zidane", "haddadi", "benamar",
    "ouali", "yilmaz", "kaya", "demir", "sahin", "celik", "yildiz", "yildirim", "ozturk", "aydin",
    "ozdemir", "arslan", "dogan", "kilic", "aslan", "cetin", "kara", "koc", "kurt", "ozkan",
    "simsek", "hosseini", "mohammadi", "ahmadi", "rezaei", "karimi",
    // Asian
    "tran", "le", "pham", "hoang", "phan", "vu", "vo", "dang", "bui", "ngo", "duong", "ly", "wang",
    "li", "zhang", "liu", "yang", "huang", "zhao", "wu", "zhou", "xu", "sun", "zhu", "hu", "guo",
    "lin", "gao", "luo", "zheng", "liang", "xie", "tang", "han", "feng", "deng", "cao", "peng",
    "zeng", "xiao", "tian", "dong", "yuan", "pan", "cai", "jiang", "yu", "du", "wong", "chan",
    "leung", "cheung", "lau", "ho", "ng", "chow", "tan", "lim", "goh", "ong", "choi", "jung",
    "kang", "cho", "yoon", "jang", "lim", "shin", "oh", "seo", "kwon", "sato", "suzuki",
    "takahashi", "tanaka", "watanabe", "ito", "yamamoto", "nakamura", "kobayashi", "kato",
    "yoshida", "yamada", "sasaki", "yamaguchi", "matsumoto", "inoue", "kimura", "hayashi",
    "shimizu", "kumar", "sharma", "gupta", "shah", "mehta", "reddy", "rao", "iyer", "nair",
    "joshi", "verma", "mishra", "agarwal", "chopra", "malhotra", "banerjee", "chatterjee", "das",
    "bose", "sen", "pillai", "menon", "desai", "jain",
    // African
    "diallo", "traore", "diop", "ndiaye", "camara", "keita", "toure", "sow", "ba", "fall", "cisse",
    "kone", "coulibaly", "sylla", "okafor", "okeke", "adeyemi", "mensah", "owusu", "boateng",
    "mwangi", "otieno", "kamau", "dlamini", "nkosi",
];

/// More given names (modern US / UK / FR usage and others), folded.
#[rustfmt::skip]
const GIVEN_NAMES_MORE: &[&str] = &[
    "aaron", "abel", "abigail", "achille", "adalyn", "adam", "addison", "adeline", "adrian",
    "agathe", "aiden", "aitana", "alaina", "alan", "alana", "alba", "albie", "alexandra", "alexis",
    "alfie", "alice", "alina", "alivia", "alix", "allison", "amara", "amaya", "amber", "ambre",
    "amelia", "amir", "amira", "anastasia", "andrea", "andres", "angel", "angela", "aniyah",
    "anna", "annabelle", "anthony", "antoine", "antonio", "apolline", "arabella", "archer",
    "archie", "ariella", "arlo", "arthur", "arya", "ashley", "athena", "aubree", "aubrey",
    "augustin", "autumn", "ava", "axel", "aya", "ayden", "aylin", "bailey", "barrett", "basile",
    "beckett", "benjamin", "bennett", "bentley", "blake", "blakely", "bobby", "bodhi", "brady",
    "brantley", "braxton", "brayden", "brielle", "brittany", "brooks", "brynlee", "bryson",
    "caden", "callie", "callum", "camden", "camille", "capucine", "cayden", "cecilia", "cedric",
    "celeste", "cesar", "charlie", "chloe", "clara", "clemence", "clement", "colt", "connor",
    "conor", "constance", "cooper", "cora", "courtney", "crystal", "daisy", "damian", "damien",
    "daniela", "danielle", "dante", "darcy", "dawson", "dean", "delilah", "derek", "desmond",
    "dominic", "dylan", "easton", "eden", "edison", "elena", "eliana", "elias", "elise", "eliza",
    "ella", "elliana", "eloise", "elsie", "emerson", "emery", "emiliano", "emily", "emma",
    "emmett", "enzo", "erica", "erin", "esme", "esteban", "esther", "ethan", "eva", "evan",
    "evangeline", "everly", "evie", "ezekiel", "fabien", "felicity", "felix", "fernando", "finley",
    "finnegan", "fiona", "florence", "florian", "francisco", "frankie", "freddie", "freya",
    "gabin", "gael", "gavin", "gemma", "genevieve", "george", "giulia", "grace", "gracie",
    "graham", "grant", "gregory", "greyson", "griffin", "guillaume", "hadley", "hailey", "hank",
    "harry", "haven", "hayden", "heather", "hector", "heloise", "holden", "hugo", "ilyes",
    "imogen", "ines", "iris", "isaac", "isabel", "isabella", "isla", "ivan", "ivy", "jade",
    "jasmine", "jasper", "javier", "jax", "jaxon", "jaxson", "jayceon", "jayden", "jeanne",
    "jenna", "jeremiah", "jeremy", "jessica", "jesus", "joel", "johan", "jonah", "jonathan",
    "jordan", "jose", "josephine", "joshua", "josiah", "juan", "judah", "jude", "jules", "julia",
    "juliana", "juliet", "juliette", "kai", "kaia", "kaiden", "kane", "karter", "kash", "kayden",
    "kaylee", "kayson", "keegan", "kehlani", "kendall", "kennedy", "kenneth", "kenzo", "kevin",
    "khloe", "kiara", "kieran", "kilian", "killian", "kimber", "kimberly", "kingston", "kinley",
    "kinsley", "knox", "kristen", "kylian", "kyrie", "lainey", "lana", "leila", "leilani", "lena",
    "lenny", "leo", "leon", "leonardo", "leonie", "lewis", "liam", "lila", "liliana", "lilly",
    "lily", "lincoln", "lindsey", "lola", "londyn", "lorenzo", "loris", "lou", "louie", "louis",
    "louise", "louna", "luca", "lucas", "lucia", "lucie", "ludovic", "lukas", "luna", "lya",
    "lyam", "lydia", "lyla", "lyna", "mackenzie", "maddox", "madelyn", "mael", "maelys", "maeve",
    "maisie", "makayla", "malachi", "malo", "manon", "marceau", "marco", "marcus", "margaret",
    "margot", "mariah", "mario", "marius", "marley", "martin", "mateo", "mathias", "mathilde",
    "mathis", "mathys", "matias", "matilda", "maverick", "maxence", "mckenzie", "megan", "melanie",
    "melissa", "mia", "mickael", "mila", "milan", "millie", "milo", "miriam", "molly", "monica",
    "morgan", "muhammad", "nadia", "nash", "natalia", "natasha", "nathaniel", "nael", "nevaeh",
    "nico", "nicolas", "nicole", "nina", "ninon", "noam", "nolan", "norah", "nyla", "oakley",
    "oaklynn", "octave", "odin", "olive", "oliver", "olivia", "olivier", "omar", "orion", "otto",
    "paisley", "palmer", "parker", "patrick", "paul", "pauline", "paxton", "payton", "phoebe",
    "piper", "poppy", "presley", "preston", "quinn", "raelynn", "raphael", "reagan", "rebecca",
    "reese", "reggie", "reid", "remington", "remy", "rhett", "ricardo", "riley", "romain", "roman",
    "romane", "romy", "ronnie", "rory", "rosalie", "rosie", "rowan", "ruben", "ruby", "ruth",
    "ryan", "ryder", "ryker", "ryland", "sabrina", "sacha", "sage", "salome", "samson", "santiago",
    "sara", "sarah", "sawyer", "scarlet", "sebastien", "selena", "serenity", "shane", "shannon",
    "sienna", "silas", "simon", "skye", "sloane", "soan", "sofia", "sophia", "sophie", "soren",
    "spencer", "stacy", "stanley", "stella", "stetson", "steven", "sydney", "talia", "tara",
    "tate", "taylor", "teddy", "tessa", "theo", "thiago", "thomas", "tiffany", "timeo", "tobias",
    "tom", "tommy", "travis", "tristan", "troy", "tucker", "valentina", "valeria", "vanessa",
    "vera", "victor", "victoria", "vincent", "vivian", "waylon", "wesley", "weston", "whitney",
    "willa", "willow", "xavier", "ximena", "yannis", "yohan", "zachary", "zane", "zara", "zayden",
    "zelie", "zion", "zoe", "zoey",
];

/// More surnames (FR, EN, DE, IT, ES), folded.
#[rustfmt::skip]
const SURNAMES_MORE: &[&str] = &[
    "abbott", "acosta", "adkins", "aguilar", "aguirre", "albers", "allison", "alonso", "amato",
    "andrade", "arias", "armstrong", "arnold", "arnoux", "atkins", "aubry", "austin", "avery",
    "ayala", "bailly", "baldwin", "barbe", "barber", "barbieri", "barker", "barnett", "barre",
    "barrett", "barton", "bates", "bauer", "bazin", "beck", "becker", "bellini", "benard",
    "benitez", "benoit", "benson", "berg", "berger", "bergmann", "berthelot", "bertrand",
    "besnard", "besson", "bianchi", "bigot", "bischoff", "blair", "blake", "blanco", "blondel",
    "bock", "bonneau", "bonnin", "bossard", "bouchard", "boucher", "boulay", "bouquet", "bourdon",
    "bourgeois", "boutin", "bouvet", "bowen", "bowman", "boyd", "bradford", "brady", "brandt",
    "bravo", "brewer", "briand", "briggs", "brock", "bruneau", "brunel", "brunet", "bruno",
    "bryan", "buchanan", "buisson", "burgess", "burke", "burton", "busch", "bush", "byrd",
    "caballero", "cabrera", "caldwell", "calhoun", "calvo", "campos", "camus", "cano", "cardenas",
    "carlier", "carlson", "carmona", "carney", "caron", "carr", "carrasco", "carson", "carter",
    "cartier", "caruso", "castaneda", "castillo", "castro", "chabert", "chandler", "chapman",
    "charpentier", "charrier", "chartier", "chauveau", "chauvet", "chevalier", "chevallier",
    "christensen", "clarke", "clavel", "clay", "clayton", "clerc", "cobb", "cochran", "cohen",
    "colas", "collier", "collin", "colombo", "combs", "conner", "conrad", "conte", "conway",
    "copeland", "cordier", "cornu", "cortes", "cortez", "costa", "coste", "coulon", "courtois",
    "cousin", "couturier", "craig", "crespo", "crosby", "cruz", "cummings", "curry", "da-silva",
    "dalton", "daniel", "davidson", "dawson", "de-luca", "decker", "delacruz", "delattre",
    "delaunay", "delgado", "delmas", "delorme", "denis", "dennis", "deschamps", "devaux",
    "dickerson", "didier", "dietrich", "diez", "dillon", "dominguez", "donovan", "dorsey", "doyle",
    "drake", "drouet", "dubreuil", "ducos", "duffy", "dufresne", "dumas", "dumont", "dumoulin",
    "dunlap", "dupont", "duprat", "dupuis", "dupuy", "duran", "durand", "durham", "dyer", "eaton",
    "engel", "erickson", "ernst", "esposito", "esteban", "estrada", "etienne", "evans", "eymard",
    "fabbri", "fabre", "faivre", "farina", "farmer", "farrell", "faulkner", "faure", "ferrand",
    "ferrari", "ferreira", "ferrer", "ferri", "figueroa", "finley", "fischer", "fitzgerald",
    "fleming", "fletcher", "fleury", "flores", "floyd", "fontaine", "fontana", "forbes", "fouquet",
    "fournier", "fowler", "francis", "frank", "franklin", "frazier", "fuchs", "fuentes", "fuller",
    "gaillard", "gallagher", "gallardo", "gallego", "galli", "gallo", "galloway", "garcia",
    "garner", "garnier", "garrett", "garrido", "gates", "gatti", "gauthier", "gautier", "george",
    "germain", "gibbs", "gil", "gilbert", "gill", "gilles", "gillet", "gimenez", "girard",
    "giraud", "girault", "glover", "godard", "gomes", "gomez", "goodman", "goodwin", "gould",
    "graf", "grassi", "greco", "greer", "gregory", "grenier", "griffith", "grondin", "gros",
    "guerin", "guerra", "guerrero", "guichard", "guillaume", "guillet", "guillon", "guillot",
    "gutierrez", "guyon", "guyot", "haas", "hahn", "hale", "haley", "hamel", "hammond", "hamon",
    "hampton", "hancock", "hansen", "hanson", "hardin", "hardy", "harmon", "harper", "harrell",
    "harrington", "hartman", "harvey", "hatfield", "hawkins", "hayden", "haynes", "hebert",
    "heinrich", "heinz", "henson", "hermann", "herrera", "herrero", "herve", "hess", "hidalgo",
    "hines", "hoarau", "hobbs", "hodge", "hodges", "hogan", "holden", "holland", "holloway",
    "holt", "hooper", "hopkins", "horn", "horton", "howe", "howell", "hubbard", "huber", "hubert",
    "huet", "huff", "hughes", "hull", "humbert", "humphrey", "hurst", "hutchinson", "ibanez",
    "iglesias", "ingram", "jacob", "jacobs", "jacques", "jacquet", "jarvis", "jefferson",
    "jennings", "jensen", "johns", "joly", "joseph", "joubert", "jourdan", "joyce", "julien",
    "jung", "kaufman", "keller", "kemp", "kerr", "kidd", "kirby", "kirk", "klein", "knapp", "knox",
    "koch", "kolb", "kraft", "kramer", "kruse", "kuhn", "kurz", "labbe", "lacombe", "lacroix",
    "lagarde", "laine", "lambert", "lamy", "lang", "langlois", "laporte", "laroche", "larson",
    "laurent", "lawson", "leach", "lebas", "leblanc", "leblond", "lebon", "lebreton", "lebrun",
    "leclerc", "leclercq", "lecomte", "leconte", "ledoux", "lefebvre", "lefeuvre", "lefort",
    "legrand", "legros", "lejeune", "lemaire", "lemaitre", "lemoine", "lemonnier", "lenoir",
    "leon", "leone", "leroux", "leroy", "lesage", "lester", "leveque", "levine", "levy",
    "lindemann", "lindsey", "livingston", "logan", "lombardi", "longo", "lopez", "lorenz",
    "lorenzo", "lowe", "lozano", "lucas", "ludwig", "lynch", "macdonald", "maddox", "mahoney",
    "maillard", "maillot", "mallet", "malone", "mancini", "mann", "manning", "marchal", "marchand",
    "marchi", "marechal", "mariani", "marie", "mariette", "marin", "marini", "marquez", "martel",
    "martin", "martineau", "martinelli", "masse", "massey", "masson", "mathews", "mathieu",
    "maury", "maxwell", "mayer", "mccall", "mccann", "mccarthy", "mcclain", "mcconnell",
    "mccormick", "mccoy", "mccullough", "mcdaniel", "mcfarland", "mcgee", "mcintosh", "mckay",
    "mckee", "mckinney", "mclaughlin", "mcmillan", "mcneil", "mcpherson", "medina", "melton",
    "menard", "mendez", "mercer", "mercier", "merrill", "mertens", "meunier", "meyer", "meyers",
    "michaud", "michel", "middleton", "millet", "molina", "monnier", "monroe", "montero",
    "montgomery", "mora", "morales", "morel", "moreno", "moretti", "morin", "morse", "morton",
    "moulin", "mourier", "moya", "mueller", "muller", "mullins", "munoz", "murray", "myers",
    "nash", "navarro", "neal", "neveu", "newman", "newton", "nicolas", "nielsen", "nieto", "noel",
    "nolan", "norman", "norris", "norton", "nunez", "oconnell", "odom", "oliver", "olivier",
    "olsen", "oneal", "ortega", "ortiz", "osborne", "owen", "pace", "pacheco", "padilla",
    "palumbo", "parisi", "parra", "parrish", "parsons", "pascual", "pasquier", "pastor", "pate",
    "patrick", "patton", "paul", "payet", "payne", "pearson", "pellegrini", "pelletier", "pena",
    "pennington", "perkins", "perrier", "perrin", "perrot", "petersen", "petit", "petitjean",
    "phelps", "picard", "pichon", "pierre", "pineau", "pittman", "pohl", "poirier", "pollard",
    "pons", "poole", "poulain", "pratt", "preston", "prevost", "prieto", "pruitt", "pugh", "quinn",
    "ramos", "ramsey", "randall", "randolph", "rasmussen", "raymond", "remy", "renard", "renaud",
    "rey", "reyes", "reynaud", "rhodes", "ricci", "richard", "richer", "richmond", "rigaud",
    "riggs", "rinaldi", "rios", "riva", "rivas", "riviere", "rizzi", "roach", "robbins",
    "roberson", "robin", "robles", "rocha", "roche", "rocher", "rodgers", "rodriguez", "roger",
    "rojas", "rolland", "rollins", "roman", "romano", "romero", "rosales", "rossi", "rossignol",
    "roussel", "rousset", "roux", "rowe", "rowland", "roy", "royer", "rubio", "ruggiero", "ruiz",
    "russo", "rutledge", "sabatier", "saez", "sala", "salinas", "sampson", "sanchez", "sanna",
    "santana", "santiago", "santoro", "santos", "sanz", "sauer", "saunders", "sauvage", "schmid",
    "schmitt", "schneider", "schreiber", "schubert", "schulte", "schultz", "schulz", "schumacher",
    "schwartz", "seidel", "sellers", "serra", "serrano", "sexton", "shaffer", "shannon", "shelton",
    "shepard", "shepherd", "sheppard", "sherman", "simon", "simpson", "sims", "singleton",
    "skinner", "slater", "soler", "solomon", "sommer", "sosa", "soto", "spence", "stafford",
    "stanley", "steele", "stein", "stephenson", "stevenson", "stokes", "strickland", "stuart",
    "suarez", "sullivan", "sutton", "swanson", "sweeney", "talley", "tanguy", "tanner", "tate",
    "terry", "tessier", "testa", "texier", "thibault", "thomas", "thornton", "tissot", "todd",
    "torres", "tournier", "townsend", "traore", "travis", "trevino", "turpin", "tyler",
    "underwood", "valdez", "valencia", "valette", "vallee", "vallet", "vance", "vargas", "vasseur",
    "vaughn", "vazquez", "vega", "velasco", "velazquez", "verdier", "vicente", "vidal", "villa",
    "villarreal", "vincent", "vitale", "vogel", "voisin", "voss", "wade", "walter", "walters",
    "walther", "walton", "ward", "warner", "watkins", "watts", "weber", "welch", "wendt",
    "wheeler", "whitaker", "whitehead", "whitley", "wiggins", "wilcox", "wilder", "wilkerson",
    "wilkins", "wilkinson", "william", "williamson", "winkler", "winters", "wolff", "wong",
    "woodard", "wyatt", "yates", "zamora", "ziegler", "zimmerman",
];

/// Given names of more cultures (PL, CZ, HU, TR, Arabic, IN, CN, JP, KR,
/// VN, West / East African, Nordic, FI, GR, RU / UA, PT / BR, ES, IT),
/// folded.
#[rustfmt::skip]
const GIVEN_NAMES_WORLD: &[&str] = &[
    "aadhya", "aanya", "aarav", "abdelkader", "abderrahmane", "abdoulaye", "abdullah", "abena",
    "adaeze", "ade", "aditya", "adrian", "adwoa", "afonso", "agnes", "agnieszka", "ahmad", "ahmet",
    "aicha", "aisha", "akane", "akira", "akosua", "alberto", "alejandro", "alena", "alessandro",
    "alexander", "alexey", "ali", "alice", "alicja", "alina", "aline", "ama", "amaka", "amel",
    "amina", "aminata", "amit", "amparo", "ana", "ananya", "anas", "anastasia", "anders", "andrea",
    "andrey", "andriy", "andrzej", "angel", "angelo", "anh", "anika", "aniko", "anil", "anjali",
    "anna", "anne", "antonio", "antti", "aoi", "arjun", "arne", "artem", "arturo", "arun", "ashok",
    "astrid", "attila", "awa", "axel", "ayaka", "ayman", "ayse", "babatunde", "balazs", "barbara",
    "bartlomiej", "bassam", "beata", "beatriz", "bence", "bernardo", "birgitta", "bjorn", "bo",
    "bogdan", "bohdan", "boubacar", "bruna", "bruno", "bukola", "burak", "busra", "camila",
    "camilla", "carlo", "carlos", "carolina", "chaima", "chao", "cheikh", "chiamaka", "chinedu",
    "christos", "chukwuemeka", "claudio", "concepcion", "csaba", "daiki", "daniele", "danuta",
    "daria", "dariusz", "davide", "deepika", "derya", "dimitra", "dimitris", "dinesh", "diogo",
    "divya", "diya", "djamel", "dmitry", "dolores", "domenico", "dominik", "dora", "dorota",
    "dounia", "doyun", "duarte", "duc", "ebba", "ebru", "eduardo", "efua", "egor", "ekaterina",
    "elena", "eleni", "elias", "elif", "ella", "elsa", "elzbieta", "emeka", "emil", "emilia",
    "emine", "emre", "enrique", "erik", "ernesto", "erzsebet", "esra", "eszter", "eunji", "eva",
    "ewa", "fabrizio", "fadi", "fang", "farid", "fatima", "fatma", "fatou", "federico", "femi",
    "ferenc", "fernanda", "fernando", "folake", "francesco", "francisca", "francisco", "franco",
    "frantisek", "frederik", "freja", "funmilayo", "gabor", "gabriel", "gabriela", "gabriele",
    "ganesh", "geeta", "gianni", "giorgos", "giovanni", "giuseppe", "goncalo", "grazyna",
    "grzegorz", "guadalupe", "gulsen", "gustav", "hafida", "hajar", "halil", "halima", "halina",
    "halyna", "hana", "hanh", "hanna", "hanne", "hao", "haruka", "haruto", "hasan", "hatice",
    "hauwa", "hayoon", "hector", "henning", "henrik", "henryk", "hicham", "hilde", "hina", "hinata",
    "hiroshi", "hisham", "hoa", "hong", "houria", "hua", "hubert", "hugo", "hui", "hulya", "hung",
    "huong", "huseyin", "huy", "hyejin", "hyun", "ibrahim", "ibrahima", "ichiro", "ida", "igor",
    "ikechukwu", "ikram", "ilias", "ilona", "ines", "ingrid", "irena", "irina", "iryna", "ishaan",
    "ismail", "istvan", "ivan", "iwona", "jamal", "jan", "jana", "janos", "jari", "jaroslav",
    "javier", "jens", "jerzy", "jesus", "jie", "jiho", "jihun", "jimin", "jing", "jiri", "jisoo",
    "jitka", "jiwoo", "joanna", "joao", "johan", "jolanta", "jonas", "jorge", "jose", "josef",
    "jozsef", "juan", "juha", "jukka", "juliana", "jun", "justyna", "kadiatou", "kaito", "kamel",
    "karel", "kari", "karim", "karima", "karin", "karl", "karolina", "kasper", "katalin",
    "katarzyna", "katerina", "kavya", "kazimierz", "kazuki", "keiko", "kemal", "kenji", "khadija",
    "khaled", "khoa", "kinga", "kiran", "kirill", "klara", "knut", "kofi", "kojo", "kostas",
    "krishna", "kristian", "kristina", "krisztina", "krystyna", "krzysztof", "ksenia", "kunle",
    "kwabena", "kwame", "lakshmi", "lan", "larissa", "lars", "laszlo", "latifa", "laura", "lei",
    "lene", "lenka", "leonardo", "leonor", "leticia", "li", "liam", "lin", "lina", "ling", "linh",
    "linnea", "lorenzo", "luana", "lucas", "lucie", "luigi", "luis", "lukas", "lukasz", "madalena",
    "mads", "magnus", "mahesh", "mahmoud", "mahmut", "mai", "maja", "malgorzata", "malika",
    "mamadou", "manoj", "manuel", "marcello", "marek", "margareta", "margarida", "maria", "mariama",
    "mariana", "marie", "mario", "marit", "mariusz", "marta", "martim", "martin", "martyna",
    "massimo", "mathias", "matilde", "matteo", "matti", "maurizio", "maxim", "meera", "mehdi",
    "mehmet", "mei", "meriem", "merve", "mette", "michaela", "michal", "michele", "miguel", "mika",
    "mikael", "mikhail", "milan", "ming", "minh", "minji", "minjun", "minna", "mio", "miroslav",
    "misaki", "miyu", "modou", "mohammed", "mourad", "moussa", "muhammad", "murat", "mustafa",
    "mykola", "myra", "na", "nabil", "nabila", "naima", "nam", "nanami", "naoki", "naoko", "nassim",
    "natalia", "nataliya", "naveen", "navya", "nawal", "neha", "ngoc", "ngozi", "niels", "nikita",
    "nikos", "nils", "nisha", "nnamdi", "noah", "nora", "nordine", "obinna", "oksana", "ole",
    "oleg", "oleksandr", "oleksiy", "olena", "olga", "olof", "olumide", "oluwaseun", "omer",
    "ondrej", "oskar", "osman", "oumou", "ousmane", "ozlem", "pablo", "paivi", "panagiotis",
    "paolo", "pari", "patricia", "patrycja", "paulina", "pavel", "pawel", "pedro", "pekka", "peng",
    "pernille", "peter", "petr", "petra", "phuc", "phuong", "pietro", "piotr", "polina", "pooja",
    "poul", "pradeep", "prakash", "priscila", "priya", "przemyslaw", "qiang", "qing", "quang",
    "rachid", "rachida", "radek", "radha", "rafael", "rafal", "rahul", "rajesh", "ramazan",
    "ramesh", "rami", "rasmus", "raul", "recep", "redouane", "reka", "rekha", "renata", "reyansh",
    "ricardo", "riccardo", "riikka", "riku", "rim", "rin", "roberto", "rocio", "rodrigo", "rohan",
    "roman", "rosario", "ryota", "ryszard", "saanvi", "saga", "sai", "saida", "sakura", "salih",
    "salma", "salvatore", "samer", "samia", "sandor", "sanjay", "santiago", "sari", "sarra",
    "satoshi", "segun", "seojun", "seoyeon", "seoyun", "sergey", "sergio", "serkan", "seydou",
    "shaurya", "shota", "shreya", "sibel", "silje", "simone", "sindre", "siwoo", "slawomir",
    "sneha", "sofia", "sofiane", "soledad", "sooyoung", "soren", "sota", "souad", "soufiane",
    "stefano", "suleyman", "sunil", "sunita", "suresh", "susanne", "sven", "svetlana", "svitlana",
    "swati", "szymon", "tadeusz", "takeshi", "takumi", "tamas", "tao", "taras", "tarek", "taro",
    "tatiana", "teresa", "tetyana", "thanh", "thao", "thomas", "thu", "tiago", "tiina", "timea",
    "timo", "tomas", "tomasz", "tommaso", "tomoko", "tor", "trang", "trung", "tuan", "tugba",
    "tunde", "urszula", "vaclav", "vanessa", "vasilis", "vasyl", "veronika", "vihaan", "vijay",
    "vikram", "ville", "vincenzo", "vinh", "vivaan", "vladimir", "vojtech", "volkan", "walid",
    "wei", "weronika", "wiam", "wieslaw", "wiktor", "wiktoria", "william", "wilma", "wojciech",
    "xia", "xin", "xiu", "yacine", "yan", "yang", "yannis", "yasmina", "yaw", "yetunde", "ying",
    "yoko", "younes", "yu", "yui", "yuki", "yulia", "yun", "yuna", "yuri", "yuriy", "yusuf", "yuto",
    "zainab", "zakaria", "zbigniew", "zdenek", "zeynep", "ziad", "zofia", "zoltan", "zsolt",
    "zsuzsanna",
    "cem", "selin", "deniz", "oguz", "gokhan", "yasemin", "aysegul", "ozan", "eren", "kaan", "berk", "ece", "irem", "cansu", "gizem", "pinar", "sevgi", "tolga", "serdar", "onur", "baris", "cagla", "seda", "melike", "hakan", "umut", "sinan", "tugce", "didem", "ipek", "harsha", "nandini", "siddharth", "karthik", "meenakshi", "vikas", "nikhil", "shruti", "pallavi", "aishwarya", "daichi", "shun", "kaede", "sho", "yuka", "natsuki", "kazuya", "takahiro", "ayumi", "yaa", "babajide", "olamide", "chidi", "uche", "chioma", "nkechi", "ifeoma", "eskil", "leif", "solveig", "torben", "hakon", "liv", "sigurd", "halvard", "ragnhild", "tove",
];

/// Surnames of more cultures (same families), folded.
#[rustfmt::skip]
const SURNAMES_WORLD: &[&str] = &[
    "abbas", "abe", "abramov", "acar", "acheampong", "adamczyk", "adamski", "adebayo", "adeyemi",
    "afanasiev", "afolabi", "agyeman", "ahn", "ahonen", "ahuja", "akimov", "aktas", "alaoui",
    "aleksandrov", "alekseev", "alexiou", "ali", "almeida", "alves", "amrani", "amundsen",
    "andersen", "andersson", "ando", "andrade", "andreassen", "andreev", "andresen", "andrzejewski",
    "anisimov", "ansah", "antal", "antonopoulou", "antonov", "antunes", "aoki", "appiah", "arai",
    "araujo", "arkhipov", "arora", "arslan", "arvidsson", "asante", "aslan", "athanasiou", "avci",
    "axelsson", "aydin", "azevedo", "aziz", "ba", "babatunde", "babic", "bae", "baek", "bah", "bak",
    "bakke", "bakken", "balazs", "balde", "balog", "balogh", "balogun", "banerjee", "baran",
    "baranov", "baranowski", "barbosa", "barros", "barry", "bartos", "batista", "belkacem", "belov",
    "belyaev", "benali", "benes", "bengtsson", "benjelloun", "benmoussa", "bennani", "benyahia",
    "berg", "berge", "berglund", "bergman", "bergqvist", "bergstrom", "berrada", "bhatia",
    "bhattacharya", "biro", "biryukov", "bjork", "blazek", "blazevic", "blomqvist", "boateng",
    "bogdan", "bogdanov", "bondar", "bondarenko", "borisov", "borkowski", "boros", "bose",
    "bouazza", "boudiaf", "bouzid", "boyko", "bozkurt", "brzezinski", "bui", "bulut", "bykov",
    "cai", "cakir", "camara", "campos", "cao", "cardoso", "carvalho", "castro", "cavalcanti",
    "celik", "cermak", "cerny", "cetin", "cha", "chakraborty", "chan", "chatterjee", "chauhan",
    "chen", "cheng", "cherif", "chernov", "chernyshev", "cheung", "chiba", "chmielewski", "cho",
    "choi", "chopra", "chow", "chraibi", "christensen", "christodoulou", "cieslak", "ciobanu",
    "cisse", "claesson", "coelho", "constantin", "conte", "correia", "costa", "coulibaly",
    "cristea", "cruz", "cunha", "czarnecki", "czerwinski", "dabrowski", "dahl", "dang",
    "danielsson", "danilov", "darko", "darwish", "das", "davydov", "dembele", "demir", "deng",
    "denisov", "desai", "diallo", "dias", "dieng", "dimitriou", "ding", "dinh", "dinu", "diop",
    "djordjevic", "dmitriev", "do", "doan", "dogan", "dolezal", "dong", "doumbia", "dragomir", "du",
    "dubey", "dudek", "dumitru", "duong", "dutta", "dvorak", "efimov", "efremov", "egorov", "eide",
    "eklund", "elamin", "elidrissi", "emelyanov", "endo", "engstrom", "erdogan", "eriksen",
    "eriksson", "ermakov", "evensen", "eze", "fall", "farias", "farkas", "farouk", "fassi", "faye",
    "fazekas", "fedorov", "fedotov", "feher", "fekete", "feng", "fernandes", "ferreira", "fiala",
    "figueiredo", "filatov", "filippov", "florea", "fodor", "fomin", "fonseca", "forsberg",
    "fransson", "fredriksen", "fredriksson", "freitas", "frolov", "fu", "fujii", "fujimoto",
    "fujita", "fujiwara", "fukuda", "fung", "gajewski", "gal", "gao", "gavrilov", "georgiou",
    "gerasimov", "gheorghe", "ghosh", "giannopoulos", "glowacki", "golubev", "gomes", "goncalves",
    "goncharov", "gorbunov", "gorski", "goto", "grabowski", "grachev", "grgic", "grigoriev",
    "grishin", "gromov", "grover", "gueye", "gul", "guler", "gulyas", "gundersen", "gunes",
    "gunnarsson", "guo", "gupta", "gusev", "gustafsson", "ha", "haddad", "hagen", "hajek",
    "hakansson", "halvorsen", "hamalainen", "hamdan", "hamidi", "han", "hansen", "hansson", "hara",
    "harada", "hasegawa", "hashimoto", "hassan", "hauge", "haugen", "hayashi", "he", "heikkila",
    "heikkinen", "heinonen", "henriksen", "henriksson", "heo", "hirano", "ho", "hoang", "holm",
    "holmberg", "holub", "hong", "horak", "horvat", "horvath", "hu", "huang", "hussein", "huynh",
    "hwang", "ibrahim", "ikeda", "ilic", "ilyin", "imai", "inoue", "ioannou", "ionescu", "isaev",
    "isaksson", "ishida", "ishii", "ishikawa", "isik", "ito", "ivanov", "iversen", "iwasaki",
    "iyengar", "iyer", "jablonski", "jacobsen", "jakab", "jakobsen", "jakobsson", "jakubowski",
    "jang", "jankowski", "jansson", "jarvinen", "jasinski", "jaworski", "jelinek", "jensen", "jeon",
    "jesus", "jiang", "jin", "johannessen", "johansen", "johansson", "johnsen", "jokinen",
    "jonsson", "joo", "jorgensen", "joshi", "jovanovic", "juhasz", "jung", "juric", "kaczmarek",
    "kadlec", "kalinin", "kalinowski", "kamau", "kaminski", "kaneko", "kang", "kante", "kaplan",
    "kapoor", "kara", "karagiannis", "karim", "kariuki", "karjalainen", "karlsen", "karlsson",
    "karpov", "kato", "katona", "kaya", "kazakov", "kazmierczak", "keita", "kelemen", "keskin",
    "kettani", "khalil", "khanna", "khoury", "kikuchi", "kilic", "kim", "kimura", "kinnunen",
    "kinoshita", "kiraly", "kirillov", "kis", "kiselev", "kiselyov", "klimov", "knezevic",
    "knudsen", "knutsen", "ko", "kobayashi", "koc", "kocsis", "kojima", "kolar", "kolesnikov",
    "kolesov", "kolodziej", "komarov", "konate", "kondo", "kondratiev", "kone", "konecny",
    "konovalov", "konstantinou", "koo", "kopecky", "korhonen", "korkmaz", "korolev", "koskinen",
    "kotov", "kovacevic", "kovacic", "kovacs", "kovalchuk", "kovalenko", "kovalev", "kovalyov",
    "kovar", "kowalczyk", "kowalski", "kozlov", "kozlowski", "krajewski", "kral", "kravchenko",
    "krawczyk", "krishnan", "kristensen", "kristiansen", "kristoffersen", "kriz", "krol", "krylov",
    "kubiak", "kubo", "kucera", "kucharski", "kudo", "kudryavtsev", "kulikov", "kumar", "kurt",
    "kuzmin", "kuznetsov", "kwak", "kwiatkowski", "kwok", "kwon", "lahlou", "lahtinen", "laine",
    "laitinen", "lakatos", "lam", "larsen", "larsson", "laskowski", "laszlo", "lau", "lazar",
    "lazarev", "le", "lebedev", "lee", "lehtinen", "lehtonen", "leonov", "leung", "lewandowski",
    "li", "liang", "lien", "lim", "lima", "lin", "lind", "lindberg", "lindgren", "lindqvist",
    "lindstrom", "lis", "liu", "lofgren", "lopes", "lourenco", "lu", "lui", "lukacs", "lukin",
    "lund", "lundberg", "lunde", "lundgren", "lundin", "lundqvist", "luo", "luu", "ly", "lysenko",
    "ma", "machado", "maciejewski", "maeda", "magnusson", "magyar", "mai", "majewski", "mak",
    "makarov", "makela", "makinen", "makowski", "makris", "maksimov", "malhotra", "malinowski",
    "maly", "malyshev", "mansour", "marchenko", "marciniak", "marek", "maric", "marin", "markov",
    "markovic", "marques", "martins", "martinsen", "martynov", "maruyama", "maslov", "masuda",
    "matei", "mathisen", "matos", "matsuda", "matsui", "matsumoto", "matsuo", "mattila", "mattsson",
    "matveev", "mazur", "mazurek", "mbaye", "medvedev", "mehta", "melnikov", "melnyk", "melo",
    "mendes", "menon", "mensah", "meszaros", "meziane", "michalak", "michalski", "mihai",
    "mikhailov", "milosevic", "min", "miranda", "mironov", "mishra", "miura", "miyamoto",
    "miyazaki", "moe", "moen", "moiseev", "moldovan", "molnar", "monteiro", "moreira", "mori",
    "morita", "moroz", "morozov", "mostafa", "moura", "mukherjee", "munteanu", "murakami", "murata",
    "mwangi", "na", "nagy", "naidu", "nair", "najjar", "nakagawa", "nakajima", "nakamura", "nakano",
    "nakayama", "nam", "nascimento", "nasser", "naumov", "navratil", "nazarov", "ndiaye", "neagu",
    "nemec", "nemeth", "neves", "ng", "ngo", "nguyen", "niang", "nielsen", "niemi", "nieminen",
    "nikiforov", "nikitin", "nikolaev", "nikolaou", "nikolic", "nilsen", "nilsson", "nishimura",
    "njoroge", "noguchi", "noh", "nomura", "nordstrom", "novak", "novikov", "novotny", "nowak",
    "nowakowski", "nowicki", "nunes", "nwosu", "nyberg", "nygard", "nystrom", "obi", "ochieng",
    "odhiambo", "ogawa", "ogunleye", "oh", "ohno", "oikonomou", "okada", "okafor", "okamoto",
    "okeke", "okonkwo", "oladipo", "olah", "oliveira", "oliynyk", "olsen", "olsson", "olszewski",
    "omar", "onishi", "ono", "orban", "orlov", "orsos", "osei", "osipov", "ostrowski", "ota",
    "otieno", "otsuka", "ovchinnikov", "owusu", "ozcan", "ozdemir", "ozer", "ozkan", "ozturk",
    "pan", "pandey", "panov", "papadakis", "papadopoulos", "papp", "pappas", "patel", "paulsen",
    "pavlov", "pavlovic", "pawlak", "pawlowski", "pedersen", "peng", "pereira", "persson",
    "petrenko", "petrov", "petrovic", "pettersen", "pettersson", "pham", "phan", "pietrzak",
    "pillai", "pinter", "pinto", "piotrowski", "pires", "pokorny", "polak", "polat", "polishchuk",
    "polyakov", "ponomarev", "pop", "popa", "popescu", "popov", "pospisil", "potapov", "prochazka",
    "prokhorov", "przybylski", "racz", "radu", "rahman", "raman", "ramos", "rantanen", "rao",
    "raposo", "rasmussen", "rathore", "reddy", "reis", "ren", "rezende", "ribeiro", "rocha",
    "rodionov", "rodrigues", "romanov", "roy", "rudenko", "rumyantsev", "rusu", "rutkowski",
    "ruzicka", "ryu", "saadi", "saarinen", "sadowski", "saha", "sahin", "said", "saito", "sakai",
    "sakamoto", "sakurai", "saleh", "salem", "salminen", "salo", "salonen", "samuelsson",
    "sandberg", "sandor", "sane", "sangare", "sano", "santos", "sari", "sasaki", "sato",
    "savchenko", "savelyev", "savolainen", "sawicki", "sayed", "seck", "sedlacek", "semenov", "sen",
    "seo", "serban", "sergeev", "sethi", "shah", "sharma", "shcherbakov", "shen", "shevchenko",
    "shevchuk", "shibata", "shimizu", "shin", "sidibe", "sidorov", "sikora", "sikorski", "silva",
    "simoes", "simon", "simsek", "singh", "sipos", "sjoberg", "slimani", "smirnov", "soares",
    "sobczak", "sobolev", "soderberg", "sokolov", "sokolowski", "solberg", "solheim", "soloviev",
    "somogyi", "son", "sorensen", "sorokin", "sousa", "souza", "sow", "stan", "stankovic",
    "stepanek", "stepanov", "stepien", "stoica", "stojanovic", "strand", "su", "subramanian",
    "sugawara", "sugimoto", "sugiyama", "sung", "suzuki", "svendsen", "svensson", "svoboda",
    "sylla", "szabo", "szalai", "szczepanski", "szewczyk", "szilagyi", "szucs", "szulc",
    "szymanski", "szymczak", "takacs", "takada", "takagi", "takahashi", "takeda", "takeuchi",
    "taleb", "tamura", "tanaka", "tang", "taniguchi", "tarasov", "tas", "tavares", "tazi",
    "teixeira", "thakur", "tian", "tikhonov", "timofeev", "titov", "tiwari", "tkachenko", "tkachuk",
    "todorovic", "tomaszewski", "torok", "toth", "touati", "toure", "tran", "traore", "trinh",
    "trofimov", "truong", "tsang", "tudor", "tuominen", "turan", "turunen", "uchida", "ueda",
    "ueno", "unal", "urban", "urbanski", "vanek", "varga", "vasileiou", "vasiliev", "verma",
    "vesely", "vieira", "vinogradov", "virtanen", "vlasov", "vlcek", "vo", "volkov", "vorobiev",
    "voronin", "vu", "vukovic", "wada", "walczak", "wallin", "wang", "wanjiru", "wasilewski",
    "watanabe", "wei", "wieczorek", "wikstrom", "wilczynski", "wilk", "wisniewski", "witkowski",
    "wlodarczyk", "wojciechowski", "wojcik", "wong", "woo", "wozniak", "wrobel", "wroblewski", "wu",
    "wysocki", "xiao", "xie", "xu", "yadav", "yakovlev", "yalcin", "yamada", "yamaguchi",
    "yamamoto", "yamashita", "yamazaki", "yang", "yao", "yavuz", "ye", "yeung", "yildirim",
    "yildiz", "yilmaz", "yokoyama", "yoo", "yoon", "yoshida", "yousef", "yu", "yuan", "zaitsev",
    "zajac", "zakharov", "zakrzewski", "zalewski", "zawadzki", "zeman", "zeng", "zerrouki", "zhang",
    "zhao", "zheng", "zhong", "zhou", "zhu", "zhukov", "zhuravlev", "zielinski", "ziolkowski",
];

/// Places (major cities, countries, US states, regions) and brands (car
/// makers, fashion houses, large companies) whose names are also person
/// names (`Austin`, `Lincoln`, `Hugo Boss`): folded whole values, words
/// separated by single spaces. A column of such values is not a column of
/// person names.
#[rustfmt::skip]
const ENTITIES: &[&str] = &[
    "aarhus", "aberdeen", "abidjan", "abu dhabi", "abuja", "accra", "addis ababa", "adelaide",
    "adobe", "airbnb", "airbus", "aix en provence", "ajaccio", "akron", "alabama", "alaska",
    "albania", "alberta", "albuquerque", "aldi", "alexandria", "alfa romeo", "algeria", "algerie",
    "algiers", "alicante", "allemagne", "almere", "alsace", "amazon", "amiens", "amman",
    "amsterdam", "anaheim", "anchorage", "andalucia", "andalusia", "angers", "ankara", "annecy",
    "antibes", "antwerp", "antwerpen", "apple", "aquitaine", "argenteuil", "argentina", "arizona",
    "arkansas", "arlington", "armani", "armenia", "aston martin", "asuncion", "athens", "atlanta",
    "auchan", "auckland", "audi", "augsburg", "aurora", "austin", "australia", "austria",
    "autriche", "auvergne", "avignon", "azerbaijan", "baghdad", "bakersfield", "balenciaga",
    "baltimore", "bangalore", "bangkok", "bangladesh", "barcelona", "bari", "basel", "bastia",
    "bath", "baton rouge", "bavaria", "bayern", "beijing", "beirut", "belarus", "belfast",
    "belgique", "belgium", "belo horizonte", "bengaluru", "bentley", "bergen", "berlin", "bern",
    "besancon", "bielefeld", "bilbao", "birmingham", "bmw", "bochum", "boeing", "bogota", "boise",
    "bologna", "bonn", "bordeaux", "bosch", "bosnia", "boston", "boulogne billancourt", "bourgogne",
    "braga", "brasilia", "brazil", "breda", "bremen", "brescia", "brest", "bretagne", "brighton",
    "brisbane", "bristol", "british columbia", "brno", "bruges", "brugge", "brussels", "bruxelles",
    "bucharest", "bucuresti", "budapest", "buenos aires", "buffalo", "bugatti", "buick", "bulgaria",
    "burberry", "busan", "cadillac", "caen", "cairo", "calais", "calgary", "california",
    "calvin klein", "cambridge", "canada", "canberra", "cancun", "cannes", "cape town", "caracas",
    "cardiff", "carrefour", "casablanca", "catalonia", "catalunya", "catania", "celine",
    "champagne", "chandler", "chanel", "charleroi", "charleston", "charlotte", "chengdu", "chennai",
    "chesapeake", "chester", "chevrolet", "chicago", "chile", "china", "chloe", "christchurch",
    "christian dior", "christian louboutin", "chrysler", "chula vista", "cincinnati", "cisco",
    "citroen", "clermont ferrand", "cleveland", "clinton", "cluj napoca", "coco chanel", "coimbra",
    "cologne", "colombes", "colombia", "colorado", "colorado springs", "columbus", "connecticut",
    "copenhagen", "cordoba", "cork", "corpus christi", "corse", "creteil", "croatia", "cuba",
    "cupra", "curitiba", "cyprus", "czech republic", "czechia", "dacia", "dakar", "dallas",
    "danone", "dayton", "debrecen", "decathlon", "delaware", "delhi", "dell", "den haag", "denmark",
    "denver", "des moines", "detroit", "deutschland", "dhaka", "dijon", "dior", "disney", "dodge",
    "doha", "dolce gabbana", "dortmund", "dresden", "dubai", "dublin", "duisburg", "dundee",
    "durban", "durham", "dusseldorf", "edinburgh", "edmonton", "egypt", "eindhoven", "el paso",
    "engie", "england", "ericsson", "espagne", "espana", "espoo", "essen", "estee lauder",
    "estonia", "ethiopia", "faro", "fendi", "ferrari", "fes", "fiat", "finland", "firenze",
    "florence", "florida", "ford", "fort wayne", "fort worth", "fortaleza", "france", "frankfurt",
    "franklin", "freiburg", "fremont", "fresno", "fukuoka", "galicia", "galway", "garland",
    "gdansk", "geneva", "geneve", "genoa", "genova", "gent", "georgia", "germany", "ghana", "ghent",
    "gijon", "gilbert", "giorgio armani", "givenchy", "glasgow", "glendale", "google", "goteborg",
    "gothenburg", "granada", "graz", "greece", "greensboro", "grenoble", "groningen", "guadalajara",
    "guangzhou", "gucci", "guy laroche", "halifax", "hamburg", "hamilton", "hannover", "hanoi",
    "hanover", "hartford", "havana", "hawaii", "heidelberg", "helsinki", "henderson", "hermes",
    "hesse", "hessen", "hialeah", "ho chi minh city", "honda", "hong kong", "honolulu", "houston",
    "hp", "hugo boss", "hungary", "hyderabad", "hyundai", "ibm", "iceland", "idaho", "ikea",
    "ile de france", "illinois", "incheon", "india", "indiana", "indianapolis", "indonesia",
    "innsbruck", "intel", "iowa", "iran", "iraq", "ireland", "irvine", "irving", "israel",
    "istanbul", "italia", "italie", "italy", "izmir", "jackson", "jacksonville", "jaguar",
    "jakarta", "japan", "jean paul gaultier", "jeddah", "jeep", "jersey city", "jerusalem",
    "johannesburg", "jordan", "kansas", "kansas city", "karachi", "karlsruhe", "kazakhstan",
    "kentucky", "kenya", "kenzo", "kharkiv", "kia", "kiev", "kinshasa", "knoxville", "kobe",
    "kobenhavn", "kolkata", "koln", "korea", "krakow", "kuala lumpur", "kyiv", "kyoto", "la paz",
    "la rochelle", "lacoste", "lagos", "lahore", "lamborghini", "lancia", "land rover", "las vegas",
    "latvia", "lausanne", "le havre", "le mans", "lebanon", "leclerc", "leeds", "leicester",
    "leipzig", "lenovo", "lexington", "lexus", "liban", "lidl", "liege", "lille", "lima",
    "limerick", "limoges", "lincoln", "linz", "lisboa", "lisbon", "lithuania", "little rock",
    "liverpool", "lodz", "lombardia", "lombardy", "london", "long beach", "loreal", "lorraine",
    "los angeles", "louis vuitton", "louisiana", "louisville", "lubbock", "lucerne", "lugano",
    "luxembourg", "lviv", "lyon", "madison", "madrid", "maine", "malaga", "malaysia", "malmo",
    "malta", "manaus", "manchester", "manila", "manitoba", "mannheim", "marc jacobs", "maroc",
    "marrakech", "marseille", "maryland", "maserati", "massachusetts", "mazda", "mclaren",
    "medellin", "melbourne", "memphis", "mercedes", "mercedes benz", "mesa", "messina", "meta",
    "metz", "mexico", "mexico city", "miami", "michael kors", "michelin", "michigan", "microsoft",
    "milan", "milano", "milwaukee", "mini", "minneapolis", "minnesota", "minsk", "mississippi",
    "missouri", "mitsubishi", "mobile", "modena", "monaco", "montana", "monterrey", "montevideo",
    "montgomery", "montpellier", "montreal", "montreuil", "morocco", "moschino", "moscow",
    "mulhouse", "mumbai", "munchen", "munich", "munster", "murcia", "nagoya", "nairobi", "namur",
    "nancy", "nanterre", "nantes", "naples", "napoli", "nashville", "nebraska", "nederland",
    "nestle", "netflix", "netherlands", "nevada", "new delhi", "new hampshire", "new jersey",
    "new mexico", "new orleans", "new york", "new zealand", "newark", "newcastle", "nice",
    "nigeria", "nijmegen", "nimes", "nissan", "nokia", "norfolk", "normandie", "north carolina",
    "north dakota", "north las vegas", "norway", "nottingham", "nuremberg", "nurnberg", "oakland",
    "occitanie", "odense", "odesa", "ohio", "oklahoma", "oklahoma city", "omaha", "ontario", "opel",
    "oracle", "oran", "orange", "oregon", "orlando", "orleans", "osaka", "oslo", "ostrava",
    "ottawa", "oxford", "padova", "padua", "pakistan", "palermo", "palma", "paris", "parma", "pau",
    "pays bas", "pennsylvania", "perpignan", "perth", "peru", "peugeot", "philadelphia",
    "philippines", "philips", "phoenix", "picardie", "pierre cardin", "pisa", "pittsburgh", "plano",
    "plymouth", "poitiers", "poland", "pologne", "porsche", "portland", "porto", "porto alegre",
    "portsmouth", "portugal", "poznan", "prada", "prague", "praha", "pretoria", "provence",
    "providence", "pune", "qatar", "quebec", "quito", "rabat", "raleigh", "ralph lauren", "recife",
    "reims", "renault", "rennes", "reno", "reykjavik", "rhode island", "richmond", "riga",
    "rio de janeiro", "riverside", "riyadh", "rolls royce", "roma", "romania", "rome", "rosario",
    "rotterdam", "roubaix", "rouen", "russia", "sachsen", "sacramento", "saint etienne",
    "saint laurent", "saint louis", "saint paul", "saint petersburg", "salamanca", "salem",
    "salesforce", "salt lake city", "salvador", "salvatore ferragamo", "salzburg", "samsung",
    "san antonio", "san diego", "san francisco", "san jose", "santa ana", "santiago", "sao paulo",
    "sapporo", "sardinia", "saudi arabia", "savannah", "savoie", "saxony", "schweiz", "scotland",
    "scottsdale", "seat", "seattle", "senegal", "seoul", "serbia", "sevilla", "seville", "sfax",
    "shanghai", "sheffield", "shenzhen", "sicilia", "sicily", "siemens", "siena", "singapore",
    "skoda", "slovakia", "slovenia", "smart", "sofia", "sony", "south africa", "south carolina",
    "south dakota", "south korea", "southampton", "spain", "spokane", "spotify", "springfield",
    "st louis", "stockholm", "stockton", "strasbourg", "stuttgart", "subaru", "suisse", "suzuki",
    "swansea", "sweden", "switzerland", "sydney", "syria", "szczecin", "tacoma", "taipei",
    "tallinn", "tampa", "tampere", "tangier", "tehran", "tel aviv", "tennessee", "tesla", "texas",
    "thailand", "the hague", "thessaloniki", "tilburg", "tokyo", "toledo", "tom ford",
    "tommy hilfiger", "torino", "toronto", "toscana", "total", "toulon", "toulouse", "tourcoing",
    "tours", "toyota", "trieste", "trondheim", "tucson", "tulsa", "tunis", "tunisia", "tunisie",
    "turin", "turkey", "turku", "tuscany", "tyler", "uber", "ukraine", "united kingdom",
    "united states", "uppsala", "usa", "utah", "utrecht", "valencia", "valentino", "valladolid",
    "vancouver", "venezia", "venezuela", "venice", "vermont", "verona", "versace", "versailles",
    "vienna", "vietnam", "vigo", "villeurbanne", "vilnius", "virginia", "virginia beach",
    "vitry sur seine", "volkswagen", "volvo", "wales", "walmart", "warren", "warsaw", "warszawa",
    "washington", "wellington", "west virginia", "wichita", "wien", "wiesbaden", "winnipeg",
    "winston salem", "wisconsin", "wroclaw", "wuhan", "wuppertal", "wyoming", "yokohama", "york",
    "yves saint laurent", "zara", "zaragoza", "zurich",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folding() {
        assert_eq!(fold("Anaïs"), "anais");
        assert_eq!(fold("ÉLODIE"), "elodie");
        assert_eq!(fold("O'Connor"), "oconnor");
        assert_eq!(fold("Straße"), "strasse");
        assert_eq!(fold("Łukasz"), "lukasz");
    }

    #[test]
    fn lists_are_folded() {
        for list in [
            GIVEN_NAMES,
            GIVEN_NAMES_MORE,
            SURNAMES,
            SURNAMES_MORE,
            GIVEN_NAMES_WORLD,
            SURNAMES_WORLD,
            NOT_NAME_WORDS,
            SURNAME_SUFFIXES,
        ] {
            for w in list {
                assert_eq!(fold(w).replace('-', ""), w.replace('-', ""), "{w}");
            }
        }
    }

    #[test]
    fn lookups() {
        assert!(is_given_name(&fold("Chloé")));
        assert!(is_surname(&fold("Kowalski")));
        assert!(has_surname_suffix("gustavsson"));
        assert!(!has_surname_suffix("son"));
        assert!(is_not_name_word("gmbh"));
        assert!(is_entity("Austin"));
        assert!(is_entity("NEW YORK"));
        assert!(is_entity("Saint-Étienne"));
        assert!(is_entity("Hugo Boss"));
        assert!(!is_entity("Jean Dupont"));
        assert_eq!(month(&fold("Févr")), Some(2));
        assert_eq!(month("mai"), Some(5));
    }
}
