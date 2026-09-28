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
    set(GIVEN_NAMES)
        .union(&set(GIVEN_NAMES_MORE))
        .copied()
        .collect()
});
static FAMILY: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| set(SURNAMES).union(&set(SURNAMES_MORE)).copied().collect());
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
        assert_eq!(month(&fold("Févr")), Some(2));
        assert_eq!(month("mai"), Some(5));
    }
}
