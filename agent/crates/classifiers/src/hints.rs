//! Column-name hints (FR + EN, and common DE / ES / IT / NL / PT words).
//!
//! A hint never produces a finding on its own: values must match too.
//! Values are detected first ([`crate::column`]); a hint lowers the share of
//! matching values a whole-value classifier needs (`pii.person_name`,
//! `pii.postal_address`, `pii.birth_date`, AWS secret access keys), lets
//! loose phone formats and raw password digests count, and raises the
//! confidence of validated classifiers. Negative names turn a hint off
//! (`phone_country`), card numbers off (`order_number`, `imei`), or make
//! 40-character AWS secrets need more evidence (`session_token`).
//!
//! Names are split into lowercase tokens on non-alphanumeric characters and
//! camelCase boundaries (`accessKeyId` -> `access`, `key`, `id`;
//! `date_naissance` -> `date`, `naissance`). For a field path, every segment
//! contributes tokens (`name.first`, `address.street`).

use unicode_normalization::UnicodeNormalization;

use crate::id::ClassifierId;

/// Longest column name examined (bytes); longer names give no hint.
const MAX_NAME_BYTES: usize = 512;

/// Tokens that name a data type directly.
const DIRECT: &[(ClassifierId, &[&str])] = &[
    (
        ClassifierId::Email,
        &[
            "email",
            "mail",
            "courriel",
            "emailaddress",
            "mailaddress",
            "adressemail",
            "correo",
            "emailaddr",
            "mailaddr",
            "epost",
        ],
    ),
    (
        ClassifierId::Phone,
        &[
            "phone",
            "tel",
            "telephone",
            "téléphone",
            "mobile",
            "portable",
            "gsm",
            "fax",
            "cell",
            "cellphone",
            "msisdn",
            "telephonenumber",
            "phonenumber",
            "mobilephone",
            "homephone",
            "telefon",
            "telefono",
            "teléfono",
            "fone",
            "handy",
            "telno",
            "phoneno",
            "tfno",
            "mob",
            "landline",
            "contactnumber",
            "phonenum",
            "numtel",
            "numerotelephone",
            "cellular",
            "cellulaire",
            "cellulare",
            "celular",
            "movil",
            "móvil",
            "mobil",
            "mobiel",
            "telefone",
            "telemovel",
            "telemóvel",
            "telefonnummer",
            "telefoonnummer",
            "handynummer",
            "mobilnummer",
            "rufnummer",
            "whatsapp",
            "sms",
            "tlf",
            "telf",
        ],
    ),
    (ClassifierId::Iban, &["iban", "rib", "bban"]),
    (
        ClassifierId::CardNumber,
        &[
            "card",
            "cardnumber",
            "pan",
            "cc",
            "ccnum",
            "carte",
            "cb",
            "creditcard",
            "cardno",
            "cardnum",
            "ccnumber",
            "ccno",
            "kreditkarte",
            "tarjeta",
            "primaryaccountnumber",
        ],
    ),
    (
        ClassifierId::Nir,
        &[
            "nir",
            "secu",
            "sécu",
            "numsecu",
            "insee",
            "ssn",
            "securite",
            "sécurité",
            "nss",
            "numss",
            "securitesociale",
            "numerosecu",
            "nirpp",
        ],
    ),
    (
        ClassifierId::BirthDate,
        &[
            "dob",
            "birth",
            "birthdate",
            "birthday",
            "dateofbirth",
            "naissance",
            "datenaissance",
            "ddn",
            "born",
            "birthdt",
            "bdate",
            "bday",
            "dateofbirth",
            "geburtsdatum",
            "geburtstag",
            "nacimiento",
            "fechanacimiento",
            "nascita",
            "datanascita",
            "geboortedatum",
            "naiss",
            "datnaiss",
        ],
    ),
    (
        ClassifierId::PersonName,
        &[
            "firstname",
            "lastname",
            "fullname",
            "givenname",
            "surname",
            "forename",
            "familyname",
            "middlename",
            "maidenname",
            "displayname",
            "prenom",
            "prénom",
            "patronyme",
            "cn",
            "sn",
            "holder",
            "cardholder",
            "titulaire",
            "fname",
            "lname",
            "apellido",
            "apellidos",
            "vorname",
            "nachname",
            "cognome",
            "voornaam",
            "achternaam",
            "nomfamille",
            "prenoms",
            "prénoms",
            "nomcomplet",
            "nomusage",
            "nomnaissance",
            "personname",
            "contactname",
            "customername",
            "clientname",
            "employeename",
            "patientname",
            "membername",
            "ownername",
            "holdername",
            "accountholder",
            "beneficiary",
            "beneficiaire",
            "bénéficiaire",
        ],
    ),
    (
        ClassifierId::PostalAddress,
        &[
            "address",
            "addr",
            "adresse",
            "street",
            "rue",
            "voie",
            "streetaddress",
            "postaladdress",
            "homeaddress",
            "homepostaladdress",
            "registeredaddress",
            "addressline",
            "adres",
            "direccion",
            "dirección",
            "indirizzo",
            "anschrift",
            "strasse",
            "straße",
            "calle",
            "addr1",
            "addr2",
            "address1",
            "address2",
            "street1",
            "street2",
            "domicile",
            "domicilio",
            "mailingaddress",
            "billingaddress",
            "shippingaddress",
            "adressepostale",
            "adrpostale",
            "line1",
            "line2",
        ],
    ),
    (
        ClassifierId::PasswordHash,
        &[
            "password",
            "passwd",
            "pwd",
            "pass",
            "mdp",
            "motdepasse",
            "userpassword",
            "passwordhash",
            "pwhash",
            "hash",
            "pw",
            "passhash",
            "pwdhash",
            "hashedpassword",
            "encryptedpassword",
            "passworddigest",
            "motpasse",
            "secretpassword",
        ],
    ),
    (
        ClassifierId::AwsKey,
        &[
            "aws",
            "accesskey",
            "accesskeyid",
            "secretkey",
            "secretaccesskey",
        ],
    ),
];

/// Generic name tokens that only hint at a person name when qualified
/// (`first_name`, `requester_name`, `nom_client`), or when they are the
/// whole column name.
const NAME_WORDS: &[&str] = &["name", "names", "nom", "noms", "nombre", "nome"];
const PERSON_QUALIFIERS: &[&str] = &[
    "first",
    "last",
    "full",
    "given",
    "family",
    "middle",
    "maiden",
    "sur",
    "display",
    "legal",
    "birth",
    "requester",
    "customer",
    "client",
    "clients",
    "contact",
    "contacts",
    "holder",
    "owner",
    "person",
    "people",
    "employee",
    "patient",
    "member",
    "famille",
    "usage",
    "complet",
    "naissance",
    "author",
    "sender",
    "recipient",
    "signer",
    "signatory",
    "guest",
    "passenger",
    "traveler",
    "traveller",
    "student",
    "teacher",
    "user",
    "billing",
    "shipping",
    "emergency",
    "spouse",
    "parent",
    "father",
    "mother",
    "child",
    "applicant",
    "candidate",
    "tenant",
    "buyer",
    "doctor",
    "physician",
    "manager",
    "agent",
    "real",
    "nick",
    "maiden",
    "common",
    "preferred",
];

/// Tokens that name a password (not a generic hash): raw hex digests are
/// password hashes only under such a name.
const PASSWORD_WORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "mdp",
    "motdepasse",
    "motpasse",
    "userpassword",
    "passwordhash",
    "pwhash",
    "pw",
    "passhash",
    "pwdhash",
    "hashedpassword",
    "encryptedpassword",
    "passworddigest",
    "secretpassword",
];

/// Tokens of things other than persons that have names (pets, ships,
/// products, teams, projects, hosts, files, places, companies…): a `name`
/// qualified by one of them (`pet_name`, `dogName`, `hostname`,
/// `company.name`) is not a person name, whatever the values look like.
const NOT_PERSON_WORDS: &[&str] = &[
    "pet",
    "pets",
    "dog",
    "dogs",
    "cat",
    "cats",
    "animal",
    "animals",
    "horse",
    "horses",
    "breed",
    "species",
    "ship",
    "ships",
    "boat",
    "boats",
    "vessel",
    "yacht",
    "aircraft",
    "plane",
    "product",
    "products",
    "item",
    "items",
    "article",
    "sku",
    "brand",
    "brands",
    "model",
    "models",
    "make",
    "team",
    "teams",
    "club",
    "project",
    "projects",
    "host",
    "hosts",
    "server",
    "servers",
    "machine",
    "vm",
    "node",
    "cluster",
    "device",
    "devices",
    "file",
    "files",
    "folder",
    "directory",
    "dir",
    "path",
    "city",
    "cities",
    "town",
    "village",
    "place",
    "places",
    "location",
    "site",
    "venue",
    "country",
    "region",
    "state",
    "province",
    "street",
    "company",
    "companies",
    "organization",
    "organisation",
    "org",
    "business",
    "firm",
    "employer",
    "store",
    "shop",
    "restaurant",
    "hotel",
    "school",
    "university",
    "bank",
    "merchant",
    "vendor",
    "supplier",
    "carrier",
    "app",
    "application",
    "service",
    "database",
    "db",
    "schema",
    "table",
    "queue",
    "topic",
    "bucket",
    "repo",
    "repository",
    "branch",
    "package",
    "module",
    "library",
    "category",
    "tag",
    "event",
    "campaign",
    "course",
    "book",
    "song",
    "album",
    "movie",
    "film",
    "game",
    "planet",
    "domain",
    "workspace",
    "channel",
    "group",
    "role",
    "department",
    "dept",
    "plan",
    "feature",
    "metric",
    "sensor",
    "job",
    "task",
    "pipeline",
    "workflow",
    "report",
    "dataset",
    "template",
    "chien",
    "chat",
    "cheval",
    "produit",
    "marque",
    "modele",
    "equipe",
    "projet",
    "serveur",
    "fichier",
    "ville",
    "pays",
    "societe",
    "entreprise",
    "magasin",
    "boutique",
    "navire",
    "bateau",
    "mascota",
    "perro",
    "gato",
    "tier",
    "hund",
    "katze",
    "firma",
    "stadt",
];

/// Tokens of other 40-character secrets and digests (session tokens, API
/// tokens, commit ids, checksums): a 40-character value there is not an
/// AWS secret access key without a secret-key name.
const OTHER_TOKEN_WORDS: &[&str] = &[
    "token",
    "tokens",
    "session",
    "sessionid",
    "sid",
    "nonce",
    "csrf",
    "xsrf",
    "jwt",
    "bearer",
    "cookie",
    "signature",
    "sig",
    "checksum",
    "digest",
    "hash",
    "sha",
    "sha1",
    "salt",
    "etag",
    "commit",
    "revision",
    "rev",
    "uuid",
    "guid",
    "apikey",
    "refresh",
    "otp",
    "totp",
    "captcha",
];

/// Tokens of identifiers that pass Luhn or look like card numbers without
/// being cards (order and tracking numbers, IMEI, barcodes…). SIRET / SIREN
/// columns have their own rule ([`NameHints::siret`]).
const NOT_CARD_WORDS: &[&str] = &[
    "order",
    "orders",
    "commande",
    "tracking",
    "track",
    "imei",
    "imeisv",
    "invoice",
    "facture",
    "shipment",
    "parcel",
    "colis",
    "serial",
    "sku",
    "ean",
    "gtin",
    "upc",
    "isbn",
    "barcode",
    "awb",
    "consignment",
    "iccid",
    "imsi",
    "waybill",
];

/// Qualifiers glued before a phone word in flat names (`workphone`,
/// `contactphone`, `homemobile`).
const PHONE_PREFIXES: &[&str] = &[
    "home",
    "work",
    "office",
    "business",
    "contact",
    "customer",
    "client",
    "user",
    "primary",
    "secondary",
    "main",
    "alt",
    "other",
    "private",
    "personal",
    "emergency",
    "billing",
    "shipping",
    "company",
    "direct",
    "fixed",
    "day",
    "night",
    "evening",
    "mobile",
    "cell",
    "num",
    "numero",
    "no",
];
/// Suffixes glued after a phone word (`mobilenumber`, `telnr`, `faxno`).
const PHONE_SUFFIXES: &[&str] = &["number", "numbers", "num", "no", "nr", "nummer", "numero"];

/// Name words of things about a phone rather than its number
/// (`phone_imei`, `mobile_serial`, `phone_model`, `phone_price`): the phone
/// hint is dropped wherever they appear in the name.
const NOT_PHONE_WORDS: &[&str] = &[
    "imei",
    "imsi",
    "iccid",
    "meid",
    "esn",
    "serial",
    "sn",
    "model",
    "models",
    "version",
    "build",
    "firmware",
    "os",
    "price",
    "prices",
    "cost",
    "amount",
    "pin",
    "puk",
    "plan",
    "minutes",
    "duration",
    "carrier",
    "operator",
    "mac",
    "udid",
    "uuid",
    "sku",
    "stock",
    "quantity",
    "qty",
    "level",
    "gain",
    "volume",
    "battery",
    "storage",
    "memory",
    "screen",
    "color",
    "colour",
    "charger",
    "case",
    "sales",
    "revenue",
    "tariff",
    "contract",
    "subscription",
];

/// A name token that designates phone numbers beyond the listed words:
/// trailing digits and plural dropped (`phone1`, `phones`), or a listed
/// word with a glued qualifier or number suffix (`workphone`,
/// `mobilenumber`, `telnr`).
fn phone_token(t: &str, words: &[&str]) -> bool {
    let t = t.trim_end_matches(|c: char| c.is_ascii_digit());
    let bare = |x: &str| {
        !x.is_empty()
            && (words.contains(&x) || x.strip_suffix('s').is_some_and(|y| words.contains(&y)))
    };
    if bare(t) {
        return true;
    }
    let core = PHONE_SUFFIXES
        .iter()
        .find_map(|s| t.strip_suffix(s).filter(|c| bare(c)))
        .unwrap_or(t);
    if core != t {
        return true;
    }
    PHONE_PREFIXES.iter().any(|p| {
        t.strip_prefix(p).is_some_and(|rest| {
            bare(rest)
                || PHONE_SUFFIXES
                    .iter()
                    .any(|s| rest.strip_suffix(s).is_some_and(bare))
        })
    })
}

/// Tokens of the **last** segment that turn a hint off for the hint-gated
/// classifiers: the column is about the data type, not the data itself
/// (`email_opt_in`, `phone_country`, `card_brand`, `postal_code`…).
const NEGATIVE: &[&str] = &[
    "id",
    "ids",
    "code",
    "zip",
    "city",
    "country",
    "verified",
    "opt",
    "optin",
    "brand",
    "type",
    "format",
    "count",
    "template",
    "extension",
    "ext",
    "status",
    "domain",
    "length",
    "flag",
    "enabled",
    "policy",
    "hint",
    "expiry",
    "expires",
    "at",
];

/// Hints derived from a column name or field path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameHints {
    hinted: Vec<ClassifierId>,
    negative: bool,
    aws_secret: bool,
    siret: bool,
    person_weak: bool,
    password: bool,
    not_card: bool,
    other_token: bool,
    not_person: bool,
}

impl NameHints {
    /// Computes the hints of a column name or field path.
    #[must_use]
    pub fn of(name: &str) -> Self {
        if name.len() > MAX_NAME_BYTES {
            return Self::default();
        }
        // Compatibility composition (NFKC): `pre\u{301}nom` (decomposed),
        // fullwidth letters and ligatures read like `prénom`.
        let name: String = name.nfkc().collect();
        let segments: Vec<Vec<String>> = name.split('.').map(tokens).collect();
        let all: Vec<&str> = segments.iter().flatten().map(String::as_str).collect();
        let last: &[String] = segments.last().map_or(&[], Vec::as_slice);
        let has = |t: &str| all.contains(&t);

        let mut hinted = Vec::new();
        for (id, words) in DIRECT {
            if words.iter().any(|w| has(w)) {
                hinted.push(*id);
            }
        }
        let name_word = all.iter().any(|t| NAME_WORDS.contains(t));
        let mut person_weak = false;
        if name_word && !hinted.contains(&ClassifierId::PersonName) {
            if all.iter().any(|t| PERSON_QUALIFIERS.contains(t)) {
                hinted.push(ClassifierId::PersonName);
            } else if all.iter().all(|t| NAME_WORDS.contains(t)) {
                hinted.push(ClassifierId::PersonName);
                person_weak = true;
            }
        }
        // `access_key` split as `access`, `key`.
        let access_key = has("access") && has("key");
        if access_key && !hinted.contains(&ClassifierId::AwsKey) {
            hinted.push(ClassifierId::AwsKey);
        }
        let aws_secret = has("secretaccesskey")
            || has("secretkey")
            || (has("secret") && (has("key") || has("aws")));
        if aws_secret && !hinted.contains(&ClassifierId::AwsKey) {
            hinted.push(ClassifierId::AwsKey);
        }
        if let Some((_, words)) = DIRECT.iter().find(|(id, _)| *id == ClassifierId::Phone)
            && !hinted.contains(&ClassifierId::Phone)
            && all.iter().any(|t| phone_token(t, words))
        {
            hinted.push(ClassifierId::Phone);
        }
        if all.iter().any(|t| NOT_PHONE_WORDS.contains(t)) {
            hinted.retain(|c| *c != ClassifierId::Phone);
        }
        hinted.sort();
        let negative = last.iter().any(|t| NEGATIVE.contains(&t.as_str()));
        let siret = ["siret", "siren", "numsiret", "numsiren"]
            .iter()
            .any(|t| has(t));
        // A bare `hash` / `hashed` column (in a table of accounts) holds
        // password hashes; `file_hash`, `content_hash`… do not.
        // A name of something that is not a person: an object word
        // (`pet_name`, `PetName`, flat `petname`, `pets[].name`) and no
        // person qualifier or person name word (`pet_owner_name`).
        let person_ctx = all.iter().any(|t| PERSON_QUALIFIERS.contains(t))
            || DIRECT
                .iter()
                .find(|(id, _)| *id == ClassifierId::PersonName)
                .is_some_and(|(_, words)| words.iter().any(|w| has(w)));
        let flat_object_name = all.iter().any(|t| {
            ["names", "name", "nom"].iter().any(|n| {
                t.strip_suffix(n)
                    .is_some_and(|p| NOT_PERSON_WORDS.contains(&p))
            })
        });
        let object_ctx =
            flat_object_name || (name_word && all.iter().any(|t| NOT_PERSON_WORDS.contains(t)));
        let not_person = object_ctx && !person_ctx;
        if not_person {
            hinted.retain(|c| *c != ClassifierId::PersonName);
        }
        let password = all.iter().any(|t| PASSWORD_WORDS.contains(t))
            || (!last.is_empty() && last.iter().all(|t| matches!(t.as_str(), "hash" | "hashed")));
        let not_card = !hinted.contains(&ClassifierId::CardNumber)
            && all.iter().any(|t| NOT_CARD_WORDS.contains(t));
        Self {
            hinted,
            negative,
            aws_secret,
            siret,
            person_weak,
            password,
            not_card,
            other_token: all.iter().any(|t| OTHER_TOKEN_WORDS.contains(t)),
            not_person,
        }
    }

    /// Whether the name hints at this classifier.
    #[must_use]
    pub fn hints(&self, id: ClassifierId) -> bool {
        self.hinted.contains(&id)
    }

    /// Whether a hint-gated classifier may run: hinted, and the last segment
    /// does not describe metadata about the type (`phone_country`).
    #[must_use]
    pub fn gates(&self, id: ClassifierId) -> bool {
        self.hints(id) && !self.negative
    }

    /// Whether the name designates a French company number (SIRET / SIREN):
    /// 14-digit Luhn-valid values there are not card numbers.
    #[must_use]
    pub fn siret(&self) -> bool {
        self.siret
    }

    /// Whether the person-name hint only comes from a bare `name` / `nom`
    /// (which also names products, cities, companies…): the values must
    /// then look like known given names or surnames too.
    #[must_use]
    pub fn person_name_weak(&self) -> bool {
        self.person_weak
    }

    /// Whether the name designates a password (`password`, `pwd`, `mdp`…,
    /// or a bare `hash`), not any hash (`file_hash`, `checksum`): raw hex
    /// digests count as password hashes only there.
    #[must_use]
    pub fn password(&self) -> bool {
        self.password && !self.negative
    }

    /// Whether the name designates identifiers that look like card numbers
    /// without being cards (`order_number`, `tracking_ref`, `imei`,
    /// `barcode`…) and no card.
    #[must_use]
    pub fn not_card(&self) -> bool {
        self.not_card
    }

    /// Whether the name says the values name something other than a person
    /// (`pet_name`, `dogName`, `SHIP_NAME`, `hostname`, `product.name`,
    /// `team_name`, `company_name`…): person names are not reported there.
    #[must_use]
    pub fn not_person(&self) -> bool {
        self.not_person
    }

    /// Whether the name designates another kind of token or digest
    /// (`session_token`, `api_token`, `commit_sha`, `checksum`…).
    #[must_use]
    pub fn other_token(&self) -> bool {
        self.other_token && !self.hints(ClassifierId::AwsKey)
    }

    /// Whether the name designates an AWS secret access key.
    #[must_use]
    pub fn aws_secret(&self) -> bool {
        self.aws_secret && !self.negative
    }
}

/// Lowercase tokens of one name segment, plus their joined form.
fn tokens(segment: &str) -> Vec<String> {
    let mut out = word_tokens(segment);
    // Joined forms catch `e_mail`, `num_secu`, `date_naissance`, `pass_word`.
    let joined: String = out.concat();
    if out.len() > 1 && !out.contains(&joined) {
        out.push(joined);
    }
    out
}

/// Lowercase words of one name segment, split on non-alphanumeric
/// characters and camelCase boundaries (`archiveLucasMartin` -> `archive`,
/// `lucas`, `martin`).
pub(crate) fn word_tokens(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in segment.chars() {
        if c.is_alphanumeric() {
            if c.is_uppercase() && prev_lower && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = c.is_lowercase() || c.is_ascii_digit();
            cur.extend(c.to_lowercase());
        } else {
            prev_lower = false;
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ClassifierId as C;

    fn hinted(name: &str) -> Vec<ClassifierId> {
        let h = NameHints::of(name);
        C::ALL.into_iter().filter(|c| h.hints(*c)).collect()
    }

    #[test]
    fn tokenizer() {
        assert_eq!(
            tokens("accessKeyId"),
            ["access", "key", "id", "accesskeyid"]
        );
        assert_eq!(
            tokens("date_naissance"),
            ["date", "naissance", "datenaissance"]
        );
        assert_eq!(tokens("FIRSTNAME"), ["firstname"]);
        assert_eq!(tokens("Prénom"), ["prénom"]);
    }

    #[test]
    fn positive_hints() {
        for (name, want) in [
            ("email", C::Email),
            ("work_email", C::Email),
            ("mail", C::Email),
            ("e_mail", C::Email),
            ("iban", C::Iban),
            ("nir", C::Nir),
            ("num_secu", C::Nir),
            ("date_naissance", C::BirthDate),
            ("dob", C::BirthDate),
            ("birth_date", C::BirthDate),
            ("tel", C::Phone),
            ("phone", C::Phone),
            ("telephonenumber", C::Phone),
            ("mobile_phone", C::Phone),
            ("adresse", C::PostalAddress),
            ("home_address", C::PostalAddress),
            ("address.street", C::PostalAddress),
            ("nom", C::PersonName),
            ("prenom", C::PersonName),
            ("first_name", C::PersonName),
            ("name.first", C::PersonName),
            ("requester_name", C::PersonName),
            ("contacts.*.name", C::PersonName),
            ("givenname", C::PersonName),
            ("card_holder", C::PersonName),
            ("cards[].holder", C::PersonName),
            ("password", C::PasswordHash),
            ("pwd", C::PasswordHash),
            ("password_hash", C::PasswordHash),
            ("aws_access_key_id", C::AwsKey),
            ("credentials.secretAccessKey", C::AwsKey),
            ("card_number", C::CardNumber),
        ] {
            assert!(hinted(name).contains(&want), "{name} -> {want}");
        }
        assert!(NameHints::of("aws_secret_access_key").aws_secret());
        assert!(NameHints::of("credentials.secretAccessKey").aws_secret());
    }

    #[test]
    fn non_person_names() {
        for n in [
            "pet_name",
            "petName",
            "PetName",
            "PET_NAME",
            "petname",
            "dog_name",
            "ANIMAL_NAME",
            "horseName",
            "ship_name",
            "boat_name",
            "product_name",
            "productName",
            "brand_name",
            "model_name",
            "team_name",
            "project_name",
            "hostname",
            "host_name",
            "server_name",
            "file_name",
            "filename",
            "city_name",
            "place_name",
            "company_name",
            "companyName",
            "pets[].name",
            "company.name",
            "nom_produit",
            "nom_ville",
        ] {
            let h = NameHints::of(n);
            assert!(h.not_person(), "{n}");
            assert!(!h.hints(C::PersonName), "{n}");
        }
        for n in [
            "first_name",
            "pet_owner_name",
            "company.contact_name",
            "customer_name",
            "name",
            "cn",
            "full_name",
            "author_name",
        ] {
            assert!(!NameHints::of(n).not_person(), "{n}");
        }
        // Decomposed (NFD) and fullwidth names read like their composed form.
        assert!(NameHints::of("pre\u{301}nom").hints(C::PersonName));
        assert!(NameHints::of("\u{ff45}\u{ff4d}\u{ff41}\u{ff49}\u{ff4c}").hints(C::Email));
    }

    #[test]
    fn hint_strengths() {
        assert!(NameHints::of("name").person_name_weak());
        assert!(!NameHints::of("first_name").person_name_weak());
        assert!(NameHints::of("password_hash").password());
        assert!(NameHints::of("hash").password());
        assert!(!NameHints::of("file_hash").password());
        assert!(!NameHints::of("checksum").password());
        assert!(NameHints::of("order_number").not_card());
        assert!(NameHints::of("imei").not_card());
        assert!(!NameHints::of("card_number").not_card());
        assert!(NameHints::of("session_token").other_token());
        assert!(!NameHints::of("aws_secret_access_key").other_token());
    }

    #[test]
    fn phone_names() {
        for n in [
            "phones",
            "phone1",
            "Phone2",
            "workPhone",
            "workphone",
            "MobileNumber",
            "mobilenumber",
            "telnr",
            "PHONE_NR",
            "faxno",
            "contactphone",
            "telefonnummer",
            "celular",
            "cellular",
            "whatsapp",
            "tel_portable",
            "customerphonenumber",
        ] {
            assert!(hinted(n).contains(&C::Phone), "{n}");
        }
        for n in [
            "phone_imei",
            "mobile_serial",
            "phone_model",
            "phone_price",
            "mobile_app_build",
            "mobile_imsi",
            "microphone_level",
            "microphone",
            "hotel",
            "hotelno",
            "telemetry",
        ] {
            assert!(!hinted(n).contains(&C::Phone), "{n}");
        }
    }

    #[test]
    fn negative_hints() {
        assert!(hinted("key_name").is_empty());
        assert!(hinted("product_name").is_empty());
        assert!(hinted("created_at").is_empty());
        assert!(hinted("amount_cents").is_empty());
        assert!(hinted("status").is_empty());
        assert!(!NameHints::of("phone_country").gates(C::Phone));
        assert!(!NameHints::of("email_opt_in").gates(C::Email));
        assert!(!NameHints::of("address.postalCode").gates(C::PostalAddress));
        assert!(!NameHints::of("address.city").gates(C::PostalAddress));
        assert!(!NameHints::of("accessKeyId").aws_secret());
        assert!(hinted(&"a".repeat(600)).is_empty());
    }
}
