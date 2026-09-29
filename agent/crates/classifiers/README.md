# databastion-classifiers

Sensitive data classifiers, masking and fingerprints for the DataBastion agent. This crate is the
only place where a value read from a target can become something that leaves the agent
(invariant I2, [ADR-0003](../../../docs/adr/0003-data-minimization-at-source.md),
[ADR-0007](../../../docs/adr/0007-mask-access-events.md)).

## Classifier ids (frozen)

Classifier set version `2026.09.1` (`id::CLASSIFIERS_VERSION`). The ids match the contract
`ClassifierId` pattern (`^[a-z]+(\.[a-z0-9_]+)+$`) and `dev/ground-truth.json`. An id is never
renamed: a change of meaning is a new id in a new classifier set version.

| Id | Detection | Column name |
|----|-----------|-------------|
| `pii.birth_date` | whole value: real calendar date 1900–2030 in ISO (`-`, `/`, `.`), `DD/MM/YYYY`, `MM/DD/YYYY` (day first unless impossible), `DD.MM.YYYY`, `DD-MM-YYYY`, `YYYYMMDD`, textual months EN / FR / DE / ES / IT / NL / PT (`17 mai 1980`, `May 17, 1980`, `17-May-1980`, weekday allowed), optional time and zone; token: a date after a label in text (`born`, `DOB`, `né(e) le`, `date de naissance`, `geboren`…) | optional: without a hint the column needs an age distribution (below) |
| `pii.card_number` | token: 13–19 digits with optional space / hyphen separators, Luhn, known issuer prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay, Maestro) | an order / tracking / IMEI / barcode name turns it off |
| `pii.email` | token: e-mail syntax (Unicode local part, alphabetic TLD of 2+ characters), **personal mailboxes only**: not the user part of a URI (`https://user@host`, `ssh://git@host`), not an scp-like remote (`git@host:org/repo`), not glued to other text, not a message id or machine-generated local part (UUID, hex, many digits), not a system or placeholder mailbox (`noreply`, `mailer-daemon`, `postmaster`, `root`, `user`, `test`…), not a local / file "domain" (`host.local`, `icon@2x.png`); `name@1.2.3` package specs fail the TLD rule | no |
| `pii.iban` | token: `CCkk` (any case) + exactly the country's IBAN length, single space / hyphen / dot separators, ISO 7064 mod 97 | no |
| `pii.nir` | token: French NIR, 15 characters with optional separators anywhere (space, dot, hyphen; key separated by space, `-` or `/`), sex `1`/`2`, plausible month, Corsica `2A`/`2B` (any case), key `97 - n mod 97` | no |
| `pii.person_name` | whole value: 1–5 name words, capitalized, upper or (known names only) lower case, compound (`Jean-Pierre`, `García-López`), elided particles (`O'Connor`, `d'Angelo`), `McDonald`, lowercase particles (`de la`, `van der`), initials, leading titles (`Mr`, `Mme`, `Dr`), suffixes (`Jr.`), `LAST, First`; no digit, no word of an organization, place, product, role or status; evidence from a lexicon of given names and surnames (multi-cultural) and surname endings | optional: without a hint the lexicon must recognize the column |
| `pii.phone` | token: international `+` / `00` with 8–15 digits (area code in parentheses, trunk `(0)` ignored), North American `(202) 555-0125` / `202-555-0125`, national with a trunk `0` (FR, UK, DE, IT, NL, BE, CH: 9–12 digits with separators, 10–11 compact), Italian mobiles `3xx xxx xxxx`, Spanish mobiles `6xx xx xx xx`; not glued to a longer number, a code (`REF-0123…`), a time, a decimal or a word; not date-shaped; North American area code and exchange not `N11`. Each number is graded: *strong* (`+`, area code in parentheses, a phone label before it), *normal* (consistent separators and a national grouping: pairs, 3-2-2, 2-2-2, one 6–8 digit group, or two groups ending with 4 digits; `0123-456-789` does not fit), *weak* (compact digits). With a phone hint, also any whole value of 7–15 digits with the usual separators and an optional extension (`x12`, `ext. 12`, `poste 12`) | lowers the threshold |
| `pii.postal_address` | whole value: a house number before a FR / EN street type (`10 rue …`, `10, rue …`, `221B Baker Street`, `123 main st`), a number-last street type or compound street name then a number (`Via Roma 10`, `Calle Mayor 5`, `C/ Mayor 5`, `ul. Długa 5`, `Musterstraße 12`, `Kerkstraat 12`, `Storgatan 12`), a post office box (`PO Box`, `BP`, `Postfach`, `Apartado`, `Postbus`…), or a street type with a postcode (FR / DE / ES / IT / US 5 digits, ZIP+4, UK, NL, CA, PT, PL, SE, 4-digit with a city); abbreviations (`av.`, `bd`, `St`, `Rd`, `Blvd`); comma, line or LDAP `$` separated. *Weak* evidence: a street type alone, or a house number then a word | optional: without a hint strong addresses are needed |
| `secret.aws_key` | token: access key id `AKIA` / `ASIA` / `ABIA` / `ACCA` / `A3T…` + 16 characters (not glued to other letters or digits); a 40-character secret after its key id or after its name in text (`aws_secret_access_key = …`, `"SecretAccessKey": "…"`); whole value: 40 characters `[A-Za-z0-9/+]` mixing cases and digits | optional (secret-key names lower the threshold; token / session / digest names raise it) |
| `secret.password_hash` | token: bcrypt (`$2a/b/x/y$`, Django `bcrypt_sha256$`), argon2 (PHC, Django), scrypt (PHC, `$7$`, Werkzeug), yescrypt `$y$`, sha-crypt `$5$` / `$6$`, md5-crypt `$1$`, `$apr1$`, NetBSD `$sha1$`, phpass `$P$` / `$H$`, Drupal `$S$`, pbkdf2 (PHC / passlib, Django, Werkzeug), Django legacy salted digests, PostgreSQL SCRAM and `md5…`, MySQL `*…` and `$A$`, LDAP `{SSHA}`-style schemes, Atlassian `{PKCS5S2}`; whole value: a raw hex / base64 digest (MD5, SHA-1, SHA-2) only under a password name (`password`, `pwd`, `mdp`, `pw_hash`… or a bare `hash`) | raw digests only |

Tokens never overlap: detectors run from the most to the least specific (AWS key id, password hash,
AWS secret key in context, e-mail, IBAN, card, NIR, labelled date of birth, phone), so phone-shaped
digit groups inside an IBAN are not phones. All regular expressions run on the `regex` crate (linear
time). A pattern that does not compile stops the agent with the pattern name
(`detect::check_patterns` forces them all; the agent calls it at startup, in `core::runtime::run`, before loading its configuration) instead of silently disabling a
detector; the crate declares the `regex` features its patterns need (`unicode-case` for `(?i)`), and
`tests/regex_features.rs` checks the production feature set without dev-dependency feature
unification.

In a column named `siret` / `siren` (or `num_siret`…), 14-digit card candidates are dropped: SIRETs
pass Luhn and some start with a Diners Club prefix (`36`, `38`, `39`). Real 14-digit Diners cards in
such a column are missed. Elsewhere, a column of SIRETs is not reported as cards by the checksum
consistency rule below (most SIRETs are Luhn-valid but not issuer-shaped).

### Known limits

- **Scan bounds**: only the first 8 KiB of a value are scanned, and at most 64 tokens are kept per
  value. A sensitive value past 8 KiB in a long text, or beyond the 64th token, is not seen; the
  column can still be found through its other rows.
- **Whole-value classifiers** (`pii.person_name`, `pii.postal_address`, `pii.birth_date`, AWS secret
  keys) decide on the share of matching values; in free text they only see labelled birth dates,
  AWS secrets next to their name or key id, and strong addresses (a column where at least 3 values
  and 10 % hold one).
- **Person names without a hint** rely on the lexicon: a column of rare given names or surnames
  only (not in the lists, no known surname ending) is missed; brands and places named after people
  that are not in the entity list can be reported. Names in free text are not detected.
- **Birth dates without a hint** rely on the age distribution: dates of birth of children (median
  after 2002) are missed; other old dates spread over decades (publication dates) can be reported.
  `01/02/1980` is read day first (fingerprints included).
- **Phones**: compact numbers (`0612345678`, `2025550125`) and national formats not listed above are
  only found under a phone name, except a column of compact French mobile numbers.
- **Person names in identifiers**: the name normalizer masks words from a small list of common
  first names (`archive_lucas_martin` -> `*`, `ou=Oliver Martin` -> `ou=*`), but a surname alone
  (`archive_martin`) or a first name missing from the list is not recognized.
- The recall / precision measured on the dev seed and on `tests/synthetic_eval.rs` is in-sample:
  the detectors were written with them in view.

### Column-name hints

Names are split into lowercase tokens on separators and camelCase (`accessKeyId` → `access`, `key`,
`id`), plus the joined form (`num_secu` → `numsecu`). Every segment of a field path counts.

| Classifier | Tokens (FR + EN + others) |
|------------|--------------------------|
| `pii.email` | `email`, `mail`, `courriel`, `emailaddress`, `adressemail`, `correo`, `epost` |
| `pii.phone` | `phone`, `tel`, `telephone`, `mobile`, `portable`, `gsm`, `fax`, `cell`, `msisdn`, `telephonenumber`, `telefon`, `telefono`, `handy`, `landline`, `mob`… |
| `pii.iban` | `iban`, `rib`, `bban` |
| `pii.card_number` | `card`, `cardnumber`, `pan`, `cc`, `carte`, `cb`, `creditcard`, `cardno`, `kreditkarte`, `tarjeta` |
| `pii.nir` | `nir`, `secu`, `numsecu`, `insee`, `ssn`, `securite`, `nss`, `securitesociale` |
| `pii.birth_date` | `dob`, `birth`, `birthdate`, `birthday`, `dateofbirth`, `naissance`, `datenaissance`, `ddn`, `born`, `bday`, `geburtsdatum`, `nacimiento`, `nascita`, `geboortedatum` |
| `pii.person_name` | `firstname`, `lastname`, `fullname`, `givenname`, `surname`, `prenom`, `cn`, `sn`, `holder`, `titulaire`, `fname`, `lname`, `vorname`, `nachname`, `apellido`, `cognome`, `voornaam`, `achternaam`, `beneficiary`…; `name` / `nom` / `nombre` / `nome` with a person qualifier (`first`, `last`, `requester`, `client`, `contact`, `author`, `sender`, `recipient`, `guest`, `student`…); a bare `name` / `nom` is a *weak* hint |
| `pii.postal_address` | `address`, `addr`, `adresse`, `street`, `rue`, `voie`, `postaladdress`, `homeaddress`, `adres`, `direccion`, `indirizzo`, `anschrift`, `strasse`, `calle`, `address1`, `line1`, `domicile`… |
| `secret.password_hash` | `password`, `passwd`, `pwd`, `pass`, `mdp`, `motdepasse`, `userpassword`, `hash`, `pw`, `passhash`, `hashedpassword`… |
| `secret.aws_key` | `aws`, `accesskey`, `accesskeyid`, `access` + `key`; secret key: `secret` + `key` / `aws`, `secretaccesskey` |

A last segment containing `id`, `code`, `city`, `country`, `verified`, `opt`, `brand`, `type`,
`format`, `extension`, `status`… (e.g. `phone_country`, `address.postalCode`) turns the hint off.
**Names of things other than persons.** A name word (`name`, `nom`, `nombre`, `nome`) qualified by
an object word, or a flat `<object>name`, turns `pii.person_name` off in every naming style
(`pet_name`, `petName`, `PET_NAME`, `petname`, `pets[].name`, `hostname`, `company.name`,
`nom_produit`): pets and animals, ships, horses, products, brands, models, teams, projects, hosts
and servers, files, places, companies, applications, groups… Values alone cannot tell `Max, Bella,
Luna` from people. A person qualifier or person name word wins (`pet_owner_name`,
`company.contact_name`).

Column names are read in NFKC (`pre\u{301}nom` and fullwidth letters read like `prénom`).

Negative names: `order`, `tracking`, `imei`, `invoice`, `serial`, `sku`, `ean`, `barcode`, `awb`,
`iccid`… (no card hint) turn card numbers off; `token`, `session`, `nonce`, `jwt`, `checksum`,
`digest`, `hash`, `sha`, `commit`, `uuid`… make whole 40-character values AWS secrets only when 30 %
hold `/` or `+`.

## Column API

```rust
use databastion_classifiers::column::ColumnClassifier;
use databastion_classifiers::masking::{HmacKey, PhoneRegion, RawSample};

let key = HmacKey::new(&key_bytes)?;               // agent-local key, >= 32 bytes
let values: Vec<RawSample<'_>> = rows.iter().map(|v| RawSample::new(v)).collect();
let findings = ColumnClassifier::new()
    .only(&job_classifiers)                          // optional job filter
    .with_key(&key)                                  // optional fingerprints
    .phone_region(PhoneRegion::Fr)                   // optional, from agent.yaml
    .classify("customers.email", &values);           // at most 10 000 values examined
for f in findings {
    // f.classifier(), f.confidence(), f.sampled(), f.matched(),
    // f.masked_samples() (<= 5), f.fingerprints() (<= 50), f.into_finding(location)
}
```

Deterministic for a given key and stateless; raw values are only borrowed for the call.

**Evidence selection.** Masked samples are never the first rows: that would pick the same rows in
every column of a table and let the console rebuild partial records. Each column keeps the 5
distinct masked samples whose values have the smallest
`HMAC(key, "sample-order" 0x00 column_name 0x00 value)`, which is deterministic for a key but
independent across columns. Without the agent key, a random key (OS CSPRNG) is drawn for the call.
Fingerprints are the 50 smallest distinct ones, emitted sorted.

**Unicode.** Each value is put in canonical composition (NFC) before detection, so a value stored
decomposed (`e` + U+0301, as written by macOS and some ETLs) is recognized like its composed form
(names, addresses, textual months, e-mail local parts). Tokens, masked samples and fingerprints are
taken from the NFC value: fingerprints of names and addresses were already computed on NFC (no
change); for other classifiers the fingerprint of a non-NFC value is now that of its NFC form
(ASCII values are unchanged). Compatibility forms (NFKC: fullwidth, ligatures) apply to column names
only, not to values.

**Decision rules.** Values are detected first; a column name only lowers thresholds. `n` counts the
informative values (empty values and placeholders such as `N/A`, `null`, `-`, `unknown`,
`0000-00-00` skipped), `ratio = matched / n`:

| Classifiers | Reported when | Confidence |
|-------------|---------------|------------|
| IBAN, card, NIR | `matched >= 1` and at least half of the checksum-shaped candidates are valid (a column of order numbers, SIRETs, IMEIs or EAN codes where a few pass Luhn by chance is not reported); card: not under an order / tracking / IMEI / barcode name | `0.6 + 0.35·ratio (+0.05 hint)` |
| AWS key id or secret in context, password hash token | `matched >= 1` | idem |
| e-mail | hint, `ratio >= 0.05` or `matched >= 3`; not the same single address repeated (`matched >= 3`) | idem |
| phone | hint and `matched >= 1`; no hint: `>= 0.3` of values with a formatted number (national plan groupings, North American, `+` / `00`), compact digits only in a column of `>= 0.8` whole compact numbers 60 % with a mobile prefix `06` / `07`, or 3 values and `>= 0.05` with a strong number (`+`, area code in parentheses, a phone label such as `tel`, `phone`, `call` just before) | `0.4 + 0.4·ratio (+0.2 hint)` |
| birth date | labelled dates in text: `ratio >= 0.05` or 3 values; hint: dates `>= 0.5`; no hint: dates `>= 0.7`, at least 3, distributed like ages (median year ≤ 2002, 10-year spread between the 10th and 90th percentiles, ≤ 15 % after 2014, none after 2026, not all on the 1st; with more than 20 % times of day, median ≤ 1995 and ≤ 5 % after 2014) | `0.3 + 0.5·ratio (+0.15 hint)` |
| person name | never under a name of something else (below); hint: name-shaped `>= 0.6` (bare `name`: `>= 0.7` and 25 % with a known name); no hint: name-shaped `>= 0.7`, 40 % with a known given name, surname or surname ending, 25 % with a listed name, under 20 % well-known places or brands (`Austin`, `Lincoln`, `Hugo Boss`: a list of major cities, countries, US states, regions, car makers, fashion houses and large companies), 3 distinct values | idem |
| postal address | hint: address-like `>= 0.5`; no hint: strong addresses `>= 0.5`, address-like `>= 0.8` with 25 % strong, or at least 3 strong addresses and `>= 0.1` | idem |
| AWS secret key (whole value) | secret-key hint and `>= 0.5`; no hint: `>= 0.8` and 3 values (30 % with `/` or `+` under a token / digest name) | `0.6 + 0.35·ratio` |
| password hash (raw digest) | password name and `>= 0.5` | idem |

## Name normalization (ADR-0009)

`names::normalize_path` (a dotted name), `names::normalize_field_path` (the keys and array levels a
connector walked; preferred for MongoDB) and `names::normalize_ldap_dn` produce a `NormalizedName`,
which always matches the contract `Identifier` (pattern and `not` rule; anything else becomes `*`).
Values are located in the **whole** name, so a value split across separators is found: the token
detectors above run on the name as is and with `.`, `_`, `-`, `/` read as spaces; an `@` masks the
address around it; digit runs split by single separators with more than 6 digits are values. Every
segment a value touches becomes `*` (`a.0612.345678` -> `a.*`, `card_4111_1111_1111_1111` -> `*`).
Inputs are NFKC-folded first (fullwidth digits, `＠`, `．`); percent-encoded bytes make a segment a
value; password-hash prefixes and split AWS key ids are masked; the final gate rejects any name with
more than 6 numeric characters in a row or 8 in total, in any script.

A dotted string cannot tell a container from the local part of an address:
`normalize_path("contacts.jane@example.com.phone")` gives `*.phone` (conservative), while
`normalize_field_path(&[Key("contacts"), Key("jane@example.com"), Key("phone")])` gives
`contacts.*.phone`. Digit-only object keys are dynamic keys (`hourly.13` -> `hourly.*`); array
levels become `[]`.

## Masking

Every masked sample is checked against the contract `MaskedSample` rules (ASCII, at least one `*`,
no run of more than 4 letters or digits, at least 50 % `*` among letters, digits and `*`,
≤ 128 characters), plus at most 4 digits in total, and falls back to `***` otherwise.

| Classifier | Masked |
|------------|--------|
| `pii.email` | `j***@e***.com` (first character of local part and domain if ASCII alphanumeric; TLD if 2–4 ASCII letters, else `***`) |
| `pii.iban` | `FR** **** **** **** **** ***0 189` (country code + last 4, check digits hidden) |
| `pii.card_number` | `**** **** **** 1111` (last 4) |
| `pii.phone` | `+33 * ** ** ** 78`, `+1 *** *** **25`, `+351 *** *** **8` (country code after `+`, then the last digits up to 4 kept in total); national `** ** ** ** 78` (last 2); separators and parentheses kept (`(***) ***-**25`) |
| `pii.nir` | `* ** ** ** *** *** **` |
| `pii.birth_date` | `****-**-**` |
| `pii.person_name` | `J*** D***` (ASCII initials, at most 4 words) |
| `pii.postal_address` | `***` |
| `secret.aws_key` | `AKIA****************`; secret access key `********` |
| `secret.password_hash` | `********` |

## Fingerprints

`hmac-sha256:<64 hex>` =
`HMAC-SHA256(agent_local_key, "databastion/fp/v1" 0x00 domain 0x00 normalized_value)` (RustCrypto
`hmac` + `sha2`), where `domain` is the classifier id, or `db_user` for `db_user_fingerprint`
(`HmacKey::fingerprint_db_user`, exact bytes). The domain keeps the same string under two classifiers,
or as an account name, from correlating. The key is the 32-byte `<state_dir>/hmac.key` generated at
enrollment and loaded by the core; `HmacKey` keys the HMAC state once and clones it per value.

Normalization: e-mail trimmed + lowercased; IBAN, card and NIR without separators, uppercase; phone
`+<digits>` when written with `+` (a trunk `(0)` dropped), national numbers as their digits (`0X…` →
`+33X…` and `00…` → `+…` only with `PhoneRegion::Fr`, from the column or the agent configuration);
birth date ISO `YYYY-MM-DD` from any accepted format (`01/02/1980` read day first); names
and addresses NFC-normalized, trimmed, whitespace collapsed, lowercased; keys and hashes trimmed.

`RawSample`, `RawValue` and `HmacKey` have a redacted `Debug` and no `Display`; `RawValue`, `HmacKey`
(its keyed HMAC-SHA256 state, through the `zeroize` features of `hmac` and `sha2`, checked at compile
time) and the normalized values are zeroized on drop. Production callers must pass the agent key
(`ColumnClassifier::with_key`); without it the sample order is random per call.

## Access events and signals (ADR-0007, P4-A)

`masking::MaskedEvent` is the only event type the uplink accepts. It is built
from closed enums (`EventSource`, `EventAction`, `Signal`), an
`EventPrincipal` (account name; application reduced to
`[A-Za-z0-9 ._:/+-]{0,64}`; client address kept only as an IP literal or
`local`) and `EventObject`s made of `NormalizedName`s. It has no field for
query text, parameters or returned values.

The contract `Signal` is an open pattern (`signature.* | shape.* | volume.*`);
this agent emits only the closed set below (`masking::Signal::ALL`):

| Signal | Emitted when |
|---|---|
| `signature.pg_dump` | `application_name` is `pg_dump` / `pg_dumpall`, or one session (one role per `pg_stat_statements` poll) copied at least 3 distinct whole relations to the client |
| `signature.copy_to_file` | `COPY … TO '<server file>'` |
| `signature.copy_to_program` | `COPY … TO PROGRAM` |
| `shape.full_table_copy` | `COPY` out of a whole relation, or of a query without filter, aggregation or small limit |
| `shape.full_table_read` | a read without top-level `WHERE`, aggregation, derived table, and without a limit or with a limit above 10 000 rows |
| `volume.large_result` | more than 10 000 rows returned or affected by one statement (or one counter delta); on the pgaudit source only with `pgaudit.log_rows = on`; on MySQL / MariaDB only from `performance_schema` (the audit log files carry no row count) |
| `signature.mysqldump` | MySQL / MariaDB: the client's `program_name` is `mysqldump` / `mariadb-dump` (`performance_schema` only), or a whole-table read with `SQL_NO_CACHE` (`SELECT /*!40001 SQL_NO_CACHE */ … FROM t`), or one session reading whole tables after `SHOW CREATE TABLE` of the same table, after a consistent snapshot or global read lock, or of at least 3 distinct tables (P4-B) |
| `signature.into_outfile` | MySQL / MariaDB `SELECT … INTO OUTFILE` / `INTO DUMPFILE`, also when the server refused it (P4-B) |

The thresholds sit above the agent's own maximum sample (10 000 rows), so
its Discovery never raises them. `shape.*` and `signature.*` are heuristics
and **evadable by design** (`WHERE true`, `LIMIT 10000` pagination, a
forged `application_name`); volume × sensitivity in the console is the
robust signal.

## Query normalizer (ADR-0012 obligation 5)

`query::analyze` lexes PostgreSQL statement text and keeps only
literal-free tokens, for every statement of the text and for the body of a
dollar-quoted `DO` block (one level): statement kind, relation names (from identifier tokens,
normalized before the uplink), `COPY` form, and shape (`*`, `WHERE`,
aggregation, `LIMIT`). The normalized text (DML allow-list only: `SELECT`,
`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `VALUES`, `TABLE`, `WITH`) has every
literal and parameter replaced by `?`, comments removed, identifiers
normalized, at most 1024 characters; it is never sent (the contract has no
field for it). Fail-closed rules: unterminated literal / identifier /
comment, text over 1 MiB, possibly truncated text, or a backslash whose
reading depends on `standard_conforming_strings` give no normalized text
(and no shape or relations when ambiguous). Property tests:
`tests/query_props.rs`.

The MySQL / MariaDB dialect (`AnalyzeOptions::mysql()`, P4-B, ROADMAP P4-D)
lexes backticks, `'…'` and `"…"` strings with `\` escapes, `N'…'`, `X'…'`,
`B'…'`, `_charset'…'`, `0x…`, `#` and `-- ` comments, and executable
comments (`/*! … */`, `/*M! … */`) as code. The `sql_mode` of a logged
statement is unknown: the text is lexed with and without
`NO_BACKSLASH_ESCAPES` and `ANSI_QUOTES`, and kept only when every reading
gives the same tokens. A `"…"` token is never a name. Version comments
that a supported server may read as comments (a version from 5.7.0, which
MariaDB skips, six digits, MariaDB's `/*M!`) are lexed both ways too. Text with a byte >= 0x80
directly followed by `\` or a backtick (a trail byte in gbk, big5, sjis,
cp932, gb18030), and raw text that is not UTF-8 (`query::analyze_raw`),
keep only the statement kind, unless the source already transcoded it to
UTF-8 (`AnalyzeOptions::transcoded`: `performance_schema`). `REPLACE` joins the
DML allow-list; account statements, `SET PASSWORD`, `GRANT`, `CHANGE
MASTER` / `CHANGE REPLICATION SOURCE`, `CREATE SERVER` and every other
utility statement keep no text. Property tests: `tests/query_mysql_props.rs`
(every literal and comment form, both `sql_mode` readings, password-bearing
statements as clients write them and as the servers log them, truncation).

## Tests

- unit tests: positive / negative cases per detector, validator, hint and masking format;
- `tests/masking_props.rs` (proptest): contract conformance, no raw value or 5-digit run survives,
  stability, keyed, deterministic and domain-separated fingerprints, no raw value in `Debug`;
- `tests/names_props.rs`: name normalizer (ADR-0009), including the Gate property tests: cards,
  phones, IBANs and e-mail addresses split across separators never survive normalization;
- `tests/ground_truth.rs`: column-level recall / precision against `dev/ground-truth.json`, offline,
  from the committed seed (`dev/seed/out/`), under the real column names and again under opaque
  names (`col_17`: values alone must carry the decision). `cargo test -p databastion-classifiers
  --test ground_truth -- --nocapture` prints the tables (counts only);
- `tests/synthetic_eval.rs`: ~340 synthetic labeled columns generated in code (deterministic PRNG,
  fake values): every classifier in many formats and name styles (descriptive, camelCase,
  PascalCase, UPPER, flat, innocent, opaque, misleading), sparse and mixed columns, free text, and
  hard negatives (event dates, cities, products, companies, order and tracking numbers, IMEIs,
  SIRETs, EAN codes, URLs with user info, git remotes, message ids, package specs, system
  mailboxes, checksums, session tokens…); gate 95 % recall and precision per classifier;
- `tests/regex_features.rs`: the `regex` features resolved for the production build (without
  dev-dependencies) cover the detector patterns;
- `tests/holdout.rs`: the phase 2 gate on the independent held-out corpus (`dev/holdout/`,
  scoring as in its README: Wilson 95 % lower bound, recall ≥ 0.90 and precision ≥ 0.85 per
  classifier). `#[ignore]`d because the corpus is generated, not committed; when run it never
  skips. It checks the corpus SHA-256 against `labels.json` first and prints aggregates plus the
  ids and tags of misclassified columns, never a value:
  `python3 dev/holdout/generate.py`, then `cargo test -p databastion-classifiers --test holdout
  -- --ignored --nocapture` (paths overridable with `DATABASTION_HOLDOUT_CORPUS` /
  `DATABASTION_HOLDOUT_LABELS`). Never tune a classifier against it (independence rule).
