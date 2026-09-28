# databastion-classifiers

Sensitive data classifiers, masking and fingerprints for the DataBastion agent. This crate is the
only place where a value read from a target can become something that leaves the agent
(invariant I2, [ADR-0003](../../../docs/adr/0003-data-minimization-at-source.md),
[ADR-0007](../../../docs/adr/0007-mask-access-events.md)).

## Classifier ids (frozen)

Classifier set version `2026.09.1` (`id::CLASSIFIERS_VERSION`). The ids match the contract
`ClassifierId` pattern (`^[a-z]+(\.[a-z0-9_]+)+$`) and `dev/ground-truth.json`. An id is never
renamed: a change of meaning is a new id in a new classifier set version.

| Id | Detection | Needs a column-name hint |
|----|-----------|--------------------------|
| `pii.birth_date` | whole value: ISO `YYYY-MM-DD` (optionally at midnight) or `DD/MM/YYYY`, real calendar date, 1900–2030 | yes |
| `pii.card_number` | token: 13–19 digits with optional space / hyphen separators, Luhn, known issuer prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay, Maestro) | no |
| `pii.email` | token: e-mail syntax (Unicode local part, alphabetic TLD of 2+ characters) | no |
| `pii.iban` | token: `CCkk` + exactly the country's IBAN length, single spaces allowed, ISO 7064 mod 97 | no |
| `pii.nir` | token: French NIR, 15 characters with optional separators, sex `1`/`2`, plausible month, Corsica `2A`/`2B`, key `97 - n mod 97` | no |
| `pii.person_name` | whole value: 1–4 capitalized or all-caps words, letters with internal `-` / `'`, lowercase particles | yes |
| `pii.phone` | token: French national `0X XX XX XX XX` (space, dot or hyphen) or international `+…` with 8–15 digits | no, but raises the threshold without one |
| `pii.postal_address` | whole value: house number then a word, or a street-type word (FR, EN, DE, NL, ES, IT) | yes |
| `secret.aws_key` | token: access key id `AKIA` / `ASIA` + 16 characters; with a secret-key hint, a whole 40-character `[A-Za-z0-9/+]` value mixing cases and digits | secret access key only |
| `secret.password_hash` | whole value: bcrypt, argon2 (PHC), scrypt (PHC, `$7$`), pbkdf2 (PHC / passlib, Django), `crypt(3)` `$5$` / `$6$`, LDAP `{SSHA}`-style schemes | no |

Tokens never overlap: detectors run from the most to the least specific (AWS key id, password hash,
e-mail, IBAN, card, NIR, phone), so phone-shaped digit groups inside an IBAN are not phones. All
regular expressions run on the `regex` crate (linear time).

In a column named `siret` / `siren` (or `num_siret`…), 14-digit card candidates are dropped: SIRETs
pass Luhn and some start with a Diners Club prefix (`36`, `38`, `39`). Real 14-digit Diners cards in
such a column are missed; elsewhere, a Luhn-valid SIRET with those prefixes is reported as a card.

### Known limits

- **Scan bounds**: only the first 8 KiB of a value are scanned, and at most 64 tokens are kept per
  value. A sensitive value past 8 KiB in a long text, or beyond the 64th token, is not seen; the
  column can still be found through its other rows.
- **Hint-gated classifiers** (`pii.person_name`, `pii.postal_address`, `pii.birth_date`, AWS secret
  keys) find nothing in a column whose name gives no hint, and nothing in free text.
- **Person names in identifiers**: the name normalizer masks words from a small list of common
  first names (`archive_lucas_martin` -> `*`, `ou=Oliver Martin` -> `ou=*`), but a surname alone
  (`archive_martin`) or a first name missing from the list is not recognized.
- The recall / precision measured on the dev seed is in-sample: the detectors were written with
  the seed generator in view.

### Column-name hints

Names are split into lowercase tokens on separators and camelCase (`accessKeyId` → `access`, `key`,
`id`), plus the joined form (`num_secu` → `numsecu`). Every segment of a field path counts.

| Classifier | Tokens (FR + EN) |
|------------|------------------|
| `pii.email` | `email`, `mail`, `courriel`, `emailaddress`, `adressemail` |
| `pii.phone` | `phone`, `tel`, `telephone`, `mobile`, `portable`, `gsm`, `fax`, `cell`, `msisdn`, `telephonenumber` |
| `pii.iban` | `iban`, `rib`, `bban` |
| `pii.card_number` | `card`, `cardnumber`, `pan`, `cc`, `carte`, `cb`, `creditcard` |
| `pii.nir` | `nir`, `secu`, `numsecu`, `insee`, `ssn`, `securite` |
| `pii.birth_date` | `dob`, `birth`, `birthdate`, `birthday`, `dateofbirth`, `naissance`, `datenaissance`, `ddn` |
| `pii.person_name` | `firstname`, `lastname`, `fullname`, `givenname`, `surname`, `prenom`, `cn`, `sn`, `holder`, `titulaire`…; `name` / `nom` alone or with a person qualifier (`first`, `last`, `requester`, `client`, `contact`…) |
| `pii.postal_address` | `address`, `addr`, `adresse`, `street`, `rue`, `voie`, `postaladdress`, `homeaddress` |
| `secret.password_hash` | `password`, `passwd`, `pwd`, `pass`, `mdp`, `motdepasse`, `userpassword`, `hash` |
| `secret.aws_key` | `aws`, `accesskey`, `accesskeyid`, `access` + `key`; secret key: `secret` + `key` / `aws`, `secretaccesskey` |

A last segment containing `id`, `code`, `city`, `country`, `verified`, `opt`, `brand`, `type`,
`format`, `extension`, `status`… (e.g. `phone_country`, `address.postalCode`) turns the hint off for
the hint-gated classifiers.

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
Fingerprints are the 50 smallest distinct ones, emitted sorted. Decision rules
(`ratio = matched / sampled`, empty values skipped):

| Classifiers | Reported when | Confidence |
|-------------|---------------|------------|
| e-mail, IBAN, card, NIR, AWS key id, password hash | `matched >= 1` | `0.6 + 0.35·ratio (+0.05 hint)` |
| phone | `ratio >= 0.2`, or `matched >= 1` with a hint | `0.4 + 0.4·ratio (+0.2 hint)` |
| birth date, person name, AWS secret key | hint and `ratio >= 0.8` | `0.3 + 0.5·ratio` (secret key: as validated) |
| postal address | hint and `ratio >= 0.6` | `0.3 + 0.5·ratio` |

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
| `pii.phone` | `+33 * ** ** ** 78`, `+1 *** *** **25`, `+351 *** *** **8` (country code after `+`, then the last digits up to 4 kept in total); national `** ** ** ** 78` (last 2); separators kept |
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
`+<digits>` when written with `+`, national numbers as their digits (`0X…` → `+33X…` and `00…` →
`+…` only with `PhoneRegion::Fr`, from the column or the agent configuration); birth date ISO; names
and addresses NFC-normalized, trimmed, whitespace collapsed, lowercased; keys and hashes trimmed.

`RawSample`, `RawValue` and `HmacKey` have a redacted `Debug` and no `Display`; `RawValue`, `HmacKey`
(its keyed HMAC-SHA256 state, through the `zeroize` features of `hmac` and `sha2`, checked at compile
time) and the normalized values are zeroized on drop. Production callers must pass the agent key
(`ColumnClassifier::with_key`); without it the sample order is random per call.

## Tests

- unit tests: positive / negative cases per detector, validator, hint and masking format;
- `tests/masking_props.rs` (proptest): contract conformance, no raw value or 5-digit run survives,
  stability, keyed, deterministic and domain-separated fingerprints, no raw value in `Debug`;
- `tests/names_props.rs`: name normalizer (ADR-0009), including the Gate property tests: cards,
  phones, IBANs and e-mail addresses split across separators never survive normalization;
- `tests/ground_truth.rs`: column-level recall / precision against `dev/ground-truth.json`, offline,
  from the committed seed (`dev/seed/out/`). `cargo test -p databastion-classifiers --test
  ground_truth -- --nocapture` prints the table (counts only).
- `tests/holdout.rs`: the phase 2 gate on the independent held-out corpus (`dev/holdout/`,
  scoring as in its README: Wilson 95 % lower bound, recall ≥ 0.90 and precision ≥ 0.85 per
  classifier). `#[ignore]`d because the corpus is generated, not committed; when run it never
  skips. It checks the corpus SHA-256 against `labels.json` first and prints aggregates plus the
  ids and tags of misclassified columns, never a value:
  `python3 dev/holdout/generate.py`, then `cargo test -p databastion-classifiers --test holdout
  -- --ignored --nocapture` (paths overridable with `DATABASTION_HOLDOUT_CORPUS` /
  `DATABASTION_HOLDOUT_LABELS`). Never tune a classifier against it (independence rule).
