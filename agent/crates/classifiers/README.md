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
regular expressions run on the `regex` crate (linear time). Values are scanned up to 8 KiB.

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
use databastion_classifiers::masking::{HmacKey, RawSample};

let key = HmacKey::new(&key_bytes)?;               // agent-local key, >= 32 bytes
let values: Vec<RawSample<'_>> = rows.iter().map(|v| RawSample::new(v)).collect();
let findings = ColumnClassifier::new()
    .only(&job_classifiers)                          // optional job filter
    .with_key(&key)                                  // optional fingerprints
    .classify("customers.email", &values);           // at most 10 000 values examined
for f in findings {
    // f.classifier(), f.confidence(), f.sampled(), f.matched(),
    // f.masked_samples() (<= 5), f.fingerprints() (<= 50), f.into_finding(location)
}
```

Deterministic and stateless; raw values are only borrowed for the call. Decision rules
(`ratio = matched / sampled`, empty values skipped):

| Classifiers | Reported when | Confidence |
|-------------|---------------|------------|
| e-mail, IBAN, card, NIR, AWS key id, password hash | `matched >= 1` | `0.6 + 0.35·ratio (+0.05 hint)` |
| phone | `ratio >= 0.2`, or `matched >= 1` with a hint | `0.4 + 0.4·ratio (+0.2 hint)` |
| birth date, person name, AWS secret key | hint and `ratio >= 0.8` | `0.3 + 0.5·ratio` (secret key: as validated) |
| postal address | hint and `ratio >= 0.6` | `0.3 + 0.5·ratio` |

## Masking

Every masked sample is checked against the contract `MaskedSample` rules (ASCII, at least one `*`,
no run of more than 4 letters or digits, at least 50 % `*` among letters, digits and `*`,
≤ 128 characters) and falls back to `***` otherwise. At most 4 digits of a value are ever kept.

| Classifier | Masked |
|------------|--------|
| `pii.email` | `j***@e***.com` (first character of local part and domain if ASCII alphanumeric; TLD if 2–4 ASCII letters, else `***`) |
| `pii.iban` | `FR** **** **** **** **** ***0 189` (country code + last 4, check digits hidden) |
| `pii.card_number` | `**** **** **** 1111` (last 4) |
| `pii.phone` | `06 ** ** ** 78`, `+1 2** *** **25` (first 2 + last 2 digits, separators kept) |
| `pii.nir` | `* ** ** ** *** *** **` |
| `pii.birth_date` | `****-**-**` |
| `pii.person_name` | `J*** D***` (ASCII initials, at most 4 words) |
| `pii.postal_address` | `***` |
| `secret.aws_key` | `AKIA****************`; secret access key `********` |
| `secret.password_hash` | `********` |

## Fingerprints

`hmac-sha256:<64 hex>` = `HMAC-SHA256(agent_local_key, normalized_value)` (RustCrypto `hmac` +
`sha2`), keyed with the 32-byte `<state_dir>/hmac.key` generated at enrollment and loaded by the
core. Normalization: e-mail trimmed + lowercased; IBAN, card and NIR without separators, uppercase;
phone `+<digits>` (French `0X…` → `+33X…`, `00` → `+`); birth date ISO; names and addresses
trimmed, whitespace collapsed, lowercased; keys and hashes trimmed. `HmacKey::fingerprint_exact`
hashes without normalization (account names for `db_user_fingerprint`).

`RawSample`, `RawValue` and `HmacKey` have a redacted `Debug` and no `Display`; `RawValue` and
`HmacKey` are zeroized on drop.

## Tests

- unit tests: positive / negative cases per detector, validator, hint and masking format;
- `tests/masking_props.rs` (proptest): contract conformance, no raw value or 5-digit run survives,
  stability, keyed and deterministic fingerprints, no raw value in `Debug`;
- `tests/names_props.rs`: name normalizer (ADR-0009);
- `tests/ground_truth.rs`: column-level recall / precision against `dev/ground-truth.json`, offline,
  from the committed seed (`dev/seed/out/`). `cargo test -p databastion-classifiers --test
  ground_truth -- --nocapture` prints the table (counts only).
