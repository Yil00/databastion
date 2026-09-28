# Holdout corpus (classifier evaluation set)

An offline, deterministic, labeled set of database columns used as a **CI regression gate** for the phase 2 exit criterion on the Discovery classifiers: **recall ≥ 90 % and precision ≥ 85 %, judged on the Wilson 95 % lower bound**, for every classifier.

It is separate from the dev seed ([../seed/generate.py](../seed/generate.py), [../ground-truth.json](../ground-truth.json)). The dev seed feeds the containers and the integration tests. This corpus is never loaded into a database: a scorer reads the column values directly, runs the classifiers on them and compares the result with the labels.

## Independence rule
- The corpus was written **without looking at the classifier implementation** (`agent/crates/classifiers`). The only inputs were the classifier id list, the label format of `dev/ground-truth.json` and general knowledge of the data types.
- **Do not tune classifiers against this corpus.** Do not add a rule or a test because a holdout column fails, and do not copy holdout values into classifier tests. Fix the classifiers against the dev seed or against your own examples. The holdout only measures the result.
- **Rotate the seed after each release** (`SEED` in [generate.py](generate.py); it must stay different from the dev seed `20260928`). Anyone who has seen failing holdout columns while working on the classifiers has partly "seen" the test set. A new seed produces new values. The value shapes and naming families stay the same, so this rotation limits leakage but does not remove it. Adding new naming or format families from time to time helps as well.
- Whoever changes the classifiers should not also change this corpus in the same PR.

## Files
| File | Content |
|------|---------|
| [generate.py](generate.py) | Generator. Python 3 stdlib only, fixed seed `5318027` |
| `corpus.json` (**not committed**, git-ignored, about 8 MB) | `{"generator", "seed", "version", "rows_per_column", "columns": [...]}`. Each column is `{id, engine, database, container, object, field, values}`, with 200 string `values` |
| `labels.json` (committed, the reviewable artifact) | `{"generator", "seed", "version", "classifiers", "notes", "corpus_sha256", "locations": [...]}`, one location per column, joined on `id`. `corpus_sha256` is the SHA-256 of the exact bytes of `corpus.json` |
| [test_generate.py](test_generate.py) | Unit tests: check-digit validators, determinism, validation, committed `labels.json` and pinned corpus SHA-256 up to date, minimum counts |

```sh
python3 dev/holdout/generate.py            # write corpus.json + labels.json, validate, print counts
python3 dev/holdout/generate.py --check    # regenerate in memory; fail if the corpus SHA-256 differs from
                                           # labels.json corpus_sha256, or if labels.json is out of date
python3 -m unittest discover -s dev/holdout -v
```
`corpus.json` is not committed because the generator is deterministic: the committed `labels.json` pins its SHA-256, so the regenerated corpus is exactly the one the labels were written for. Each run builds the corpus twice and fails if the two builds differ. It also re-checks every checksum with validators written separately from the builders (see "Validation" below).

### Differences from `dev/ground-truth.json` locations
Same keys: `engine`, `database`, `container`, `object`, `field`, `expected_classifiers`, `negative_control`, `name_contains_value`, optional `note` and `expected_normalized_name`. The differences:

| Key | Meaning |
|-----|---------|
| `id` (added) | `h0001`… The join key with `corpus.json` (the location tuple is unique too) |
| `values` (moved) | Stored in `corpus.json`, not in the labels |
| `ambiguous` (added) | `true` means the column is **excluded from scoring**. Its `expected_classifiers` is only a best guess |
| `ambiguity` (added) | Why the column is ambiguous |
| `tags` (added) | `naming:{explicit,innocent_name,opaque,misleading}`, `style:{snake,camel,upper,pascal,flat}`, `format:<value profile>`, `negative:<type>`, `free_text`, `embedded:*`, `low_prevalence`, `sparse`, `mixed_types`, `dynamic_key`, `ambiguous`. They are for slicing error reports, not for scoring |
| `negative_control` | `true` for every non-ambiguous column with empty `expected_classifiers`. Each of these is a deliberate hard negative (a sensitive-looking name or shape) |
| `name_contains_value` | Always `false`. Names that embed values are the subject of the P2-E invariant test, not of this corpus |
| `expected_normalized_name` | Set on MongoDB dynamic-key paths such as `devices.<deviceId>.imei` → `devices.*.imei` |

Engines: `postgresql` (database + schema `container`), `mysql` (`container: null`), `mongodb` (`container: null`, dotted paths such as `profile.email`, arrays such as `items[].pan`, dynamic keys such as `sessions.<sessionId>.phone`).

## Scoring method
Scoring is done per classifier `c`, at **column level**, over the non-ambiguous columns only (`ambiguous: false`):

- a column is **predicted** `c` if the classifier pipeline reports a finding of type `c` on it (with the production sampling and thresholds, all 200 values given as the sample);
- **TP**: `c` is predicted and `c ∈ expected_classifiers`;
- **FP**: `c` is predicted and `c ∉ expected_classifiers`. This includes the hard negatives and the positive columns of other classifiers;
- **FN**: `c ∈ expected_classifiers` and `c` is not predicted;
- recall = TP / (TP + FN), precision = TP / (TP + FP);
- gate: `wilson_lower(TP, TP + FN) ≥ 0.90` **and** `wilson_lower(TP, TP + FP) ≥ 0.85`, with z = 1.96:

```
wilson_lower(k, n) = (p + z²/2n − z·sqrt(p(1−p)/n + z²/4n²)) / (1 + z²/n),  p = k/n
```

A multi-label column (for example free text with both an e-mail and a phone) counts once for each expected classifier. If the pipeline predicts nothing at all for `c` (TP + FP = 0), `c` fails the gate.

### Sample size
The Wilson lower bound for a perfect score is n / (n + 3.84). **With 30 positive columns, even 30/30 gives 0.886 < 0.90, so the recall gate cannot be met.** That is why each classifier has at least 62 positive columns:

| Positive columns n | LB at 100 % recall | Misses tolerated (LB ≥ 0.90) |
|---|---|---|
| 30 | 0.886 | none, the gate is unreachable |
| 35 | 0.901 | 0 |
| 50 | 0.929 | 0 |
| 62 | 0.942 | 1 |
| 78 | 0.953 | 2 |
| 100 | 0.963 | 4 |

For precision (LB ≥ 0.85): with TP = 62 the gate tolerates up to 4 FP, with TP = 78 up to 6 FP. So in practice the gate asks for about 98 % recall at column level. Anyone who wants more slack should raise `TARGET_POSITIVES` (for example 100 allows 4 misses) and not lower the bar.

## Counts (seed 5318027)
1416 columns × 200 rows: 643 positive columns, 759 hard-negative columns and 14 ambiguous columns (excluded).

Non-ambiguous positive columns per classifier:

| Classifier | Columns | of which: innocent name / opaque name | Notes |
|---|---|---|---|
| `pii.birth_date` | 62 | 0 / 0 | opaque-named date columns are ambiguous (see below) |
| `pii.card_number` | 62 | 6 / 10 | |
| `pii.email` | 78 | 6 / 10 | + 12 free-text, + 4 e-mail-or-phone contact columns |
| `pii.iban` | 62 | 6 / 10 | |
| `pii.nir` | 62 | 6 / 10 | |
| `pii.person_name` | 62 | 6 / 10 | |
| `pii.phone` | 78 | 6 / 10 | + 12 free-text, + 4 e-mail-or-phone contact columns |
| `pii.postal_address` | 62 | 6 / 10 | |
| `secret.aws_key` | 62 | 6 / 10 | |
| `secret.password_hash` | 62 | 6 / 10 | |

Hard negatives, 759 columns in 45 types with at least 16 columns each. 165 of them have misleading names (`email_opt_in`, `phone_country`, `card_brand`…) and 44 have opaque names:

| Type | Targets mostly |
|---|---|
| `boolean_optin` (`email_opt_in`, `phone_verified`…), `boolean_misc` | name-driven FPs |
| `country_code` (`phone_country`, `iban_country`…), `dial_code` (`+33`), `phone_extension` | phone, iban |
| `siret`, `siren`, `imei` (all Luhn-valid), `luhn_fail_16`, `tracking`, `order_number`, `ean`, `isbn` | card, phone |
| `nir_like` (15 digits starting with 1/2, invalid key), `vat` (FR VAT, valid key), `bic` | nir, iban |
| `uuid`, `sha256`, `git_sha`, `base64_token` (length ≠ 40), `version`, `ip` | aws_key, password_hash, phone |
| `timestamp`, `epoch`, `business_date` (order / hire / expiry dates), `card_expiry`, `percent` | birth_date, phone |
| `card_last4`, `card_brand`, `hash_algo`, `aws_region`, `aws_account`, `aws_arn`, `email_domain`, `package_ref` (`lodash@4.17.21`, `git@host:repo.git`) | name-driven and shape-driven FPs |
| `price`, `sku`, `postcode`, `city` (incl. Florence, Nancy, Charlotte…), `geo`, `product_name` (on first names), `pet_name`, `company` (on surnames), `job_title`, `neg_prose` (mentions "IBAN", "e-mail" as words) | person_name, postal_address |

`python3 dev/holdout/generate.py` prints the exact per-type counts.

### What the positives cover
- **Naming**: FR, EN, DE, ES and IT names and synonyms (`courriel`, `Rufnummer`, `fecha_nacimiento`, `cognome`, `carte_vitale`, `Anschrift`, `mdp`…), rendered as `snake_case`, `camelCase`, `UPPER_CASE`, `PascalCase` or `flatcase`, plus some non-ASCII names (`téléphone`, `straße`). Some columns have innocent names (`login`, `ref`, `token`, `location`…) and some opaque names (`c3`, `col_17`, `attr_x`, `data`…), where only the values tell the type.
- **Phones**: FR `06 39 98 …`, `06.39…`, `06-39…`, compact, `+33…`, `+33 (0)6…`, `0033 6…`, `0033…`; GB, US, AU, DE, ES, IT, BE and CH numbers in several formats.
- **IBANs**: FR, MC, DE, ES, IT, BE, NL, GB, CH, LU, PT, AT. Print format, compact, lower case, dashes, and odd grouping (RIB-style `FR76 30006 00001 …`, groups of 3/5/6).
- **Cards**: Visa, Mastercard (51–55 and 2221–2720), Amex (4-6-5), Discover, JCB, Diners (14 digits, 4-6-4), UnionPay (16/19), Maestro (16/19). Formats: plain, spaces, dashes, mixed.
- **E-mails**: plain, sub-addressed (`+tag`), UPPER CASE, Mixed.Case, IDN domains (Unicode and punycode) and EAI local parts (`théo.x@exämple.test`).
- **Names**: first names only, last names only, full names, `LAST, First`, titles, initials, UPPER CASE, NFD-decomposed accents, compound first names, particles (`de La Fontaine`, `van der Berg`, `O'Connor`, `di Stefano`), Spanish double surnames.
- **Dates**: ISO, `dd/mm/yyyy`, `dd-mm-yyyy`, `dd.mm.yyyy`, US `mm/dd/yyyy`, `yyyymmdd`, ISO midnight, `12 mars 1985`, `1er mars`, `March 12, 1985`, `12. März 1985`, `12 de marzo de 1985`, `12 marzo 1985`.
- **NIR**: spaced, compact, key after a dash or a space, Corsica `2A`/`2B`, overseas `97x`, born abroad `99`.
- **AWS**: access key ids `AKIA…`/`ASIA…`, secret access keys, `id:secret` pairs.
- **Password hashes**: bcrypt (`$2a$`/`$2b$`/`$2y$`), argon2id, scrypt (passlib `$scrypt$` and Django `scrypt$`), Django `pbkdf2_sha256$`, `$6$` (with and without `rounds=`), `$5$`, `$1$`, yescrypt `$y$`, `{SSHA}`, and mixed "migration" columns.
- **Free text**: notes in 5 languages with an embedded e-mail and/or phone in about 40 % of rows, plus three **low-prevalence** columns (about 5 % of rows). These are labeled with the types actually present.
- About 15 % of the positive columns (94) are **sparse**: about 8 % of their cells are `""`, `N/A` or `-`.

## Ambiguous columns (excluded, `ambiguous: true`)
| Columns | Best-guess label | Why |
|---|---|---|
| 4 opaque-named columns of dates between 1938 and 2007 | `pii.birth_date` | Plausible birth dates, but nothing proves it. Because of this, `pii.birth_date` has no opaque-named positive |
| `birth_year`, `annee_naissance` (years only) | none | Personal data, but not a date |
| `username`, `pseudo` (`jdupont`, `marie.l`) | none | Handles derived from names, arguably `pii.person_name` |
| `password`, `pwd_hash` holding unsalted hex SHA-256 | `secret.password_hash` | Could be a weak password hash or a plain digest |
| `card_masked`, `pan_masque` (`4970 **** **** 1234`) | none | A truncated PAN is allowed by PCI-DSS; counting it is a policy choice |
| one opaque column of words that are both cities and first names | none | `Florence`, `Nancy`, `Charlotte`… |
| `fediverse` (`@user12@social.example`) | none | Same shape as an e-mail |

Two judgment calls are **not** flagged ambiguous, and a classifier owner may disagree with them:
- `postcode` and `city` alone are negatives for `pii.postal_address`, as are `geo` coordinates.
- `fax` / `tel_or_fax` columns are positives for `pii.phone`.

## Synthetic data only
- E-mail domains are reserved names: `example.{com,org,net}`, `*.example`, `*.test` and `*.invalid` (RFC 2606 / 6761). The validator rejects anything else.
- Phones use the ranges reserved for fiction where one exists: FR ARCEP (`01 99 00`, `02 61 91`, `03 53 01`, `04 65 71`, `05 36 49`, `06 39 98`, `09 72 10`), UK Ofcom (`07700 900`, `020 7946 0`, `0113 496 0`), US `555-01xx` and AU `0491 570 xxx`. DE, ES, IT, BE and CH have no published fiction range, so their numbers are random in a plausible range and are not linked to anyone.
- Cards, IBANs, NIRs, SIRET/SIREN, IMEIs, ISBN/EAN and FR VAT numbers are random digits with valid check digits.
- AWS key ids follow the AWS documentation convention: `AKIA`/`ASIA` + 9 characters + `EXAMPLE` (20 characters). Secret keys are 30 characters + `EXAMPLEKEY` (40 characters). Gitleaks' default `aws-access-token` rule allowlists `…EXAMPLE`. `gitleaks dir dev/holdout` (v8.30.1, repository `.gitleaks.toml`) reports no leaks, and it does flag the same shape without `EXAMPLE`.
- Password hashes are random bytes in the right encoding, not the hash of any password.
- Person names are random combinations of common first and last names.

## Validation
`generate.py` checks every value with validators written independently from the builders. Luhn uses a doubling table, IBAN a digit-by-digit mod 97, and NIR an arithmetic Corsica offset. The checks cover:
- every card value: Luhn and a length of 13–19 digits;
- every IBAN: country length and mod 97;
- every NIR: the key, including `2A`/`2B`;
- SIRET, SIREN and IMEI: Luhn and length;
- `luhn_fail_16` and 16-digit tracking numbers: must fail Luhn;
- `nir_like`: must fail the NIR key;
- FR VAT keys, EAN-13 and ISBN-10/13;
- base64 tokens: never the 40-character AWS secret shape;
- AWS values: must follow the EXAMPLE convention;
- e-mail domains: must be reserved.

It also checks that locations are unique and that labels and corpus agree.

## CI
The dev-env workflow does not run this yet: `.github/` belongs to another owner. Proposed steps:
```sh
timeout 300 python3 -m unittest discover -s dev/holdout -v
timeout 120 python3 dev/holdout/generate.py --check
```
**Consumer contract.** The scorer (the Rust classifier scorer in CI) must first run `python3 dev/holdout/generate.py` (Python 3, standard library only, no network; it takes a few seconds). Then it loads `dev/holdout/corpus.json` and `dev/holdout/labels.json` and applies the method above. The scorer should also check that the SHA-256 of `corpus.json` equals `labels.json` `corpus_sha256`, and refuse to score otherwise.
