# ADR-0016: Classifier semantics for set 2026.09.1

- **Status**: Accepted
- **Date**: 2026-09-28
- **Context references**: P2-F, #44 (held-out scorer), #48 (`agent/crates/classifiers/README.md`, `src/column.rs`, `src/detect.rs`, `src/hints.rs`, `src/lexicon.rs`), `dev/holdout/README.md`

## Context
The classifier ids are frozen and published as classifier set `2026.09.1` (#34, #38). The first measurement on the independent held-out corpus (#44) failed the phase 2 exit criterion for all 10 classifiers. That corpus deliberately includes columns with innocent or opaque names, where only the values tell the type, and hard negatives with misleading names (`email_opt_in`, `phone_country`). #48 reworked the column decision to meet the criterion. Several of its choices define what a finding *means* for this classifier set, and some affect the fingerprints the console stores. They must not drift silently within the set, and the evaluation that justifies them must stay credible.

Set `2026.09.1` has not been released yet (no release tag), so its semantics can still be fixed here. Once released, a change of meaning needs a new classifier set version (the rule of the classifiers crate).

## Decision
1. **Values decide; names only lower thresholds.** A column is reported on the evidence found in its sampled values. A column-name hint lowers the thresholds (and adds to the confidence); it never makes a column a finding on its own. Names can only *disable* in a few listed cases:
   - a name of something other than a person (`pet_name`, `hostname`, `company.name`, `nom_produit`…) turns `pii.person_name` off, in every naming style; a person qualifier wins (`pet_owner_name`);
   - an order / tracking / IMEI / barcode name turns `pii.card_number` off, and 14-digit card candidates are dropped under a `siret` / `siren` name;
   - a last name segment such as `id`, `code`, `country`, `verified`, `type` turns the hint of that name off (it is not a hint), without disabling detection on the values.
2. **`pii.email` means personal mailboxes only.** Not the user part of a URI, not an scp-like remote (`git@host:repo`), not a message id or a machine-generated local part, not a system or placeholder mailbox (`noreply`, `postmaster`, `root`, `test`…), not a local or file "domain". A column holding one address repeated is not reported (`matched ≥ 3` of a single address).
3. **Placeholders are non-informative.** Empty values and a fixed list of placeholders (`N/A`, `na`, `null`, `-`, `unknown`, `x`, `0`, `0000-00-00`…) are excluded from the count of informative values, so they neither dilute a sparse column nor count as matches.
4. **The birth-date age heuristic is tied to the classifier set.** Without a hint, a date column is reported as `pii.birth_date` only if its dates are distributed like ages. The distribution is computed against a fixed `REFERENCE_YEAR = 2026` (no date after it; thresholds such as "median year ≤ 2002" and "≤ 15 % after 2014" are derived from it), not against the current date: the same values give the same result for the whole life of the set. The reference year is revised with a new classifier set version.
5. **NFC normalization of values; fingerprints on NFC; `databastion/fp/v1` kept.** Each value is put in Unicode canonical composition (NFC) before detection, so a decomposed value (`e` + U+0301, as written by macOS and some ETL tools) is detected like its composed form. Tokens, masked samples and fingerprints are taken from the NFC value. Compatibility forms (NFKC) apply to column names only. The fingerprint label stays `databastion/fp/v1`:
   - fingerprints of names and addresses were already computed on NFC, and ASCII values are unchanged by NFC, so only non-ASCII values stored decomposed get a new fingerprint (that of their composed form, which is what equality should compare);
   - a new label would have changed every fingerprint, breaking deduplication and equality checks against everything already stored, for a change that affects a small set of values. The label is reserved for a change of the fingerprint scheme itself (key, construction, domain separation).
6. **Held-out evaluation process.**
   - **Independence rule** (`dev/holdout/README.md`): the corpus was written without looking at the classifiers; classifiers are never tuned against it (no rule or test added because a holdout column fails, no holdout value copied into tests); whoever changes the classifiers does not change the corpus in the same PR.
   - **Gate**: report-only while the criterion was not met (#44); **blocking** in CI since #48 (recall ≥ 90 % and precision ≥ 85 % per classifier, Wilson 95 % lower bound). The dev ground truth and the synthetic evaluation stay regression checks; they are in-sample.
   - **Feedback rounds are disclosed.** The scorer prints aggregates and the ids and tags of misclassified columns (never a value). Any use of these results during classifier work partly exposes the test set, so the PR that relies on them states how many rounds were run and what was looked at (the #48 PR description does this).
   - **Seed rotation at release**: the holdout seed is rotated after each release (new values, same shapes and naming families), and new naming or format families are added from time to time. Rotation limits leakage; it does not remove it.

## Consequences
- Findings on innocent or opaque column names become possible, and misleading names no longer produce findings by themselves. A finding can be explained by its values; the name is supporting evidence.
- Some sensitive columns are knowingly missed (recall notes in [05-security.md](../05-security.md#classifiers)): dates of birth of children without a hint (median after 2002), person names from outside the lexicon without a hint, person names under a non-person name (never reported), placeholder-only values, a single address repeated, checksum columns where fewer than half of the candidates are valid.
- The age heuristic drifts over time: real populations include more and more people born after its fixed thresholds (and, from 2027, after the reference year itself, which disqualifies a column without a hint), so recall without a hint decreases until a later set moves `REFERENCE_YEAR`.
- The fingerprints of some non-ASCII values (decomposed accents, e.g. accented e-mail addresses) changed within `databastion/fp/v1` with #48. Findings scanned before and after that change do not match on these values. This is acceptable before the first release; after a release, such a change needs a new label or a new classifier set.
- The holdout is a gate, not a target. Its credibility depends on the disclosure of feedback rounds and on the seed rotation, both of which are process rules, not enforced by CI.

## Rejected alternatives
- **Name-led classification**: cheap and explainable, but it cannot find data under innocent or opaque names and is fooled by misleading ones, which are common in real schemas.
- **Counting placeholders as informative values**: dilutes sparse columns below the thresholds, and makes the result depend on how a database spells "no value".
- **Age heuristic against the current date**: the same column would change classification over time with no change of classifier set, which breaks the comparison of findings across scans.
- **A new fingerprint label for NFC** (`databastion/fp/v2`): changes every fingerprint to fix a few; the label version is kept for scheme changes.
- **NFKC on values**: folds compatibility characters (fullwidth digits, ligatures) that are part of the stored value; it stays limited to names, where it defeats evasion.
- **Tuning against the holdout until it passes**: makes the gate measure memorization. Rejected by the independence rule.
