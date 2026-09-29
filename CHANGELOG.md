# Changelog

All notable changes to DataBastion are recorded here.

This file is **generated automatically** at each release from the commit messages ([Conventional Commits](https://www.conventionalcommits.org/)), see [RELEASE.md](RELEASE.md). Do not edit it by hand, except for the "Unreleased" section.
The project follows [semantic versioning](https://semver.org/).

## Unreleased

### ✨ Features
- MySQL / MariaDB Audit from the MariaDB `server_audit` log, the Percona `audit_log` / `audit_log_filter` JSON log and `performance_schema`, at most Partial, with the `signature.mysqldump`, `signature.into_outfile`, `shape.full_table_read` and `volume.large_result` signals (#64, ADR-0023)
- Console: `AccessEvent.bytes` stored and shown, target notes stored and rendered from the phrase catalog, signals missing from the registry flagged, `signature.*` signals kept first when an incident's signals are truncated (#62)

### 🐛 Bug Fixes
- Console: policy and notification wake-ups were not sent by the production build; process-wide state now lives in `processGlobal` / `processSlot`, and the build checks the wake-up functions (#63)
- Agent: the PostgreSQL connector's own table-less statements are no longer reported as access events; other agent-account events on unknown objects are always reported; pgaudit counts as loaded only when its `pgaudit.log_catalog` setting is in `pg_settings`; `pg_stat_statements` counts as a catalog only in the extension's schema (#65)

### 🐛 Agent classifiers
- Value-based column classification: birth dates, person names and postal addresses are detected without a column-name hint (age distribution, name lexicon, address structure); broader phone, IBAN, NIR, AWS key and password-hash formats; card and e-mail precision rules (checksum consistency, personal mailboxes only)
- Values are put in Unicode NFC before detection and fingerprinting: fingerprints of decomposed (NFD) non-ASCII values, e.g. accented e-mail addresses, change to those of their composed form
- The `regex` `unicode-case` feature is declared by the classifiers crate (case-insensitive patterns failed in the production build) and every pattern is compiled at agent startup

### 📝 Documentation
- MVP framing: vision, architecture, stack, scope, security
- Architecture decisions ADR-0001 to ADR-0006
- Audit capability matrix per engine
- Draft of the agent ↔ console protocol v1
- MVP roadmap in phases 0 to 7
- Apache 2.0 license, trademark policy, contribution and release guides
- Translate the whole repository to English

### 👷 CI
- CI (documentation, gitleaks, console, agent, protocol), PR title and DCO checks
- Automated release with release-it, multi-arch images signed with cosign on GHCR
