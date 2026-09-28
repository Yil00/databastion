# Changelog

All notable changes to DataBastion are recorded here.

This file is **generated automatically** at each release from the commit messages ([Conventional Commits](https://www.conventionalcommits.org/)), see [RELEASE.md](RELEASE.md). Do not edit it by hand, except for the "Unreleased" section.
The project follows [semantic versioning](https://semver.org/).

## Unreleased

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
