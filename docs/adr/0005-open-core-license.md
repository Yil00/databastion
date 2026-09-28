# ADR-0005: Apache 2.0, open-core model

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
The project aims for enterprise adoption, eventually with a commercial edition, following the Kestra model.

## Decision
- **Community Edition**: public repository, **Apache 2.0** license.
- **Enterprise Edition**: **separate private repository**, commercial license. It consumes the Community Edition as a dependency or as an extension module. No proprietary code in the public repository, no `ee/` folder under another license.
- External contributions under **DCO** (`Signed-off-by`), without a CLA.
- The **name and logo** are not covered by the license (Apache 2.0 §6): see `TRADEMARKS.md`.
- Feature split: `docs/EDITIONS.md`.

## Consequences
- Apache 2.0 allows external contributions to be integrated into the EE; the DCO is enough to trace their origin.
- The code is designed to be extended: extension points (authentication, event storage, policy actions) designed from the MVP, without being implemented on the EE side.
- A third party can offer a hosted DataBastion. Protection relies on the trademark and on the value of the EE, not on the license.

## Rejected alternatives
- **AGPL-3.0**: hinders enterprise adoption.
- **BSL 1.1 / SSPL**: not open source in the OSI sense, a bad signal for a security tool that people should be able to audit.
- **MIT**: no explicit patent clause.
