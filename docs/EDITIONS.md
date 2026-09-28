# Editions: Community & Enterprise

DataBastion follows an **open-core** model, like Kestra ([ADR-0005](adr/0005-open-core-license.md)).

```
┌──────────────────────────────────────────────────────────┐
│        DataBastion Community Edition — Apache 2.0        │
│               (this repository, public)                  │
│  • Console: agents, targets, findings, incidents         │
│  • Agent + PostgreSQL, MySQL/MariaDB, MongoDB,           │
│    OpenLDAP connectors (and CAS in phase 1.5)            │
│  • Discovery + Audit, standard classifiers               │
│  • Simple policies, email / webhook alerting             │
│  • Local auth + OIDC                                     │
│  • Console audit log                                     │
│  • Prometheus metrics, Docker Compose                    │
└──────────────────────────────────────────────────────────┘
                             +
┌──────────────────────────────────────────────────────────┐
│     DataBastion Enterprise Edition — commercial license  │
│               (separate private repository)              │
│  • Multi-tenancy, fine-grained RBAC (per target / team)  │
│  • SAML, SCIM                                            │
│  • Advanced Prevention mode (proxy, blocking)            │
│  • SIEM export (Splunk, Elastic, Sentinel…), long-term   │
│    retention, tamper-proof audit log                     │
│  • Advanced business classifiers, anomaly detection      │
│  • Compliance reports (GDPR, PCI-DSS)                    │
│  • Console high availability, enterprise Helm            │
│  • Support, SLA                                          │
└──────────────────────────────────────────────────────────┘
```

## Allocation rules
1. **Everything related to baseline security stays in Community**: TLS, minimization, console audit log, OIDC. A security tool that cripples the security of its free version loses its users' trust.
2. **Enterprise adds scale, governance and integration**, not baseline security.
3. A Community feature is never removed to be moved into Enterprise.

> Difference from the initial table: **OIDC** and the baseline **audit log** stay in Community. What moves to Enterprise is SAML/SCIM and the *advanced* audit log (export, retention, tamper-proofing).

## Licenses
- Community Edition → [Apache License 2.0](../LICENSE)
- Enterprise Edition → commercial license
- Name and logo → [TRADEMARKS.md](../TRADEMARKS.md)
