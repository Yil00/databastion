# Éditions : Community & Enterprise

DataBastion suit un modèle **open-core**, comme Kestra ([ADR-0005](adr/0005-licence-open-core.md)).

```
┌──────────────────────────────────────────────────────────┐
│        DataBastion Community Edition — Apache 2.0        │
│               (ce dépôt, public)                         │
│  • Console : agents, cibles, findings, incidents         │
│  • Agent + connecteurs PostgreSQL, MySQL/MariaDB,        │
│    MongoDB, OpenLDAP (et CAS en phase 1.5)               │
│  • Discovery + Audit, classifieurs standards             │
│  • Politiques simples, alerting e-mail / webhook         │
│  • Auth locale + OIDC                                    │
│  • Journal d'audit de la console                         │
│  • Métriques Prometheus, Docker Compose                  │
└──────────────────────────────────────────────────────────┘
                             +
┌──────────────────────────────────────────────────────────┐
│     DataBastion Enterprise Edition — licence commerciale │
│               (dépôt privé séparé)                       │
│  • Multi-tenancy, RBAC fin (par cible / par équipe)      │
│  • SAML, SCIM                                            │
│  • Mode Prevention avancé (proxy, blocage)               │
│  • Export SIEM (Splunk, Elastic, Sentinel…), rétention   │
│    longue, journal d'audit infalsifiable                 │
│  • Classifieurs métier avancés, détection d'anomalies    │
│  • Rapports de conformité (RGPD, PCI-DSS)                │
│  • Haute disponibilité de la console, Helm entreprise    │
│  • Support, SLA                                          │
└──────────────────────────────────────────────────────────┘
```

## Règles de répartition
1. **Tout ce qui touche à la sécurité de base reste en Community** : TLS, minimisation, journal d'audit de la console, OIDC. Un outil de sécurité qui bride la sécurité de sa version gratuite perd la confiance de ses utilisateurs.
2. **L'Enterprise ajoute de l'échelle, de la gouvernance et de l'intégration**, pas de la sécurité de base.
3. Une fonctionnalité Community n'est jamais retirée pour être déplacée en Enterprise.

> Différence avec le tableau de départ : l'**OIDC** et le **journal d'audit** de base restent en Community. Ce qui passe en Enterprise, c'est le SAML/SCIM et le journal d'audit *avancé* (export, rétention, infalsifiabilité).

## Licences
- Community Edition → [Apache License 2.0](../LICENSE)
- Enterprise Edition → licence commerciale
- Nom et logo → [TRADEMARKS.md](../TRADEMARKS.md)
