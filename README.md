<p align="center">
  <img src="docs/assets/logo.jpg" alt="DataBastion" width="140">
</p>

<h1 align="center">DataBastion</h1>

<p align="center">
  <b>DLP open-source pour bases de données et annuaires.</b><br>
  Savoir où sont vos données sensibles, et qui les extrait.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
  <img src="https://img.shields.io/badge/status-pre--alpha-orange.svg" alt="Status: pre-alpha">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey.svg" alt="Platform: Linux">
</p>

> ⚠️ **Projet en phase de conception.** Rien n'est encore utilisable en production. Voir la [roadmap](docs/ROADMAP.md).

## Pourquoi
Les DLP classiques surveillent les postes et le réseau. Ils ne savent ni **où** se trouvent les données sensibles dans vos bases, ni **qui** les exporte en masse (`pg_dump`, `mysqldump`, `mongoexport`, exports LDIF…).

DataBastion se place **au plus près de la donnée** :
- **Discovery** : classifie automatiquement les colonnes, champs et attributs qui contiennent des données personnelles ou des secrets.
- **Audit** : exploite les journaux natifs des moteurs pour détecter les accès et les exports anormaux, pondérés par la sensibilité des données touchées.

## Moteurs supportés (MVP)
PostgreSQL · MySQL / MariaDB · MongoDB · OpenLDAP — *CAS prévu juste après le MVP.*

Le niveau d'audit dépend du moteur et de son édition : voir [la matrice de capacités](docs/08-CAPACITES-PAR-MOTEUR.md).

## Comment ça marche
```
        Console DataBastion  (UI, politiques, incidents, alerting)
                  ▲
                  │  HTTPS 443, initié uniquement par les agents
      ┌───────────┼───────────┐
   Agent        Agent       Agent        ← aucun port entrant
     │            │           │
 PostgreSQL    MongoDB     OpenLDAP
```
- **Outbound only** : aucun port à ouvrir vers vos serveurs de bases.
- **Minimisation à la source** : aucune valeur sensible brute et aucun identifiant de base ne quitte l'agent. La console ne voit que des emplacements, des échantillons masqués et des empreintes.
- **Linux, Docker, installation en moins de 15 minutes** (objectif MVP).

Détails : [architecture](docs/02-ARCHITECTURE.md) · [sécurité](docs/05-SECURITE-ET-BONNES-PRATIQUES.md) · [protocole](docs/09-PROTOCOLE-AGENT.md).

## Éditions
| | Community | Enterprise |
|---|---|---|
| Licence | Apache 2.0 | Commerciale |
| Discovery + Audit, tous connecteurs | ✅ | ✅ |
| Politiques, incidents, alerting e-mail / webhook | ✅ | ✅ |
| Auth locale + OIDC, journal d'audit console | ✅ | ✅ |
| Multi-tenancy, RBAC fin, SAML / SCIM | | ✅ |
| Mode Prevention avancé, export SIEM, rapports de conformité | | ✅ |
| Support & SLA | | ✅ |

Détails : [docs/EDITIONS.md](docs/EDITIONS.md).

## Contribuer
Les contributions sont les bienvenues : voir [CONTRIBUTING.md](CONTRIBUTING.md). Les PR visent la branche `dev`.
Versions et releases : [RELEASE.md](RELEASE.md) · [CHANGELOG.md](CHANGELOG.md).
Vulnérabilités : **ne pas ouvrir d'issue publique**, voir [SECURITY.md](SECURITY.md).

## Licence
DataBastion Community Edition est distribué sous [licence Apache 2.0](LICENSE).
Le nom « DataBastion » et le logo ne sont pas couverts par cette licence : voir [TRADEMARKS.md](TRADEMARKS.md).
