# DataBastion – Résumé du projet (MVP)

## Vision
**DataBastion** est une plateforme open-source de **Data Loss Prevention (DLP)** dédiée aux bases de données et annuaires open-source.

Elle détecte, audite et (à terme) prévient les fuites de données sensibles **au plus près de la source** :
- PostgreSQL
- MySQL / MariaDB
- MongoDB
- OpenLDAP
- CAS (Central Authentication Service) — *phase 1.5, hors MVP*

## Problème adressé
Les DLP classiques surveillent les postes, la messagerie ou le réseau. Ils ne savent pas **où** se trouvent les données sensibles dans les bases, ni **qui** les extrait massivement (`pg_dump`, `mysqldump`, `mongoexport`, exports LDIF, `SELECT *` sur une table de clients…). DataBastion répond à ces deux questions :
1. **Où sont mes données sensibles ?** → *Discovery* (classification des données)
2. **Qui y accède de façon anormale ?** → *Audit* (surveillance des accès et des exports)

## Objectifs principaux
- Protéger les données au plus près de la source (bases et annuaires)
- Architecture simple, sécurisée, déployable en Docker en moins de 15 minutes
- MVP exclusivement **Linux** (Ubuntu, Debian et dérivés)
- Interface web moderne pour les politiques, les findings et les incidents

## Principes d'architecture
Inspirée de **Portabase** (agents *outbound*) et de la séparation *agent / collecteur* popularisée par Prometheus — mais **sans** son modèle *pull* (voir [ADR-0004](adr/0004-observabilite-via-console.md)) :

- **Console centrale** (Control Plane) : interface web, politiques, stockage des findings et incidents, alerting
- **Agent léger** (Data Plane) : un binaire unique avec des *connecteurs* par moteur, déployé au plus près des bases
- **Outbound only** : les agents initient toutes les communications ; la console ne contacte **jamais** les agents → aucun port entrant côté bases
- **Minimisation à la source** : aucune valeur sensible brute ne quitte l'agent ; les identifiants des bases ne quittent jamais l'agent
- Tout tourne en Docker (ou paquet `.deb` pour l'agent)

## Périmètre MVP (Linux only)
Détail complet : [04-PERIMETRE-MVP.md](04-PERIMETRE-MVP.md).

### Inclus
- Console web (Next.js)
- Agent avec connecteurs PostgreSQL, MySQL/MariaDB, MongoDB, OpenLDAP
- Modes **Discovery** et **Audit** (niveau d'audit dépendant de l'édition du moteur, voir [08-CAPACITES-PAR-MOTEUR.md](08-CAPACITES-PAR-MOTEUR.md))
- Politiques simples, findings, incidents, alerting basique (email, webhook)
- Déploiement Docker Compose

### Exclus volontairement
- Windows / macOS / iOS
- Agents endpoint sur les postes utilisateurs
- Mode Prevention temps réel (phase 2)
- CAS (phase 1.5)

## Nom
Nom retenu : **DataBastion**. Historique des candidats : [06-NOMS-PROJET.md](06-NOMS-PROJET.md).

---
*Document de cadrage MVP – septembre 2026*
