# Périmètre MVP – DataBastion

## Objectif du MVP
Livrer une première version **utile et stable** (v0.1.0), centrée sur Linux et les cas d'usage prioritaires. Découpage en phases : [ROADMAP.md](ROADMAP.md).

## Inclus dans le MVP
- Console web (Next.js) : agents, cibles, findings, incidents, politiques
- Agent Rust avec connecteurs :
  - PostgreSQL : Discovery + Audit
  - MySQL / MariaDB : Discovery + Audit
  - MongoDB : Discovery + Audit (niveau selon l'édition)
  - OpenLDAP : Discovery + Audit (via l'overlay `accesslog`)
- Classifieurs de base : e-mail, téléphone FR/intl, IBAN, carte bancaire (Luhn), NIR, secrets (clés API, hash de mots de passe, clés privées)
- Politiques DLP simples (conditions + actions : créer un incident, alerter, ignorer)
- Liste d'exceptions / retour « faux positif »
- Alerting basique : e-mail (SMTP) et webhook signé
- Communication outbound sécurisée (HTTPS, long-poll)
- Déploiement Docker Compose

## Niveaux d'audit : ce que le MVP promet
L'audit dépend de ce que le moteur journalise nativement. DataBastion **ne promet pas plus que ce que le moteur fournit** et l'affiche dans la console. Voir [08-CAPACITES-PAR-MOTEUR.md](08-CAPACITES-PAR-MOTEUR.md).

## Exclus volontairement du MVP
| Élément | Raison | Phase prévue |
|---------|--------|--------------|
| CAS | Moins prioritaire | 1.5 |
| Mode Prevention temps réel | Nécessite proxy / hooks | 2 |
| Helm / Kubernetes | Compose suffit pour le MVP | 2 |
| mTLS agent ↔ console | Jeton + TLS suffisent pour le MVP | 2 |
| Machine learning avancé | Trop lourd pour un MVP | 2/3 |
| Multi-tenancy, RBAC fin, SAML | Enterprise ([EDITIONS.md](EDITIONS.md)) | 2+ |
| Windows / macOS / iOS | Complexité élevée | 3+ |
| Agent endpoint postes utilisateurs | Hors du positionnement « au plus près de la base » | 3+ |

## Critères de succès du MVP
- Console + un agent déployés en **moins de 15 minutes** via Docker Compose
- Un agent démarre sans aucun port entrant ouvert
- Détection correcte des PII du jeu de données de test (`dev/`) : rappel ≥ 90 %, précision ≥ 85 %
- Détection d'un `pg_dump`, d'un `mysqldump`, d'un `mongodump` et d'une recherche LDAP massive dans l'environnement de test
- **Aucune valeur sensible brute** présente dans la base de la console (test automatisé)
- Impact sur la base surveillée < 2 % CPU en régime Discovery (échantillonnage borné)
- Agents stables 72 h sous Ubuntu 24.04 et Debian 12
