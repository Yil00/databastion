# Roadmap MVP – DataBastion

Le MVP (v0.1.0) est découpé en phases. Chaque phase se divise en **chantiers** indépendants, attribuables à des agents différents qui travaillent en parallèle (voir [AGENTS.md](../AGENTS.md#travail-multi-agents)).

Légende : `[ ]` à faire · `[~]` en cours · `[x]` terminé. Mettre ce fichier à jour à chaque fin de tâche.

**Phase courante : 0**

---

## Phase 0 – Fondations
*Objectif : un dépôt où plusieurs agents peuvent travailler sans se marcher dessus.*

| Chantier | Propriétaire | Tâches |
|----------|--------------|--------|
| P0-A Dépôt & CI | `docs-keeper` | [ ] Arborescence cible (`console/`, `agent/`, `shared/`, `dev/`) · [x] Branches `main` + `dev` protégées ([RELEASE.md](../RELEASE.md)) · [x] CI GitHub Actions : doc, gitleaks, console, agent, protocole (activés selon la présence du composant) · [x] Vérification DCO + format des titres de PR · [x] Workflow de release (`release-it` au merge vers `main`, `[skip-release]`) · [x] Workflow images multi-arch signées sur tags `-*` et release · [x] Script de bump de version · [x] Hooks pre-commit vérifiés · [x] Dependabot · [ ] Secret `RELEASE_TOKEN` configuré · [ ] Ajouter npm/cargo à Dependabot quand `console/` et `agent/` existent |
| P0-B Protocole | `agent-engineer` + revue `security-reviewer` | [ ] `shared/protocol/openapi.yaml` v1 depuis [09-PROTOCOLE-AGENT.md](09-PROTOCOLE-AGENT.md) · [ ] Fixtures JSON valides / invalides · [ ] Génération des types TS et Rust |
| P0-C Env. de dev | `agent-engineer` | [ ] `dev/docker-compose.yml` : PostgreSQL + pgaudit, MariaDB + server_audit, MySQL, MongoDB, OpenLDAP + accesslog · [ ] Jeux de fausses PII seedés (Faker, FR + intl) avec vérité terrain (`dev/ground-truth.json`) |
| P0-D Squelettes | `console-engineer` / `agent-engineer` | [ ] Next.js + Drizzle + pg-boss qui démarre · [ ] Workspace Cargo qui compile, `cargo clippy -D warnings` vert |

**Critère de sortie** : `make dev` lance tout ; CI verte ; contrat de protocole validé.

## Phase 1 – Console socle & agent core
*Objectif : un agent s'enrôle et apparaît « en ligne » dans la console.*

| Chantier | Propriétaire | Tâches |
|----------|--------------|--------|
| P1-A Console | `console-engineer` | [ ] Schéma DB (users, agents, targets, jobs, findings, events, incidents, policies, audit_log) · [ ] Auth locale (argon2id) · [ ] Journal d'audit console · [ ] Jetons d'enrôlement · [ ] API agent : `/enroll`, `/heartbeat`, `/jobs` (long-poll) · [ ] Page Agents & Cibles |
| P1-B Agent core | `agent-engineer` | [ ] Config `agent.yaml` · [ ] Enrôlement + stockage d'identité `0600` · [ ] Uplink (retry, backoff, `batch_id`) · [ ] Spool disque borné · [ ] Heartbeat + métriques · [ ] Détection locale des moteurs (ADR-0006) |
| P1-C Revue | `security-reviewer` | [ ] Revue enrôlement / stockage des secrets / validation des entrées API |

**Critère de sortie** : enrôlement de bout en bout en conteneur ; révocation effective en < 60 s.

## Phase 2 – Discovery SQL
*Objectif : premiers findings réels sur PostgreSQL et MySQL/MariaDB.* → **v0.1.0-alpha**

| Chantier | Propriétaire | Tâches |
|----------|--------------|--------|
| P2-A Classifieurs | `agent-engineer` | [ ] Crate `classifiers` : regex + validateurs (Luhn, IBAN mod 97, NIR clé), secrets, indices sur les noms de colonnes · [ ] Masquage + HMAC · [ ] Tests de propriétés sur le masquage |
| P2-B Connecteur PG | `agent-engineer` | [ ] Introspection du schéma · [ ] Échantillonnage borné (`TABLESAMPLE`, `statement_timeout`) · [ ] `check()` + niveau d'audit |
| P2-C Connecteur MySQL | `agent-engineer` (autre instance) | [ ] Idem PG pour MySQL / MariaDB |
| P2-D Console findings | `console-engineer` | [ ] Ingestion `/findings` (validation stricte) · [ ] Lancement de scans · [ ] Vue findings par cible / classifieur · [ ] Marquage faux positif |
| P2-E Test d'invariant | `security-reviewer` | [ ] Test auto : aucune PII de `dev/ground-truth.json` en clair dans la base console |

**Critère de sortie** : rappel ≥ 90 %, précision ≥ 85 % sur la vérité terrain ; test d'invariant vert.

## Phase 3 – Politiques, incidents, alerting
| Chantier | Propriétaire | Tâches |
|----------|--------------|--------|
| P3-A Moteur de politiques | `console-engineer` | [ ] Modèle condition → action · [ ] Exécution dans le worker · [ ] Exceptions |
| P3-B Incidents | `console-engineer` | [ ] Cycle de vie (ouvert, acquitté, résolu, faux positif) · [ ] UI |
| P3-C Alerting | `console-engineer` | [ ] SMTP · [ ] Webhook signé HMAC · [ ] Alerte « agent silencieux » |

## Phase 4 – Audit SQL
| Chantier | Propriétaire | Tâches |
|----------|--------------|--------|
| P4-A Audit PG | `agent-engineer` | [ ] Lecture pgaudit (csvlog / jsonlog) · [ ] Mode dégradé `pg_stat_statements` · [ ] Signatures `pg_dump`, `COPY` |
| P4-B Audit MySQL/MariaDB | `agent-engineer` | [ ] `server_audit` · [ ] Percona `audit_log` · [ ] `performance_schema` · [ ] Signatures `mysqldump`, `INTO OUTFILE` |
| P4-C Corrélation | `console-engineer` | [ ] Ingestion `/events` · [ ] Score volume × sensibilité · [ ] Lignes de base par principal |

**Critère de sortie** : `pg_dump` et `mysqldump` dans `dev/` → incident en < 2 min.

## Phase 5 – MongoDB
[ ] Discovery (échantillonnage de documents, champs imbriqués) · [ ] Audit Enterprise/Percona (`auditLog`) · [ ] Audit Community (logs JSON + profiler, niveau affiché « Limité ») · [ ] Détection `mongodump` / `mongoexport`

## Phase 6 – OpenLDAP
[ ] Discovery (attributs sensibles : `userPassword`, `mail`, `telephoneNumber`, attributs personnalisés) · [ ] Audit via `cn=accesslog` · [ ] Détection des recherches massives

## Phase 7 – Durcissement & release v0.1.0
[ ] Images multi-arch distroless signées (cosign) · [ ] Paquet `.deb` + unité systemd · [ ] Test « installation < 15 min » · [ ] Tests de charge / impact base · [ ] Test de stabilité 72 h · [ ] Documentation utilisateur · [ ] Politique de sécurité publiée

---

## Après le MVP
| Phase | Contenu |
|-------|---------|
| 1.5 | Connecteur CAS |
| 2 | Mode Prevention (proxy), Helm, mTLS, gRPC, export OTLP, stockage des événements à grande échelle |
| 3+ | ML de détection d'anomalies, autres OS |
