# CONTEXT.md – DataBastion

Contexte projet pour tout contributeur, humain ou agent IA. À lire **avant** toute tâche.

## En une phrase
DataBastion est un DLP open-source (Apache 2.0) qui trouve les données sensibles dans PostgreSQL, MySQL/MariaDB, MongoDB et OpenLDAP (*Discovery*) et détecte leurs extractions anormales (*Audit*), grâce à des agents qui ne reçoivent jamais de connexion entrante.

## Où en est le projet
- **Phase courante** : 0 – Fondations (voir [docs/ROADMAP.md](docs/ROADMAP.md))
- Aucun code applicatif encore : uniquement la conception.

## Invariants (non négociables)
| # | Invariant | Source |
|---|-----------|--------|
| I1 | Les agents n'ouvrent aucun port entrant ; seul l'agent initie les connexions (HTTPS 443) | ADR-0001, ADR-0004 |
| I2 | Aucune valeur sensible brute ne quitte l'agent : échantillons masqués + HMAC uniquement | ADR-0003 |
| I3 | Les identifiants des bases ne quittent jamais l'hôte de l'agent | ADR-0003 |
| I4 | L'agent ne fait que de la lecture, avec un compte dédié à moindre privilège | 05-SECURITE |
| I5 | Pas de scan réseau : cibles déclarées + détection locale uniquement | ADR-0006 |
| I6 | Le protocole est défini par `shared/protocol/openapi.yaml` ; aucun type de protocole écrit à la main | 03-STACK |
| I7 | Dépôt public = Apache 2.0 uniquement ; aucun code Enterprise ici | ADR-0005 |

## Glossaire
| Terme | Définition |
|-------|-----------|
| **Console** | Control plane : UI Next.js (`web`) + `worker` + PostgreSQL interne |
| **Agent** | Binaire Rust déployé près des bases ; client unique de la console |
| **Connecteur** | Module de l'agent spécifique à un moteur (`connector-postgres`…) |
| **Cible** (*target*) | Une instance de base ou d'annuaire surveillée par un agent |
| **Enrôlement** | Échange d'un jeton à usage unique contre une identité d'agent |
| **Job** | Ordre de la console récupéré par l'agent en long-poll (ex. `discovery.scan`) |
| **Classifieur** | Détecteur d'un type de donnée (`pii.email`, `pii.iban`, `secret.aws_key`…) |
| **Finding** | Résultat Discovery : un emplacement contient un type de donnée sensible |
| **Événement d'accès** | Résultat Audit normalisé : qui a lu quoi, combien, avec quels signaux |
| **Signal** | Indice d'exfiltration : `signature.*`, `shape.*`, `volume.*` |
| **Politique** | Règle condition → action appliquée par le worker |
| **Incident** | Ce qu'une politique crée, et que l'utilisateur traite |
| **Niveau d'audit** | Complet / Partiel / Limité / Aucun, selon le moteur (docs/08) |

## Carte de la documentation
- Pourquoi / quoi : [docs/01-RESUME-PROJET.md](docs/01-RESUME-PROJET.md), [docs/04-PERIMETRE-MVP.md](docs/04-PERIMETRE-MVP.md)
- Comment : [docs/02-ARCHITECTURE.md](docs/02-ARCHITECTURE.md), [docs/03-STACK-TECHNIQUE.md](docs/03-STACK-TECHNIQUE.md), [docs/09-PROTOCOLE-AGENT.md](docs/09-PROTOCOLE-AGENT.md)
- Limites par moteur : [docs/08-CAPACITES-PAR-MOTEUR.md](docs/08-CAPACITES-PAR-MOTEUR.md)
- Sécurité : [docs/05-SECURITE-ET-BONNES-PRATIQUES.md](docs/05-SECURITE-ET-BONNES-PRATIQUES.md)
- Décisions figées : [docs/adr/](docs/adr/README.md)
- Plan : [docs/ROADMAP.md](docs/ROADMAP.md)
