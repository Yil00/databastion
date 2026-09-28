# Capacités par moteur

DataBastion ne peut auditer que ce que le moteur journalise. Cette page dit **honnêtement** ce qui est possible pour chaque moteur et chaque édition. La console affiche le niveau atteint pour chaque cible : un audit « Limité » ne doit jamais passer pour un audit complet.

## Niveaux d'audit
| Niveau | Signification |
|--------|---------------|
| **Complet** | Chaque accès est journalisé avec l'utilisateur, l'objet et le volume retourné |
| **Partiel** | Les accès sont visibles, mais une information manque (volume, objet précis) ou dépend d'un échantillonnage |
| **Limité** | Seuls les accès lents, ou des statistiques agrégées, sont visibles. Détection d'exports probable, pas garantie |
| **Aucun** | Discovery seulement |

La **Discovery** (classification des données) fonctionne de la même manière sur tous les moteurs : elle ne dépend que d'un compte en lecture.

## Matrice

| Moteur / édition | Source d'audit | Niveau | Prérequis côté base |
|------------------|----------------|--------|---------------------|
| **PostgreSQL** + pgaudit | Journal pgaudit (`csvlog` / `jsonlog`) + `pg_stat_statements` | Complet | Extension `pgaudit` (paquets PGDG, libre), `log_connections=on`, `application_name` dans les logs |
| PostgreSQL sans pgaudit | `pg_stat_statements` + sondage de `pg_stat_activity` | Limité | `pg_stat_statements` activé |
| **MariaDB** | Plugin `server_audit` (inclus, libre) + slow log / `performance_schema` pour les volumes | Complet | `plugin_load_add = server_audit`, `server_audit_events=CONNECT,QUERY_DML,TABLE` |
| **Percona Server for MySQL** | Plugin `audit_log` | Complet | Plugin activé, format JSON |
| **MySQL Community** | `performance_schema` (`events_statements_history_long`, `ROWS_SENT`) | Partiel | `performance_schema=ON`, consumers d'historique activés |
| **MongoDB Enterprise** | `auditLog` (JSON) + profiler pour les volumes | Complet | `auditLog.destination=file`, filtre sur les lectures |
| **Percona Server for MongoDB** | `auditLog` | Complet | Idem |
| **MongoDB Community** | Logs structurés JSON (opérations lentes : `appName`, `nreturned`) + profiler | Limité → Partiel | Profiler niveau 1 avec `slowms` bas ; niveau 2 = Partiel mais coûteux |
| **OpenLDAP** | Overlay `slapo-accesslog` (base `cn=accesslog` interrogeable en LDAP) | Complet | `olcAccessLogOps: reads writes session`, compte de lecture sur `cn=accesslog` |

> **MongoDB Community** : il n'existe pas de journal d'audit dans cette édition. DataBastion voit les opérations *lentes* (ou toutes, au prix d'un profiler niveau 2). Un `mongodump` rapide sur une petite collection peut passer inaperçu. **À écrire clairement dans la documentation utilisateur et dans la console.**

> **MySQL Community** : le plugin d'audit officiel est réservé à MySQL Enterprise. `performance_schema` donne les requêtes récentes et le nombre de lignes renvoyées, mais son historique est un tampon circulaire : l'agent doit le lire assez souvent pour ne rien perdre.

## Signatures d'export connues
| Outil | Signature observable | Moteur |
|-------|---------------------|--------|
| `pg_dump` / `pg_dumpall` | `application_name = 'pg_dump'`, `COPY … TO STDOUT` sur chaque table, transaction `REPEATABLE READ` | PostgreSQL |
| `COPY … TO` / `\copy` | Instruction `COPY` sortante | PostgreSQL |
| `mysqldump` | `SELECT /*!40001 SQL_NO_CACHE */ * FROM`, `SHOW CREATE TABLE` en série, `FLUSH TABLES WITH READ LOCK` | MySQL / MariaDB |
| `SELECT … INTO OUTFILE` | Instruction explicite | MySQL / MariaDB |
| `mongodump` / `mongoexport` | `appName` de l'outil, `find` sans filtre sur toute la collection | MongoDB |
| Export LDIF / `ldapsearch` massif | Recherche `scope=sub` depuis la racine, filtre `(objectClass=*)`, `reqEntries` élevé | OpenLDAP |

Les signatures se falsifient facilement (`application_name` est choisi par le client). Elles ne sont qu'**un** des trois signaux ; la combinaison volume × sensibilité reste le signal principal (voir [02-ARCHITECTURE.md](02-ARCHITECTURE.md#détection-dexfiltration-audit)).

## Coût pour la base surveillée
| Source | Coût | Recommandation |
|--------|------|----------------|
| pgaudit (classe `read`) | Moyen : volume de logs | Restreindre aux rôles et objets sensibles (`pgaudit.role`) |
| MariaDB `server_audit` | Faible à moyen | Filtrer les utilisateurs techniques |
| `performance_schema` | Faible | OK |
| MongoDB profiler niveau 2 | **Élevé** | À éviter en production ; niveau 1 avec `slowms` adapté |
| OpenLDAP `accesslog` | Faible | Purge avec `olcAccessLogPurge` |
