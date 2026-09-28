# Sécurité & bonnes pratiques – DataBastion

Un outil de sécurité qui lit des données sensibles est lui-même une cible. Ces règles ne sont pas négociables.

## Invariants de sécurité
1. **Outbound only** : aucun port entrant vers les agents ni vers les bases.
2. **Aucune valeur sensible brute ne quitte l'agent.** Seulement : emplacement, type détecté, confiance, volumétrie, échantillon masqué, empreinte HMAC ([ADR-0003](adr/0003-minimisation-a-la-source.md)).
3. **Les identifiants des bases ne quittent jamais l'hôte de l'agent.** La console ne les stocke pas et ne les reçoit pas.
4. **Moindre privilège** : l'agent se connecte avec un compte dédié en **lecture seule**.
5. **Pas de secrets dans les images ni dans le dépôt** : variables d'environnement, secrets Docker, fichiers montés.
6. **Journal d'audit de la console** : toute action utilisateur (connexion, changement de politique, acquittement d'incident, enrôlement ou révocation d'agent) est journalisée.

## Modèle de menace (résumé)
| Compromission | Ce que l'attaquant obtient | Ce qu'il n'obtient pas |
|---------------|----------------------------|------------------------|
| Console | La cartographie des emplacements sensibles, des échantillons masqués | Les données elles-mêmes, les identifiants des bases, un accès réseau vers les bases |
| Un agent | Son propre secret, le compte lecture seule de ses cibles | Les autres agents, les secrets de la console |
| Réseau entre agent et console | Rien (TLS 1.3) | |

La cartographie reste une information sensible : la console doit être protégée (HTTPS, authentification, pas d'exposition publique conseillée).

## Masquage et empreintes
- **Échantillon masqué** : `jean.dupont@exemple.fr` → `j*********@e******.fr` ; IBAN → `FR76 **** **** **** **** ***1 89`
- **Empreinte** : `HMAC-SHA256(clé_locale_agent, valeur_normalisée)`. Elle permet de dédupliquer et de corréler sans révéler la valeur. La clé est générée à l'enrôlement et **ne quitte jamais l'agent**.
- Le masquage est implémenté dans une crate unique (`classifiers`/`masking`) et couvert par des tests de non-régression.

## Chiffrement
- **En transit** : TLS 1.3 obligatoire. Plus de chiffrement AES-GCM applicatif en plus : sans clé détenue hors de la console, il n'ajoute rien à TLS.
- **Au repos (console)** : les colonnes sensibles (échantillons masqués, secrets de webhook, configuration SMTP) sont chiffrées en AES-256-GCM avec une clé `DATABASTION_ENCRYPTION_KEY` fournie par secret Docker.
- Les secrets d'agents sont stockés **hachés** (argon2id) côté console.

## Gestion des secrets d'agents
- Jeton d'enrôlement à usage unique et à durée de vie courte (24 h), généré dans la console
- À l'enrôlement, l'agent reçoit `agent_id` + un secret long ; il le stocke dans un fichier `0600`
- Rotation depuis la console (l'agent récupère le nouveau secret lors de son prochain appel)
- Révocation immédiate
- Intégration Vault : plus tard

## Comptes de base de données recommandés (lecture seule)
```sql
-- PostgreSQL 14+
CREATE ROLE databastion LOGIN PASSWORD '...';
GRANT pg_read_all_data TO databastion;   -- Discovery (échantillonnage)
GRANT pg_monitor       TO databastion;   -- statistiques, pg_stat_statements

-- MySQL / MariaDB
CREATE USER 'databastion'@'localhost' IDENTIFIED BY '...';
GRANT SELECT, PROCESS, SHOW VIEW ON *.* TO 'databastion'@'localhost';
GRANT SELECT ON performance_schema.* TO 'databastion'@'localhost';
```
MongoDB : rôles `read` sur les bases ciblées + `clusterMonitor`. OpenLDAP : un DN de service avec droits de lecture sur l'arbre et sur `cn=accesslog`.

## Recommandations de déploiement
- Agents et console exécutés en utilisateur **non-root**, système de fichiers en lecture seule, `cap_drop: ALL`, `no-new-privileges`
- Console derrière un reverse-proxy (Traefik / Nginx / Caddy) avec HTTPS
- La base interne de la console n'est jamais exposée hors du réseau Docker
- Activer les journaux natifs des bases (pgaudit, plugin d'audit MariaDB, `accesslog` OpenLDAP…)

## Points d'attention
- **Performance** : échantillonnage borné (N lignes par colonne, `TABLESAMPLE` quand c'est possible), exécution hors heures de pointe configurable, `statement_timeout` sur chaque requête de l'agent
- **Faux positifs** : exceptions par emplacement / classifieur, retour « faux positif » qui alimente les exceptions
- **Mises à jour** : l'agent reste compatible avec la version N-1 du protocole ; la console annonce la version minimale attendue
