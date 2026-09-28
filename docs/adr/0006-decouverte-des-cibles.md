# ADR-0006 : Cibles déclarées + détection locale, pas de scan réseau

- **Statut** : Accepté
- **Date** : 2026-09-28

## Contexte
Le cadrage initial parlait de « découverte automatique des bases » sans préciser le mécanisme. Un agent qui scanne le réseau serait bruyant, déclencherait les IDS et irait contre le moindre privilège.

## Décision
- **Source de vérité** : les cibles déclarées dans `agent.yaml` (moteur, hôte/socket, compte, référence au secret).
- **Détection locale** (suggestion uniquement) : l'agent repère les moteurs présents **sur son hôte** (sockets Unix `/var/run/postgresql`, `/run/mysqld`, ports d'écoute locaux 5432/3306/27017/389, processus `postgres`, `mariadbd`, `mongod`, `slapd`). Il les remonte dans le heartbeat comme « cibles détectées non configurées ». La console les affiche avec un assistant de configuration.
- L'agent ne tente **jamais** de se connecter à une cible sans identifiants configurés, et ne scanne aucune adresse distante.
- Pas d'accès au socket Docker.

## Conséquences
- Pas de surprise pour l'équipe réseau.
- Le critère de succès « découverte automatique des bases » devient : « l'agent signale les moteurs présents sur son hôte ».
