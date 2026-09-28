# ADR-0004 : Métriques des agents remontées via la console

- **Statut** : Accepté
- **Date** : 2026-09-28

## Contexte
Le cadrage initial mentionnait des « métriques Prometheus exposées par chaque agent ». Prometheus fonctionne en *pull* : il vient interroger chaque cible, ce qui demande un port entrant vers les agents. C'est contraire au principe outbound only.

## Décision
- Les agents n'exposent **aucun port** par défaut.
- Leurs métriques (compteurs, durées, taille du spool, état des cibles) sont envoyées dans le **heartbeat**.
- La console les réexpose, avec ses propres métriques, sur **un seul** endpoint `/metrics` au format Prometheus (labels `agent_id`, `target_id`). Cet endpoint est authentifié et réservé au réseau interne.
- Option `metrics.local_listen` (désactivée par défaut, `127.0.0.1` uniquement) pour du diagnostic sur l'hôte.

## Conséquences
- Prometheus ne scrape qu'une cible : la console.
- La granularité des métriques agents suit la fréquence du heartbeat (30 s), ce qui suffit pour ce type d'outil.
- L'état « agent silencieux » devient lui-même une métrique et une alerte (`databastion_agent_last_seen_seconds`).

## Alternatives écartées
- **Pushgateway** : composant en plus, non conçu pour ce cas.
- **OTLP push vers un collecteur** : pertinent plus tard pour les clients qui ont déjà un collecteur OpenTelemetry. Pourra être ajouté en option (phase 2).
