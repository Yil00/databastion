# Protocole agent ↔ console (v1, brouillon)

> Brouillon de conception. La source de vérité sera `shared/protocol/openapi.yaml` (phase 0). Toute modification du protocole passe par ce contrat et, si elle casse la compatibilité, par un ADR.

## Principes
- L'agent est **toujours client**. La console n'initie aucune connexion.
- HTTPS (TLS 1.3), JSON, préfixe `/api/agent/v1`
- En-têtes sur chaque requête :
  - `Authorization: Bearer <agent_secret>` (sauf enrôlement)
  - `X-DataBastion-Agent-Id: <uuid>`
  - `X-DataBastion-Protocol: 1`
  - `User-Agent: databastion-agent/<version>`
- Idempotence : chaque envoi porte un `batch_id` (UUIDv7). La console ignore un lot déjà reçu, ce qui permet à l'agent de renvoyer sans risque après une coupure.

## Endpoints

| Méthode | Chemin | Rôle |
|---------|--------|------|
| `POST` | `/enroll` | Échange le jeton d'enrôlement contre `agent_id` + `agent_secret` |
| `POST` | `/heartbeat` | État, cibles détectées, métriques, version. Toutes les 30 s |
| `GET` | `/jobs?wait=25` | **Long-poll** : renvoie les jobs en attente, ou `204` après 25 s |
| `POST` | `/jobs/{job_id}/status` | `running` / `succeeded` / `failed` + progression |
| `POST` | `/findings` | Lot de findings Discovery |
| `POST` | `/events` | Lot d'événements d'accès normalisés (Audit) |
| `POST` | `/rotate` | Confirme la prise en compte d'un nouveau secret |

### Réponses spéciales
- `401` : secret invalide ou révoqué → l'agent s'arrête et le journalise (pas de boucle de retry agressive)
- `426` : version de protocole trop ancienne → l'agent le signale dans ses logs et continue en mode spool
- `429` / `503` : backoff exponentiel avec *jitter*, en respectant `Retry-After`

## Enrôlement
```
Admin (console)            Agent                               Console
     │  crée un jeton         │                                    │
     │  (usage unique, 24 h)  │                                    │
     │───────────────────────▶│  POST /enroll {token, hostname,    │
     │   (copie manuelle)     │        version, connectors}        │
     │                        │───────────────────────────────────▶│
     │                        │◀── {agent_id, agent_secret,        │
     │                        │     console_min_protocol}          │
     │                        │  génère sa clé HMAC locale         │
     │                        │  (jamais transmise)                │
```

## Jobs (console → agent, via long-poll)
```json
{
  "job_id": "01920f5e-…",
  "type": "discovery.scan",
  "target_id": "pg-prod-1",
  "params": { "sample_rows": 200, "max_duration_s": 900, "schemas": ["public"] },
  "classifiers_version": "2026.09.1"
}
```
Types MVP : `discovery.scan`, `audit.configure` (seuils, emplacements sensibles à surveiller), `agent.config.reload`, `agent.rotate_secret`.

## Finding (agent → console)
```json
{
  "batch_id": "01920f60-…",
  "job_id": "01920f5e-…",
  "findings": [{
    "target_id": "pg-prod-1",
    "location": { "engine": "postgres", "database": "crm", "schema": "public",
                  "object": "clients", "field": "email" },
    "classifier": "pii.email",
    "confidence": 0.97,
    "sampled": 200,
    "matched": 194,
    "estimated_rows": 1250000,
    "masked_samples": ["j*********@e******.fr", "m****@g****.com"],
    "fingerprints": ["hmac:9f2c…", "hmac:41ab…"]
  }]
}
```
**Interdit** : tout champ contenant une valeur brute. La console rejette les lots qui ne respectent pas le schéma (`additionalProperties: false`).

## Événement d'accès (agent → console)
```json
{
  "target_id": "pg-prod-1",
  "ts": "2026-09-28T14:02:11Z",
  "principal": { "db_user": "backup", "client_addr": "10.0.3.14", "application": "pg_dump" },
  "action": "read",
  "objects": [{ "database": "crm", "schema": "public", "object": "clients" }],
  "rows": 1250000,
  "signals": ["signature.pg_dump", "shape.full_table_copy"],
  "source": "pgaudit",
  "aggregated_count": 1
}
```
L'agent **pré-agrège** les événements répétitifs (même principal, même objet, même action sur une fenêtre de 60 s) pour limiter le volume.

## Heartbeat
Contient : version, uptime, connecteurs actifs, état de chaque cible (`reachable`, `audit_level`), taille du spool, et des métriques internes (compteurs, durées). La console les réexpose sur `/metrics`.
