# Architecture DataBastion – MVP

## Schéma global

```
                   Prometheus / Grafana (optionnel)
                              │ scrape (réseau interne console)
                              ▼
┌──────────────────────────────────────────────────────────┐
│                    Console DataBastion                   │
│                 (Control Plane – Docker)                 │
│                                                          │
│  web     : UI Next.js + API utilisateurs + API agents    │
│  worker  : corrélation, politiques, alerting (pg-boss)   │
│  postgres: état, findings, incidents, file de jobs       │
│                                                          │
│  /metrics : métriques console + agents agrégées          │
└───────────────────────────▲──────────────────────────────┘
                            │ HTTPS 443 (TLS 1.3)
                            │ initié UNIQUEMENT par les agents
                            │ long-poll jobs · envoi résultats · heartbeat
          ┌─────────────────┼─────────────────┐
          │                 │                 │
┌─────────┴──────┐ ┌────────┴───────┐ ┌───────┴────────┐
│ Agent (hôte A) │ │ Agent (hôte B) │ │ Agent (hôte C) │
│ ─ postgres     │ │ ─ mongodb      │ │ ─ openldap     │
│ ─ mysql        │ │                │ │                │
└───┬────────┬───┘ └───────┬────────┘ └───────┬────────┘
    │        │             │                  │
PostgreSQL MariaDB      MongoDB           OpenLDAP
 (lecture seule, compte dédié, identifiants locaux à l'agent)
```

## Composants

### Console
| Processus | Rôle |
|-----------|------|
| `web` | UI, API utilisateurs, API agents (`/api/agent/v1/*`) |
| `worker` | Même image, autre commande. Applique les politiques, corrèle les événements, crée les incidents, envoie les alertes |
| `postgres` | Base interne. Sert aussi de file de jobs (pg-boss) → **pas de Redis** |

### Agent
Un **binaire Rust unique** ([ADR-0002](adr/0002-agent-unique-connecteurs.md)) composé de :

```
agent
├── core        enrôlement, configuration, planificateur, uplink HTTPS, spool disque
├── connectors  postgres · mysql · mongodb · openldap   (features Cargo)
├── classifiers détection PII / secrets (regex + validateurs : Luhn, IBAN, NIR…)
└── masking     masquage + empreintes HMAC avant tout envoi
```

Un agent peut surveiller plusieurs cibles, de moteurs différents, sur le même hôte.

## Principes clés
1. **Outbound only** ([ADR-0001](adr/0001-transport-https-outbound.md)) : l'agent ouvre toutes les connexions vers la console en HTTPS/443. Ça passe les proxys d'entreprise et il n'y a aucun port à ouvrir vers la zone des bases.
2. **Minimisation à la source** ([ADR-0003](adr/0003-minimisation-a-la-source.md)) : l'agent n'envoie que des métadonnées (emplacement, type détecté, volumétrie, échantillon **masqué**, empreinte HMAC). Si la console est compromise, aucune donnée sensible ni aucun identifiant de base n'est exposé.
3. **Identifiants des bases locaux à l'agent** : la console ne connaît jamais les mots de passe des bases.
4. **Cibles déclarées + détection locale** ([ADR-0006](adr/0006-decouverte-des-cibles.md)) : pas de scan réseau.
5. **Observabilité via la console** ([ADR-0004](adr/0004-observabilite-via-console.md)) : les agents n'exposent aucun port ; leurs métriques voyagent dans le heartbeat.

## Modes de fonctionnement de l'agent
1. **Discovery** : parcours périodique des schémas / collections / entrées, échantillonnage, classification. Produit des *findings* (« la colonne `clients.email` contient des adresses e-mail, confiance 0,97 »).
2. **Audit** : lecture des journaux natifs, normalisation en *événements d'accès*, pré-agrégation. Le niveau disponible dépend du moteur et de son édition : [08-CAPACITES-PAR-MOTEUR.md](08-CAPACITES-PAR-MOTEUR.md).
3. **Prevention** (phase 2) : proxy ou hooks pour bloquer certaines opérations.

**Discovery nourrit Audit** : les emplacements classés sensibles par Discovery servent à pondérer les accès observés par Audit. Un gros volume lu sur une table sans donnée sensible n'a pas le même poids qu'un gros volume lu sur `clients`.

## Détection d'exfiltration (Audit)
La détection d'un export combine trois signaux, du plus simple au plus robuste :

| Signal | Exemple | Robustesse |
|--------|---------|------------|
| **Signature** | `application_name = 'pg_dump'`, `appName: mongodump`, motif `SELECT /*!40001 SQL_NO_CACHE */` de mysqldump | Faible (falsifiable), mais utile et peu coûteuse |
| **Forme** | `COPY … TO`, lecture séquentielle de toutes les tables d'un schéma, recherche LDAP sous-arbre `(objectClass=*)` depuis la racine | Moyenne |
| **Volume × sensibilité** | lignes retournées sur des emplacements classés sensibles, au-dessus d'une ligne de base par compte | Élevée |

Le score d'un événement = f(signaux, sensibilité de l'emplacement, écart à la ligne de base). Les politiques transforment les scores en incidents.

## Communication console ↔ agents
Spécification détaillée : [09-PROTOCOLE-AGENT.md](09-PROTOCOLE-AGENT.md).

- **Transport** : HTTPS (TLS 1.3), JSON versionné, contrat OpenAPI dans `shared/protocol/`
- **Réactivité** : *long-poll* sur `GET /jobs` (requête tenue jusqu'à 25 s), ce qui donne une réactivité quasi temps réel sans WebSocket ni gRPC
- **Authentification** : jeton d'enrôlement à usage unique → identifiant d'agent + secret long, stocké haché côté console, rotation possible. mTLS en option (phase 2).
- **Résilience** : si la console est injoignable, l'agent met en file sur disque (spool borné) et renvoie à la reconnexion.

## Modes de déploiement de l'agent
| Mode | Quand |
|------|-------|
| Paquet `.deb` + service systemd sur l'hôte de la base | Bases installées « à l'ancienne », accès aux fichiers de logs natifs |
| Conteneur dans le même réseau Docker que la base | Bases conteneurisées ; les logs sont montés en lecture seule |
