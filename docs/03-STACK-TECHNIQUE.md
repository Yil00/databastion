# Stack technique – MVP DataBastion

## Console (Control Plane)
| Composant | Technologie | Commentaire |
|-----------|-------------|-------------|
| Frontend + Backend | Next.js (App Router, TypeScript strict) | Inspiré de Portabase |
| UI | Tailwind CSS + shadcn/ui | |
| Base interne | PostgreSQL 17 | Aussi utilisée comme file de jobs |
| ORM / migrations | **Drizzle** | Proche du SQL, migrations versionnées en SQL |
| Jobs / worker | **pg-boss** | File de jobs sur PostgreSQL, pas de Redis |
| Authentification | Locale + OIDC | SAML / SCIM → Enterprise (voir [EDITIONS.md](EDITIONS.md)) |
| Gestionnaire de paquets | pnpm | |
| Packaging | Image Docker unique (`web` et `worker` = deux commandes) | |

## Agent (Data Plane)
| Composant | Technologie | Commentaire |
|-----------|-------------|-------------|
| Langage | **Rust** (stable) | Léger, sûr, binaire statique |
| Runtime async | tokio | |
| PostgreSQL + MySQL/MariaDB | sqlx | |
| MongoDB | crate officielle `mongodb` | |
| OpenLDAP | `ldap3` | |
| HTTP client | reqwest + rustls | Pas d'OpenSSL → binaire portable |
| Packaging | Image Docker distroless + `.deb` | |
| Architectures | x86_64 + arm64 | |

Un seul binaire, connecteurs activés par *features* Cargo ([ADR-0002](adr/0002-agent-unique-connecteurs.md)).

## Protocole & contrat partagé
- **Source de vérité** : `shared/protocol/openapi.yaml` (OpenAPI 3.1 + JSON Schema)
- Types générés : TypeScript (console) et Rust (agent). **Aucun type de protocole écrit à la main.**
- Versionnement : préfixe d'URL `/api/agent/v1`, en-tête `X-DataBastion-Protocol`

## Sécurité du transport
- TLS 1.3 obligatoire (terminé par le reverse-proxy devant la console)
- Plus de chiffrement AES-GCM applicatif des payloads : c'est redondant avec TLS tant que la clé est sur la console. La vraie protection est la minimisation à la source ([ADR-0003](adr/0003-minimisation-a-la-source.md)).
- Chiffrement **au repos** des champs sensibles de la console (échantillons masqués, secrets de webhooks) avec une clé fournie par secret Docker

## Observabilité
- Console : endpoint `/metrics` au format Prometheus (réseau interne, authentifié), qui agrège les métriques des agents reçues via heartbeat
- Agent : **aucun port exposé par défaut**. Option `metrics.local_listen: 127.0.0.1:9464` désactivée par défaut, pour du debug local.
- Logs : JSON structuré sur stdout (console et agent)

## Déploiement
- **Docker Compose** → MVP et petites installations ([deploy/docker-compose.example.yml](../deploy/docker-compose.example.yml))
- **Helm** → phase 2

## Structure du dépôt (cible)
```
databastion/
├── console/            # Next.js (web + worker)
├── agent/              # workspace Cargo
│   ├── crates/core/
│   ├── crates/classifiers/
│   ├── crates/connector-postgres/
│   ├── crates/connector-mysql/
│   ├── crates/connector-mongodb/
│   └── crates/connector-openldap/
├── shared/protocol/    # openapi.yaml + JSON Schemas + fixtures
├── deploy/             # docker-compose, plus tard helm/
├── dev/                # environnement de dev : bases seedées avec de fausses PII
└── docs/
```
