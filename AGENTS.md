# AGENTS.md – règles pour les agents de code

Ce fichier s'adresse à tout agent de code (Claude Code, Codex, Cursor…) et aux humains qui les pilotent. Le contexte métier est dans [CONTEXT.md](CONTEXT.md).

## Avant chaque tâche
1. Lire [CONTEXT.md](CONTEXT.md), en particulier les **invariants I1 à I7**.
2. Repérer la tâche dans [docs/ROADMAP.md](docs/ROADMAP.md) (identifiant `Px-Y`) et la passer en `[~]`.
3. Lire les ADR liés. **Ne jamais contourner un ADR accepté** : s'il bloque, s'arrêter et proposer un nouvel ADR ([docs/adr/template.md](docs/adr/template.md)).

## Langues
- Documentation : **français**
- Code, identifiants, commentaires, messages de commit, noms de branches : **anglais**

## Arborescence et propriétaires
| Chemin | Contenu | Propriétaire principal |
|--------|---------|------------------------|
| `console/` | Next.js (web + worker), Drizzle, pg-boss | `console-engineer` |
| `agent/` | Workspace Cargo (core, classifiers, connecteurs) | `agent-engineer` |
| `shared/protocol/` | OpenAPI + JSON Schemas + fixtures | `agent-engineer`, revue `security-reviewer` **obligatoire** |
| `dev/` | Environnement de dev, bases seedées, vérité terrain | `agent-engineer` |
| `deploy/` | Compose, plus tard Helm | `console-engineer` |
| `docs/`, `*.md` racine | Documentation, ROADMAP, ADR | `docs-keeper` |

Un agent ne modifie **pas** les fichiers d'un autre propriétaire, sauf si la tâche le demande explicitement. S'il en a besoin, il le signale dans son compte rendu.

## Conventions – Console (`console/`)
- TypeScript `strict`, pas de `any` non justifié
- Next.js App Router ; le code serveur de l'API agent est dans `console/src/app/api/agent/v1/`
- Toute entrée de l'API agent est validée contre le schéma généré depuis `shared/protocol/` (rejet si champ inconnu)
- Migrations Drizzle versionnées ; jamais de modification manuelle du schéma
- pnpm ; commandes (à compléter dès qu'elles existent) : `pnpm lint`, `pnpm test`, `pnpm build`

## Conventions – Agent (`agent/`)
- Rust stable, `#![forbid(unsafe_code)]` dans toutes les crates
- `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test` doivent passer
- rustls uniquement (pas d'OpenSSL)
- Chaque requête vers une base cible : `statement_timeout` / équivalent, et bornes sur l'échantillonnage
- Toute donnée qui sort d'un connecteur passe par `classifiers::masking` **avant** d'atteindre l'uplink. Pas d'accès direct à l'uplink depuis un connecteur.
- Pas de `println!` : `tracing` avec des logs JSON structurés ; **jamais** de valeur échantillonnée dans les logs

## Protocole (`shared/protocol/`)
- Seule source de vérité agent ↔ console
- Changement compatible (ajout de champ optionnel) : PR normale + revue `security-reviewer`
- Changement incompatible : nouvel ADR + nouvelle version (`/api/agent/v2`)
- Les types TS et Rust sont **générés**, jamais édités à la main

## Commandes utiles (racine)
- `python3 scripts/check-md-links.py` : liens internes de la documentation
- `node scripts/bump-version.mjs <X.Y.Z>` : aligne les versions (normalement appelé par la CI de release, pas à la main)
- `pre-commit install --hook-type pre-commit --hook-type commit-msg` : hooks gitleaks + format des commits

## Tests exigés
- Classifieurs : cas positifs / négatifs + tests de propriété sur le masquage
- Connecteurs : tests d'intégration contre `dev/` (conteneurs)
- Console : tests de l'API agent avec les fixtures de `shared/protocol/fixtures/`
- **Test d'invariant I2** (dès la phase 2) : aucune valeur de `dev/ground-truth.json` en clair dans la base de la console

## Travail multi-agents
- **Une tâche = une branche = un worktree** (`git worktree`), créée depuis `dev`, nommée `<type>/<id-roadmap>-<slug>` (ex. `feat/p2-b-pg-discovery`). Les PR visent `dev`.
- Des tâches en parallèle ne touchent pas les mêmes dossiers. Le découpage de la ROADMAP en chantiers est pensé pour ça.
- Point de synchronisation unique : `shared/protocol/`. Le contrat est figé **avant** que console et agent l'implémentent en parallèle.
- **Compte rendu de fin de tâche** (dans la description de PR) :
  1. Ce qui a été fait (tâches ROADMAP cochées)
  2. Ce qui n'a pas été fait, et pourquoi
  3. Décisions prises qui mériteraient un ADR
  4. Fichiers d'autres propriétaires qu'il faudrait modifier
- Le `docs-keeper` met à jour `docs/ROADMAP.md` et `CONTEXT.md` (phase courante) après chaque merge.

## Définition de « terminé »
- [ ] Lint + tests verts pour le composant touché
- [ ] Invariants I1–I7 respectés (le dire explicitement dans la PR si la tâche touche au réseau, aux données ou au protocole)
- [ ] Documentation mise à jour si le comportement visible change
- [ ] ROADMAP mise à jour

## Git
- Branches, tags et releases : [RELEASE.md](RELEASE.md). Ne jamais committer sur `main` ni sur `dev` directement ; ne jamais poser de tag de release.
- Conventional Commits : `feat(agent): …`, `fix(console): …`, `docs(adr): …`
- Commits signés DCO (`git commit -s`)
- **Aucune attribution d'outil IA** dans les commits ou les PR : pas de trailer `Co-Authored-By` d'un assistant, pas de mention « Generated with … ». Seule l'identité git du mainteneur ou du contributeur apparaît.
- Ne pas éditer `CHANGELOG.md` à la main (généré à la release), sauf la section « Non publié »
- Ne jamais committer de secret, de dump de base, ni de fichier de `dev/.state/`
- Ne jamais pousser ni ouvrir de PR sans demande explicite du mainteneur
