# Processus de release – DataBastion

Inspiré du fonctionnement de [Portabase](https://github.com/Portabase/portabase) : branches `main` / `dev`, Conventional Commits, changelog généré par `release-it`, release déclenchée par le merge de `dev` vers `main`. Adapté à un monorepo qui livre **deux artefacts** : la console et l'agent.

## 1. Branches

| Branche | Rôle | Protégée | Part de | Merge vers |
|---------|------|----------|---------|------------|
| `main` | Code publié. Chaque merge = une release | Oui : PR obligatoire, check `CI result` vert, pas de push direct ni de force-push (seul l'admin contourne, pour le commit de release) | — | — |
| `dev` | Intégration de la prochaine version | Oui : PR obligatoire, check `CI result` vert, pas de force-push | `main` | `main` (PR de release) |
| `feat/<id>-<slug>` | Nouvelle fonctionnalité | Non | `dev` | `dev` |
| `fix/<id>-<slug>` | Correction | Non | `dev` | `dev` |
| `docs/…`, `chore/…`, `ci/…`, `refactor/…`, `perf/…`, `test/…` | Selon le type Conventional Commits | Non | `dev` | `dev` |
| `hotfix/<slug>` | Correctif urgent sur la version publiée | Non | `main` | `main`, puis report dans `dev` |
| `release/<X.Y>` | Maintenance d'une ancienne version mineure (**à partir de 1.0 seulement**) | Oui | tag `X.Y.0` | — |

- `<id>` = identifiant ROADMAP en minuscules quand il existe : `feat/p2-b-pg-discovery`.
- Les branches de travail sont supprimées après merge.
- Stratégie de merge : **squash** vers `dev` (un commit Conventional par PR, le titre de PR devient le message) ; **merge commit** de `dev` vers `main` (garde l'historique de la release).

## 2. Versions

### Une version unique pour tout le dépôt
La console et l'agent partagent **le même numéro de version** et sortent ensemble. Un utilisateur sait ainsi que la console `0.3.1` et l'agent `0.3.1` vont ensemble.

La **version du protocole** (`/api/agent/v1`) est indépendante : elle ne change que sur un changement incompatible, avec un ADR (voir [AGENTS.md](AGENTS.md#protocole-sharedprotocol)).

### SemVer
`MAJEUR.MINEUR.CORRECTIF`, calculé automatiquement à partir des commits :

| Commits depuis la dernière release | Avant 1.0 | À partir de 1.0 |
|------------------------------------|-----------|-----------------|
| `fix:`, `perf:` | correctif | correctif |
| `feat:` | mineur | mineur |
| `feat!:` ou `BREAKING CHANGE:` | **mineur** | majeur |

Avant la 1.0, un changement cassant incrémente le mineur (`0.3.x` → `0.4.0`) et doit être signalé en tête des notes de version.

### Compatibilité
- Une console `X.Y` accepte les agents `X.Y` et `X.(Y-1)`.
- Mettre à jour la **console d'abord**, puis les agents.

## 3. Tags

| Type | Format | Exemple | Posé par | Effet |
|------|--------|---------|----------|-------|
| Release | `X.Y.Z` | `0.1.0` | CI, au merge `dev` → `main` | Release GitHub + images `X.Y.Z`, `X.Y`, `latest` + `.deb` |
| Pré-release | `X.Y.Z-alpha.N`, `-beta.N`, `-rc.N` | `0.1.0-rc.2` | Mainteneur, sur `dev` | Pré-release GitHub + images `X.Y.Z-rc.N` et `next` (**jamais `latest`**) |

Règles :
- Pas de préfixe `v` (comme Portabase) : le tag git est identique au tag Docker.
- Pré-release avec un **point** (`-rc.2`, pas `-rc2`) : l'ordre SemVer reste correct après `-rc.9`.
- Tags **annotés**. Les tags de pré-release posés à la main sont en plus signés (`git tag -s`). Les tags de release sont posés par la CI ; leur intégrité est garantie par la signature cosign des images.
- Un tag publié n'est **jamais** déplacé ni supprimé. En cas d'erreur : nouvelle version corrective.
- Étapes du MVP : `0.1.0-alpha.N` (fin de phase 2) → `0.1.0-beta.N` (phases 3 à 6) → `0.1.0-rc.N` (phase 7) → `0.1.0`.

## 4. Artefacts publiés

| Artefact | Nom | Architectures |
|----------|-----|---------------|
| Image console (web + worker) | `ghcr.io/yil00/databastion-console:<tag>` | amd64, arm64 |
| Image agent | `ghcr.io/yil00/databastion-agent:<tag>` | amd64, arm64 |
| Paquet agent (phase 7) | `databastion-agent_<X.Y.Z>_<arch>.deb` | amd64, arm64 |
| Sommes de contrôle (phase 7) | `SHA256SUMS` + signature cosign | — |

Les images sont publiées sur GHCR, construites nativement sur runners amd64 et arm64, signées avec cosign en mode *keyless* (OIDC GitHub), avec SBOM et attestation de provenance. Une image n'est construite que si son `Dockerfile` existe.

Vérifier une image :
```bash
cosign verify ghcr.io/yil00/databastion-console:0.1.0 \
  --certificate-identity-regexp '^https://github.com/Yil00/databastion/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 5. Déroulé d'une release

### Release normale
1. Sur `dev`, la CI est verte et la ROADMAP est à jour.
2. (Optionnel) Poser un tag `X.Y.Z-rc.N` sur `dev` pour tester les images candidates.
3. Ouvrir une PR `dev` → `main` intitulée `release: X.Y.Z`.
4. Au merge, la CI ([release.yml](.github/workflows/release.yml), `release-it`, config [.release-it.json](.release-it.json)) :
   - calcule la version depuis les commits et le dernier tag,
   - met à jour les numéros de version avec [scripts/bump-version.mjs](scripts/bump-version.mjs) (`package.json`, `console/package.json`, `agent/Cargo.toml` + `Cargo.lock`, plus tard le chart Helm),
   - génère la section de [CHANGELOG.md](CHANGELOG.md),
   - commite `chore(release): X.Y.Z` sous l'identité noreply du propriétaire, pose le tag `X.Y.Z`,
   - crée une **release GitHub en brouillon**,
   - construit et publie les images ([publish.yml](.github/workflows/publish.yml)).
5. Le mainteneur relit le brouillon, ajoute les notes de mise à niveau si besoin, et **publie** la release.
6. Merger `main` dans `dev` pour y récupérer le commit de version.

Pour merger dans `main` sans publier (CI, documentation…) : ajouter `[skip-release]` au titre de la PR, comme sur Portabase. **À faire tant qu'il n'y a pas de code** : sans commit `feat`/`fix`, release-it publierait une version corrective vide.

### Pré-release
```bash
git switch dev && git pull
git tag -s 0.1.0-alpha.1 -m "DataBastion 0.1.0-alpha.1"
git push origin 0.1.0-alpha.1
```
Le push du tag déclenche [publish.yml](.github/workflows/publish.yml) (images `0.1.0-alpha.1` et `next`). Créer ensuite la pré-release GitHub à la main (`gh release create 0.1.0-alpha.1 --prerelease --generate-notes`).

### Hotfix
1. `hotfix/<slug>` depuis `main`, PR vers `main` avec un commit `fix:`.
2. Le merge publie `X.Y.(Z+1)`.
3. Merger `main` dans `dev`.

### Correctif de sécurité
Suivre [SECURITY.md](SECURITY.md) : correctif préparé en privé (GitHub Security Advisory), publié en hotfix, avis de sécurité publié en même temps que la release.

## 6. Automatisation (GitHub Actions)

| Workflow | Déclencheur | Rôle |
|----------|-------------|------|
| [ci.yml](.github/workflows/ci.yml) | push et PR sur `main` / `dev` | Liens de la doc, gitleaks, console, agent, protocole (chaque job ne tourne que si son composant existe) ; check agrégé `CI result` |
| [pr-checks.yml](.github/workflows/pr-checks.yml) | PR | Titre Conventional Commits, signature DCO de chaque commit |
| [release.yml](.github/workflows/release.yml) | PR mergée dans `main` | release-it + appel de `publish.yml` |
| [publish.yml](.github/workflows/publish.yml) | appel de `release.yml`, ou tag `X.Y.Z-*` | Images multi-arch GHCR signées |
| [dependabot.yml](.github/dependabot.yml) | hebdomadaire | Mises à jour des actions et de l'outillage, PR vers `dev` |

Les actions tierces sont épinglées par SHA de commit (Dependabot les met à jour).

### Configuration du dépôt (une fois)
- **Secret `RELEASE_TOKEN`** (obligatoire pour `release.yml`) : jeton *fine-grained* du propriétaire, limité à ce dépôt, permission **Contents: read and write**. Il permet au commit de release de passer la protection de `main` (contournement réservé à l'admin). À créer dans *Settings → Developer settings → Fine-grained tokens*, puis à ajouter dans *Settings → Secrets and variables → Actions* du dépôt.
- Variables optionnelles `RELEASE_GIT_NAME` / `RELEASE_GIT_EMAIL` : identité du commit de release (par défaut, l'adresse noreply du propriétaire).
- Tant qu'il n'y a qu'un mainteneur, aucune approbation n'est exigée sur les PR (on ne peut pas approuver sa propre PR). Passer à 1 approbation dès qu'un deuxième mainteneur arrive.

## 7. Checklist avant publication
- [ ] CI verte sur tous les composants
- [ ] Test d'invariant I2 vert (aucune donnée brute dans la base console)
- [ ] Notes de version relues : changements cassants en tête, étapes de mise à niveau
- [ ] Matrice [docs/08-CAPACITES-PAR-MOTEUR.md](docs/08-CAPACITES-PAR-MOTEUR.md) à jour
- [ ] Compatibilité console N / agent N-1 testée
- [ ] Images signées, SBOM et `SHA256SUMS` publiés
