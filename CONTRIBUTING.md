# Contribuer à DataBastion

Merci de votre intérêt ! Le projet est en phase de conception : les discussions d'architecture sont aussi utiles que le code.

## Avant de commencer
1. Lire [CONTEXT.md](CONTEXT.md) et les [décisions d'architecture](docs/adr/README.md).
2. Pour toute évolution non triviale, ouvrir d'abord une issue pour en discuter.
3. Une modification qui contredit un ADR accepté passe par un **nouvel ADR**, pas par une PR de code.

## Invariants à respecter
Toute PR qui les enfreint sera refusée :
- Les agents n'ouvrent **aucun** port entrant.
- **Aucune valeur sensible brute** ne quitte l'agent (masquage + HMAC obligatoires).
- Les identifiants des bases ne sont jamais envoyés à la console.
- L'agent n'effectue que des opérations en **lecture**.

## Workflow
- **Les PR visent la branche `dev`**, jamais `main` directement (`main` = code publié).
- Branche depuis `dev`, nommée selon le type : `feat/…`, `fix/…`, `docs/…`, `chore/…`, `ci/…`, `refactor/…`, `perf/…`, `test/…`
- Commits et titres de PR au format [Conventional Commits](https://www.conventionalcommits.org/) : `feat(agent): …`, `fix(console): …`. Scopes : `console`, `agent`, `protocol`, `classifiers`, `postgres`, `mysql`, `mongodb`, `openldap`, `deploy`, `docs`
- Changement cassant : `feat!:` ou pied de commit `BREAKING CHANGE: …`
- Tests et lint verts en local ; hooks conseillés : `pre-commit install --hook-type pre-commit --hook-type commit-msg` (gitleaks + format des commits)
- Une PR = un sujet ; elle est squashée au merge

Règles complètes des branches, des tags et des releases : [RELEASE.md](RELEASE.md).

## Developer Certificate of Origin (DCO)
Chaque commit doit être signé, ce qui atteste que vous avez le droit de soumettre ce code sous licence Apache 2.0 ([developercertificate.org](https://developercertificate.org/)) :

```bash
git commit -s -m "feat(agent): add IBAN classifier"
```

Cela ajoute la ligne `Signed-off-by: Votre Nom <email>`. Aucun CLA n'est demandé.

## Licence des contributions
Toute contribution est publiée sous [licence Apache 2.0](LICENSE) (section 5 de la licence).
