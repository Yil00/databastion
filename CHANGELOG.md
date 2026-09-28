# Changelog

Toutes les évolutions notables de DataBastion sont consignées ici.

Ce fichier est **généré automatiquement** à chaque release à partir des messages de commit ([Conventional Commits](https://www.conventionalcommits.org/)), voir [RELEASE.md](RELEASE.md). Ne pas l'éditer à la main, sauf pour la section « Non publié ».
Le projet suit le [versionnage sémantique](https://semver.org/lang/fr/).

## Non publié

### 📝 Documentation
- Cadrage du MVP : vision, architecture, stack, périmètre, sécurité
- Décisions d'architecture ADR-0001 à ADR-0006
- Matrice des capacités d'audit par moteur
- Brouillon du protocole agent ↔ console v1
- Roadmap du MVP en phases 0 à 7
- Licence Apache 2.0, politique de marque, guides de contribution et de release

### 👷 CI
- CI (documentation, gitleaks, console, agent, protocole), vérification des titres de PR et du DCO
- Release automatisée avec release-it, images multi-arch signées avec cosign sur GHCR
