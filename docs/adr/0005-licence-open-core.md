# ADR-0005 : Apache 2.0, modèle open-core

- **Statut** : Accepté
- **Date** : 2026-09-28

## Contexte
Le projet vise l'adoption en entreprise, avec à terme une édition commerciale, sur le modèle de Kestra.

## Décision
- **Community Edition** : dépôt public, licence **Apache 2.0**.
- **Enterprise Edition** : **dépôt privé séparé**, licence commerciale. Elle consomme la Community comme dépendance ou comme module d'extension. Aucun code propriétaire dans le dépôt public, pas de dossier `ee/` sous une autre licence.
- Contributions externes sous **DCO** (`Signed-off-by`), sans CLA.
- Le **nom et le logo** ne sont pas couverts par la licence (Apache 2.0 §6) : voir `TRADEMARKS.md`.
- Répartition des fonctionnalités : `docs/EDITIONS.md`.

## Conséquences
- Apache 2.0 autorise l'intégration des contributions externes dans l'EE ; le DCO suffit à tracer leur origine.
- Le code est prévu pour être étendu : points d'extension (authentification, stockage des événements, actions de politique) pensés dès le MVP, sans être implémentés côté EE.
- Un tiers peut proposer un DataBastion hébergé. La protection repose sur la marque et sur la valeur de l'EE, pas sur la licence.

## Alternatives écartées
- **AGPL-3.0** : freine l'adoption en entreprise.
- **BSL 1.1 / SSPL** : pas open-source au sens OSI, mauvais signal pour un outil de sécurité qu'on veut pouvoir auditer.
- **MIT** : pas de clause explicite sur les brevets.
