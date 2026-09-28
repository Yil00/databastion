# ADR-0001 : Transport HTTPS outbound avec long-poll

- **Statut** : Accepté
- **Date** : 2026-09-28

## Contexte
Les bases sont dans des zones réseau sensibles. Ouvrir un port entrant vers elles est inacceptable pour la plupart des équipes sécurité. Les agents doivent aussi traverser des proxys d'entreprise.

## Décision
- L'agent est toujours client. Tout passe par HTTPS (TLS 1.3) sur le port 443 de la console.
- La réactivité est obtenue par **long-poll** sur `GET /api/agent/v1/jobs` (25 s).
- JSON versionné, contrat OpenAPI dans `shared/protocol/`.

## Conséquences
- Fonctionne derrière n'importe quel proxy HTTP(S) et reverse-proxy standard.
- Latence de commande console → agent < 1 s en pratique, sans connexion persistante bidirectionnelle.
- Une requête HTTP ouverte par agent en permanence : dimensionner la console en conséquence (quelques centaines d'agents au MVP).

## Alternatives écartées
- **gRPC bidirectionnel** : plus efficace, mais passe mal certains proxys et ajoute de la complexité (HTTP/2 de bout en bout). À réévaluer en phase 2.
- **WebSocket** : gain marginal par rapport au long-poll, gestion de reconnexion plus complexe.
- **Polling simple toutes les 5-30 s** : plus de latence pour autant de requêtes.
