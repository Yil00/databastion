# Politique de sécurité

## Signaler une vulnérabilité
**N'ouvrez pas d'issue publique.** Utilisez le signalement privé de GitHub : onglet **Security** → **Report a vulnerability**.

Merci d'inclure : la version ou le commit concerné, le composant (console / agent / connecteur), les étapes de reproduction et l'impact estimé.

## Engagement
- Accusé de réception sous 72 h
- Évaluation initiale sous 7 jours
- Correctif et avis de sécurité coordonnés avec la personne qui a signalé le problème

## Versions supportées
Le projet est en pré-alpha : seule la branche `main` reçoit des correctifs.

## Périmètre particulièrement sensible
- Toute fuite de valeur sensible brute hors de l'agent
- Tout moyen pour la console, ou un tiers, d'initier une connexion vers un agent
- Contournement de l'authentification agent ou console
- Élévation de privilèges de l'agent sur les bases surveillées
