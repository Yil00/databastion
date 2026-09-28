# Architecture Decision Records

Chaque décision structurante est consignée ici. **Un agent (humain ou IA) ne remet pas en cause un ADR accepté dans le cadre d'une tâche** : il propose un nouvel ADR qui le remplace (`Statut : Remplacé par ADR-XXXX`).

| # | Décision | Statut |
|---|----------|--------|
| [0001](0001-transport-https-outbound.md) | Transport HTTPS outbound avec long-poll | Accepté |
| [0002](0002-agent-unique-connecteurs.md) | Un agent unique avec des connecteurs par moteur | Accepté |
| [0003](0003-minimisation-a-la-source.md) | Aucune valeur sensible brute ne quitte l'agent | Accepté |
| [0004](0004-observabilite-via-console.md) | Métriques des agents remontées via la console | Accepté |
| [0005](0005-licence-open-core.md) | Apache 2.0, modèle open-core | Accepté |
| [0006](0006-decouverte-des-cibles.md) | Cibles déclarées + détection locale, pas de scan réseau | Accepté |

Modèle : copier [template.md](template.md).
