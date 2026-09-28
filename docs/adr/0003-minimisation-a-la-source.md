# ADR-0003 : Aucune valeur sensible brute ne quitte l'agent

- **Statut** : Accepté
- **Date** : 2026-09-28

## Contexte
Si la console stocke les données sensibles qu'elle détecte, elle devient la cible la plus rentable du SI. Le cadrage initial prévoyait un chiffrement AES-GCM des payloads en plus de TLS, mais la clé étant sur la console, cela ne protège pas contre sa compromission.

## Décision
- L'agent n'envoie que : emplacement, classifieur, confiance, volumétrie, **échantillons masqués**, **empreintes HMAC-SHA256** calculées avec une clé locale à l'agent qui ne le quitte jamais.
- Les identifiants des bases restent sur l'hôte de l'agent.
- Le schéma du protocole interdit les champs additionnels (`additionalProperties: false`) ; la console rejette les lots non conformes.
- On retire le chiffrement AES-GCM applicatif des payloads. TLS 1.3 est obligatoire. Les champs sensibles sont chiffrés au repos côté console.

## Conséquences
- La console ne peut pas afficher la valeur complète d'un finding. C'est voulu. L'utilisateur qui veut voir la donnée va la consulter dans la base, avec ses propres droits.
- Corrélation entre cibles d'un **même agent** possible via l'empreinte. Entre agents différents, elle ne l'est pas (clés différentes). Une clé partagée optionnelle pourra être étudiée plus tard.
- Test automatisé obligatoire : seed de fausses PII connues → vérifier qu'aucune n'apparaît en clair dans la base de la console.

## Alternatives écartées
- Stocker les échantillons en clair, chiffrés avec une clé console : même risque en cas de compromission.
