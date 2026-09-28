# ADR-0002 : Un agent unique avec des connecteurs par moteur

- **Statut** : Accepté
- **Date** : 2026-09-28

## Contexte
Le cadrage initial prévoyait un agent par type de base (SQL, MongoDB, OpenLDAP). Or l'enrôlement, l'uplink, le spool, les classifieurs et le masquage sont identiques pour tous. Un même hôte héberge souvent plusieurs moteurs.

## Décision
Un seul binaire Rust `databastion-agent`, organisé en workspace Cargo :
`core`, `classifiers` (masquage compris), `connector-postgres`, `connector-mysql`, `connector-mongodb`, `connector-openldap`.
Les connecteurs sont activés par *features* Cargo. L'image officielle les inclut tous ; on peut compiler un binaire minimal.

Chaque connecteur implémente un trait commun (esquisse) :
```rust
trait Connector {
    fn engine(&self) -> Engine;
    async fn check(&self) -> TargetHealth;          // joignable ? niveau d'audit ?
    async fn discover(&self, job: &ScanJob, sink: &FindingSink) -> Result<()>;
    async fn audit_stream(&self, cfg: &AuditConfig, sink: &EventSink) -> Result<()>;
}
```

## Conséquences
- Code de sécurité critique (masquage, uplink) écrit **une seule fois**.
- Un agent par hôte, même s'il y a plusieurs moteurs.
- Les connecteurs peuvent être développés en parallèle par des agents différents : frontière claire = le trait.

## Alternatives écartées
- **Un binaire par moteur** : duplication, N enrôlements par hôte.
- **Plugins dynamiques (.so / WASM)** : prématuré pour le MVP.
