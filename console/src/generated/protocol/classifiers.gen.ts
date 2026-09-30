// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/classifiers.json.
// Regenerate with `pnpm protocol:generate` (from console/).

/** Valid classifier ids per classifier set version (contract classifier registry). */
export const CLASSIFIER_REGISTRY = {
  "2026.09.1": [
    "pii.birth_date",
    "pii.card_number",
    "pii.email",
    "pii.iban",
    "pii.nir",
    "pii.person_name",
    "pii.phone",
    "pii.postal_address",
    "secret.aws_key",
    "secret.password_hash"
  ]
} as const;

/** A registered `classifiers_version`. */
export type KnownClassifiersVersion = keyof typeof CLASSIFIER_REGISTRY;
