# Generated protocol artifacts

Generated from `shared/protocol/openapi.yaml` and `shared/protocol/classifiers.json` (invariant I6) by `pnpm protocol:generate`
(`scripts/protocol/generate.ts`). **Never edit these files by hand.**

| File | Content |
|------|---------|
| `types.gen.ts` | TypeScript types (`paths`, `components`, `operations`), from `openapi-typescript` |
| `schemas.gen.json` | JSON Schema 2020-12 bundle: `components.schemas` moved to `$defs`, refs rewritten, exactly as `shared/protocol/scripts/contract-ajv.mjs` does |
| `classifiers.gen.ts` | `CLASSIFIER_REGISTRY` const: valid classifier ids per `classifiers_version`, from `shared/protocol/classifiers.json` |

- All files are committed. The test `src/lib/protocol/generated.test.ts` regenerates them in
  memory and fails if they differ: run `pnpm protocol:generate` after any contract change.
- The runtime validator is `src/lib/protocol/validate.ts`; it imports `schemas.gen.json`, so
  the running console never reads YAML nor any file outside its build.
- This directory is excluded from ESLint.
