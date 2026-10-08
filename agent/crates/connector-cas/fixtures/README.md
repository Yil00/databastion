# connector-cas fixtures

- `cas-8.0.2-oauth-oidc-audit.jsonl`: real JSON audit records written by the CAS 8.0.2 dev service
  (`make dev-cas`, [dev/README.md](../../../../dev/README.md)) for the OAuth 2.0 / OIDC flows:
  authorization code (with consent bypassed), `refresh_token`, `client_credentials` on
  `/cas/oidc/token` and `/cas/oauth2.0/accessToken`, `password`, and implicit (`id_token token`).
  Captured on 2026-10-08 with a local-only service definition (`scratch-m2m`,
  `https://m2m.example.org/cb`, every grant enabled), not part of the dev registry. Kept as CAS wrote
  them except: `SERVICE_ACCESS_ENFORCEMENT_TRIGGERED` and `AUTHENTICATION_EVENT_TRIGGERED` records
  and all but one `TICKET_GRANTING_TICKET_CREATED` record removed; every ticket and token id (masked
  by CAS) replaced by `<PREFIX>-1-****************FAKEredacted-cas01`, every `id_token` by
  `eyJFAKE.REDACTED.FAKE`, the token request's `Authorization` header (CAS logs the client id and
  secret there in clear) by `Basic REDACTED-FAKE`, the `TGC` and `JSESSIONID` cookies (the
  encrypted ticket-granting cookie and the session id, logged in clear) by `REDACTED`, and `txn` by a fixed UUID. The user is a fake dev
  user. Used by `audit::events` tests.
- `registry/`: fake service definitions in pairs, each in JSON and in the YAML form CAS 8.0.2
  writes (`--- !<class>`, Jackson class hints as verbatim tags; the sample of the CAS 8.0.2 YAML
  service registry documentation, extended): an OIDC relying party with a clear `clientSecret`,
  credential-named keys and a URL with credentials (`HR-Portal-10000003`), a CAS service with flow
  collections (`Wiki-10000004.yaml`) and a SAML service provider with a block scalar
  (`SP-10000005`). Every value is fake. Used by the `parse::definition` and `discover` tests that
  check a YAML definition gives the same findings as its JSON equivalent.
