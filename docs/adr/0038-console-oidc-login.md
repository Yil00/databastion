# ADR-0038: Console login with OpenID Connect

- **Status**: Proposed
- **Date**: 2026-10-04
- **Context references**: ROADMAP P8-A; [EDITIONS.md](../EDITIONS.md) (OIDC is Community, allocation rule 1); [05-security.md](../05-security.md#authentication-rate-limits); [ADR-0024](0024-shared-rate-limits.md) (shared rate limits)

## Context
Console users are local only today. The `users` table holds a lowercased username (`^[a-z0-9][a-z0-9._-]{0,63}$`), an argon2id hash (`password_hash`, not null) and one role of the `user_role` enum, `admin` or `analyst` (`console/src/db/schema.ts`). The only way to create a user is `pnpm admin:bootstrap`, which creates the first administrator and refuses to run once a user exists. Sessions are cookie sessions (`console/src/server/auth/session.ts`): 256 random bits, SHA-256 stored, `HttpOnly`, `SameSite=Strict`, `__Host-` prefixed and `Secure` in production, 12 h absolute lifetime, 2 h idle timeout, HMAC-derived CSRF token. Logins are rate limited per IP, per (username, IP) and per username, with device cookies, in counters shared through PostgreSQL ([ADR-0024](0024-shared-rate-limits.md)). Every login and logout is written to the console audit log (`user.login`, `user.logout`).

[EDITIONS.md](../EDITIONS.md) puts OIDC in the Community edition (baseline security), and SAML, SCIM, multi-tenancy and fine-grained RBAC in the Enterprise edition. The maintainer asked for an OIDC login "inspired by what Grafana did", tested with Keycloak.

Grafana's Generic OAuth integration (`[auth.generic_oauth]`) is the reference most operators know. It maps an identity provider's claims to Grafana attributes with JMESPath expressions (`login_attribute_path`, `email_attribute_path`, `name_attribute_path`, `groups_attribute_path`, `role_attribute_path`), can refuse a login whose role expression yields nothing (`role_attribute_strict`), filters by `allowed_groups` and `allowed_domains`, controls user creation (`allow_sign_up`), can redirect straight to the provider (`auto_login`), refreshes tokens (`use_refresh_token`), uses PKCE (`use_pkce`), logs out at the provider (`signout_redirect_url`) and can leave roles to the Grafana UI (`skip_org_role_sync`). Two Grafana lessons matter here:
- Grafana's Generic OAuth takes explicit `auth_url`, `token_url` and `api_url` settings. OIDC discovery from the issuer removes three settings that operators get wrong.
- Grafana used to match an OAuth login to an existing user by e-mail. With providers where the e-mail claim is not unique or not verified, this allowed account takeover (CVE-2023-3128, Azure AD). Grafana then disabled e-mail lookup by default (`oauth_allow_insecure_email_lookup`).

DataBastion's console holds the map of where sensitive data lives, the incidents, and the right to start scans and change Audit settings. Its login must not be weaker than the local login it complements.

## Decision
1. **Protocol: OpenID Connect Authorization Code flow with PKCE (S256), confidential client.** Only `response_type=code`. The implicit and hybrid flows, and plain OAuth 2.0 without an `id_token`, are not supported. PKCE is always used, even though the client is confidential. The client authenticates at the token endpoint with `client_secret_basic` (default) or `client_secret_post`; `private_key_jwt` can come later as a compatible addition.
2. **Discovery from the issuer URL.** The console reads `<issuer>/.well-known/openid-configuration` at startup and at most every hour after, and requires its `issuer` to equal the configured one exactly. The issuer and every endpoint must be `https://`. A plain-HTTP issuer is accepted only on a loopback address and outside production, as for the SMTP rule ([ADR-0017](0017-alerting.md)). When the provider advertises `authorization_response_iss_parameter_supported`, the `iss` of the authorization response is checked too (RFC 9207). The configuration comes from the console's environment only, never from a user request, so discovery is not an SSRF vector.
3. **TLS to the provider is always verified.** There is no "skip verify" option. `DATABASTION_OIDC_CA_FILE` adds a private CA for the provider's endpoints only.
4. **`id_token` validation.** Signature checked with the provider's JWKS (cached; refetched on an unknown `kid`, at most once per minute); allowed algorithms from `DATABASTION_OIDC_ID_TOKEN_ALGS`, default `RS256,PS256,ES256`. `none` and the `HS*` algorithms are always refused. Then: `iss` equal to the issuer, `aud` containing the client id (and `azp` equal to it when `aud` has several values), `exp` in the future and `iat` not in the future, with 60 s clock skew, and `nonce` equal to the one sent. The userinfo endpoint is called only when `DATABASTION_OIDC_USE_USERINFO=1`; its `sub` must equal the `id_token`'s `sub`, and its claims are merged under those of the `id_token`.
5. **State, nonce and CSRF.** `GET /api/auth/oidc/start` creates a 256-bit `state`, a 256-bit `nonce` and the PKCE verifier, kept in an encrypted, `HttpOnly`, `Secure` (production), `SameSite=Lax` cookie bound to the console origin with a 10-minute lifetime, and single use. `Lax` is needed because the callback is a cross-site top-level navigation from the provider; the session cookie itself stays `SameSite=Strict`. The callback answers with a same-origin page that navigates to the console, not with a cross-site redirect chain, so the `Strict` session cookie is sent on the first page load. A callback without a matching, unexpired, unused state is refused and audit logged.
6. **Identity key: (`iss`, `sub`), never the e-mail.** OIDC identities live in a new table (`user_identities`: issuer, subject, user id, unique on (issuer, subject)). A login finds its user by (`iss`, `sub`) only. The e-mail, the login claim and the name are attributes, refreshed at each login. There is **no automatic linking** of an OIDC identity to an existing local user by e-mail or by username, verified or not: the e-mail claim is chosen or edited by the user at many providers, and the Grafana CVE above shows the outcome. Linking a local account to an OIDC identity is an explicit administrator action on a pending login (decision 8), audit logged.
7. **Claim mapping with JMESPath expressions**, as in Grafana, evaluated on the merged claims (decision 4):
   - `DATABASTION_OIDC_LOGIN_ATTRIBUTE_PATH` (default `preferred_username`), `DATABASTION_OIDC_EMAIL_ATTRIBUTE_PATH` (default `email`), `DATABASTION_OIDC_NAME_ATTRIBUTE_PATH` (default `name`), `DATABASTION_OIDC_GROUPS_ATTRIBUTE_PATH` (default unset);
   - `DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH`: an expression that must yield `admin` or `analyst` (e.g. `contains(groups[*], 'databastion-admins') && 'admin' || 'analyst'`). Any other result counts as no role.
   - `DATABASTION_OIDC_ROLE_ATTRIBUTE_STRICT=1`: a login whose expression yields no role is refused. Without it, such a login gets `analyst`, never `admin`.
   - The login claim is lowercased and must match the console's username pattern, otherwise the login is refused (no silent rewriting that could make two identities collide on one display name). Usernames are display attributes for OIDC users; uniqueness of OIDC users rests on (`iss`, `sub`). A login claim equal to an existing local username is refused, not merged.
   - Bounds: expressions at most 1 KiB, claims payload at most 64 KiB, groups at most 256 entries of at most 256 characters, evaluated with a JMESPath library under the console's license gate.
8. **Who may log in.**
   - `DATABASTION_OIDC_ALLOWED_GROUPS`: comma-separated; when set, at least one mapped group must match.
   - `DATABASTION_OIDC_ALLOWED_DOMAINS`: comma-separated; when set, the e-mail domain must match **and** `email_verified` must be `true`.
   - `DATABASTION_OIDC_ALLOW_SIGN_UP`: when on, an unknown (`iss`, `sub`) that passes the filters and the role mapping becomes a console user. When off, the attempt is refused and recorded as a **pending login** (issuer, subject, mapped login, e-mail, groups, time), shown to administrators, who can approve it (creating the user bound to that `sub`, with a role) or link it to an existing local user. Pending logins expire after 7 days and are bounded in number (1000, oldest dropped).
   - A user disabled in the console (`disabled_at`) cannot log in by any method.
9. **Role synchronization.** The mapped role is applied at every login, and at every token refresh when refresh is on. `DATABASTION_OIDC_SKIP_ROLE_SYNC=1` keeps roles managed in the console instead (Grafana's `skip_org_role_sync`). Each role change is audit logged with its source (`oidc` or `user`).
10. **Only the two existing roles.** OIDC maps to `admin` or `analyst`. Fine-grained RBAC (per target or per team), team synchronization from groups, multi-organization mapping, SAML and SCIM are Enterprise features ([EDITIONS.md](../EDITIONS.md)) and are not built here, not even as stubs.
11. **Local login and break-glass.** `DATABASTION_LOCAL_LOGIN` takes `enabled` (all local users), `admins` (local users with the `admin` role only, the break-glass path) or `disabled` (`/api/auth/login` answers `404`, the form is hidden; recovery means changing the variable and restarting, which requires host access). OIDC users never have a password and cannot use the local login. The default is an open decision for the maintainer (see Consequences); this ADR proposes `enabled`, so an upgrade changes nothing, with a production startup warning recommending `admins` once OIDC is in use.
12. **`DATABASTION_OIDC_AUTO_LOGIN=1`** sends unauthenticated users straight to the provider. `/login?local=1` still shows the local form when the local login is not `disabled`.
13. **Sessions.** An OIDC login creates the same console session as a local login (12 h absolute, 2 h idle), tagged with its method and the provider's `sid` when present. Without refresh, a user disabled at the provider keeps their console session until it expires (at most 12 h): a documented residual risk. With `DATABASTION_OIDC_USE_REFRESH_TOKEN=1`, the console stores the refresh token encrypted at rest (AES-256-GCM under a new HKDF subkey `oidc-tokens.v1` of `DATABASTION_ENCRYPTION_KEY`) and refreshes it at most every 5 minutes on user activity; a failed refresh ends the session. Without a usable server key, refresh is off (fail closed) and a startup warning says so. Access tokens are not kept.
14. **Logout.** Console logout deletes the session. When the provider advertises an `end_session_endpoint`, the console then performs RP-initiated logout with `id_token_hint` and `post_logout_redirect_uri`, unless `DATABASTION_OIDC_SIGNOUT_REDIRECT_URL` overrides the target. Back-channel logout is not in this ADR.
15. **Rate limits and audit log.** `/api/auth/oidc/start` and `/api/auth/oidc/callback` are rate limited per client IP (when known) and globally through the shared counters ([ADR-0024](0024-shared-rate-limits.md)), fail closed like the other authentication limits. New audit actions: `user.login` with `method: oidc`, `user.login_denied` (a closed list of reasons: `state`, `token`, `id_token`, `group`, `domain`, `role`, `sign_up`, `disabled`, `username`), `user.signup`, `user.pending_login_approve`, `user.identity_link`, `user.role_change`. Tokens, codes, the state, the nonce and raw claims are never logged nor stored outside decision 13.
16. **Configuration** by environment variables, in the console's existing style (secrets as `_FILE` for Docker secrets):

    | Variable | Default | Meaning |
    |---|---|---|
    | `DATABASTION_OIDC_ENABLED` | unset | `1` turns OIDC on; then the issuer, client id and secret are required, or the console refuses to start |
    | `DATABASTION_OIDC_ISSUER_URL` | | Exact issuer (e.g. `https://sso.example.com/realms/acme`) |
    | `DATABASTION_OIDC_CLIENT_ID` | | |
    | `DATABASTION_OIDC_CLIENT_SECRET(_FILE)` | | Never both |
    | `DATABASTION_OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic` | or `client_secret_post` |
    | `DATABASTION_OIDC_SCOPES` | `openid profile email` | `openid` always added |
    | `DATABASTION_OIDC_DISPLAY_NAME` | `Single sign-on` | Button label |
    | `DATABASTION_OIDC_ID_TOKEN_ALGS` | `RS256,PS256,ES256` | Never `none` or `HS*` |
    | `DATABASTION_OIDC_CA_FILE` | unset | Extra CA for the provider |
    | `DATABASTION_OIDC_USE_USERINFO` | unset | Merge userinfo claims |
    | `DATABASTION_OIDC_LOGIN_ATTRIBUTE_PATH`, `_EMAIL_ATTRIBUTE_PATH`, `_NAME_ATTRIBUTE_PATH`, `_GROUPS_ATTRIBUTE_PATH`, `_ROLE_ATTRIBUTE_PATH` | see decision 7 | JMESPath |
    | `DATABASTION_OIDC_ROLE_ATTRIBUTE_STRICT` | open decision | |
    | `DATABASTION_OIDC_ALLOWED_GROUPS`, `DATABASTION_OIDC_ALLOWED_DOMAINS` | unset | |
    | `DATABASTION_OIDC_ALLOW_SIGN_UP` | open decision | |
    | `DATABASTION_OIDC_SKIP_ROLE_SYNC` | unset | |
    | `DATABASTION_OIDC_AUTO_LOGIN` | unset | |
    | `DATABASTION_OIDC_USE_REFRESH_TOKEN` | unset | |
    | `DATABASTION_OIDC_SIGNOUT_REDIRECT_URL` | unset | Overrides RP-initiated logout |
    | `DATABASTION_LOCAL_LOGIN` | open decision (`enabled` proposed) | `enabled` / `admins` / `disabled` |

    The redirect URI is `<DATABASTION_PUBLIC_URL>/api/auth/oidc/callback`; `DATABASTION_PUBLIC_URL` becomes required when OIDC is enabled.
17. **Tests and dev environment.** A Keycloak service in `dev/` with a seeded realm (a confidential client, an admin group, an analyst user, a user with an unverified e-mail, a user with an editable username), used by console integration tests and by an end-to-end scenario (login, role mapping, refused group, pending login, logout). The OIDC client library and the JMESPath library are chosen in the implementation PR, under the console license gate (Apache 2.0 compatible).

## Consequences
- The schema changes: `users.password_hash` becomes nullable (with a check that local users keep one), new `user_identities` and `oidc_pending_logins` tables, sessions tagged with their method. Versioned migrations, as usual.
- A user management page becomes necessary (approve pending logins, change roles when role sync is off, disable users). Local user creation by an administrator comes with it; it does not exist today.
- **Open decisions for the maintainer** (defaults): `DATABASTION_LOCAL_LOGIN` (`enabled` proposed, `admins` is safer but can lock out an install whose only admin is local and forgot the setting); `DATABASTION_OIDC_ALLOW_SIGN_UP` (off proposed, unlike Grafana's default on: pending logins then need an administrator); `DATABASTION_OIDC_ROLE_ATTRIBUTE_STRICT` (on proposed when a role expression is set). This ADR moves to Accepted once they are settled.
- One provider per console. Several providers would multiply the configuration and the identity key already supports them (the issuer is part of it); this can be added later without a schema change.
- Residual risks: without refresh, a user disabled at the provider keeps the console for up to 12 h; a provider compromise gives console access up to the mapped role (the break-glass local admin does not prevent this); the role expression is operator-written code and can be wrong (strict mode limits the damage).
- No change to the agent protocol or to the agents (I1 to I7 unaffected).

## Rejected alternatives
- **Generic OAuth 2.0 without OIDC** (Grafana's `api_url` user-info pattern): no signed, audience-bound identity token, so the console would trust an access token meant for another client; and three endpoint settings instead of one issuer.
- **Matching users by e-mail** (even "verified"): account takeover when the provider lets users set or change their e-mail, or when several tenants share one provider (CVE-2023-3128).
- **SAML in Community**: an Enterprise feature per [EDITIONS.md](../EDITIONS.md); OIDC covers the baseline-security need.
- **Trusted proxy authentication header** (`X-Forwarded-User` from an auth proxy): safe only with a strict trust configuration (a proxy the console alone can be reached through, and a header the proxy always overwrites); a misconfiguration gives login as anyone. It could be a separate ADR later, with a mandatory shared secret or mTLS to the proxy.
- **A TLS "skip verify" option for the provider**: the token exchange would then be open to an attacker on the path; a private CA file covers the legitimate need.
- **Storing access and ID tokens in the browser** (stateless sessions): logout and disablement could not be enforced server side, and the console already has server-side sessions.
