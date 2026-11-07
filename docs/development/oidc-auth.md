# OpenID Connect authentication

## Status and scope

The webserver has a generic OIDC login provider with one configured issuer, registered as
`provider_id="oidc"`. It uses the existing `LoginProvider`, `PendingLoginStore`, callback handler,
and MA token issuance path. Pocket ID is one possible issuer; the implementation has no
Pocket ID-specific URLs, claim names, or identity rules.

Enabled MA users can sign in with an OIDC identity that has been explicitly linked, and an
authenticated user can link an identity through the web callback. Optional OIDC registration is
disabled by default and can be enabled by an administrator. The provider never matches accounts
by email or username, grants roles from OIDC claims, or advertises Remote Access app sign-in.

Frontend commit `ee04752885ecffee0719c93829c37c5f6e755008` declares
`AuthProviderType.OIDC = "oidc"` and uses the same `provider_type` string in its linked-provider
models. Frontend and backend tests cover that wire value. A custom server image still needs the
matching frontend package if it should include the OIDC screens.

## Configuration

Configure these advanced entries under **Settings → System → Webserver**:

| Key | Purpose |
| --- | --- |
| `auth_oidc_issuer` | Exact issuer URL from the provider's discovery document. |
| `auth_oidc_client_id` | Client ID registered for Music Assistant. |
| `auth_oidc_client_secret` | Confidential client secret, stored as a secure string. |
| `auth_oidc_scopes` | Space-separated scopes, defaulting to `openid profile email`. Only those three scopes are accepted; `openid` is required. |
| `auth_oidc_allow_registration` | Allow verified, unlinked identities to create regular MA users. Defaults to `false` and is independent of Home Assistant self-registration. |

OIDC is disabled until issuer, client ID and client secret are all set and valid. Registration
also requires an existing enabled MA administrator, so an OIDC user cannot occupy the initial
administrator setup path. New registrations always receive the regular `user` role, regardless of
OIDC role claims.

Use an HTTPS issuer in normal deployments. HTTP is accepted only for loopback addresses so tests
can use a local mock issuer. Discovery, token, UserInfo and JWKS endpoints must be HTTPS too,
except when the configured issuer itself is loopback HTTP. TLS certificate verification remains
enabled. The token endpoint can advertise `client_secret_basic` or `client_secret_post`; the
provider uses one of those methods as advertised and never places the secret in a URL.

The server uses one fixed callback URI for OIDC: the configured webserver `external_url`, or
`base_url` when no external URL is configured, followed by
`/auth/callback?provider_id=oidc`. Register that exact URI with the issuer. A return URL or request
host does not change it. Forwarded and other proxy headers are not used to establish the callback
origin.

## Authorization flow

1. A sign-in starts through the existing `GET /auth/authorize?provider_id=oidc` route or
   `auth/authorization_url` command. A link starts through `POST /auth/oidc/link/start` with a
   Music Assistant bearer session and `{"confirmed": true}`. The link endpoint checks the
   `CONFIG_PROVIDERS_OWN` scope. The provider obtains authorization, token, UserInfo and JWKS
   endpoints from the configured issuer's discovery document and checks that the discovered
   `issuer` exactly matches configuration.
2. `PendingLoginStore` creates independent random state, OIDC nonce and IdP PKCE verifier values.
   The pending record is server-side, expires after ten minutes, is usable once, and is subject
   to the existing limit of 100 pending authorization transactions. Link state has an `l.`
   prefix; ordinary browser sign-in and native app states keep their existing `w.` and `n.`
   prefixes. The authorization request uses PKCE S256 and requests only the configured OIDC
   profile scopes.
3. The browser returns to the fixed callback URI. The callback consumes state before provider,
   target, error or code validation. A denial or cancellation consumes state and returns a safe
   error page; `error_description` is ignored. Missing, mismatched, expired, replayed or malformed
   callbacks fail without exchanging a code.
4. The server exchanges the code using the exact stored redirect URI and PKCE verifier. It does
   not return or persist provider access, refresh or ID tokens.
5. PyJWT validates the ID token with the configured issuer's JWKS and a fixed `RS256` allow-list.
   Required claims are `iss`, `sub`, `aud`, `exp`, `iat` and `nonce`; present `nbf` is checked too.
   Issuer and audience must match exactly, the nonce must match the pending login, and future
   issued-at values are rejected. The verifier uses 30 seconds of clock leeway. A multi-audience
   token must set `azp` to this client; any provided `azp` must match as well. The token header
   cannot choose an algorithm or JWKS URL.
6. The provider fetches UserInfo over the validated issuer endpoint and requires its `sub` to
   match the verified ID token. For a link transaction, the callback also checks the one-time
   HttpOnly browser cookie and the initiating MA session. It then rechecks the enabled account
   and active session in the same database transaction that inserts the provider link. For a
   login transaction, the exact `(issuer, sub)` pair is resolved through `AuthProviderType.OIDC`.
   Disabled users are refused. An unlinked identity fails unless OIDC registration is enabled.
   OIDC roles and profile claims never grant MA privileges or modify an existing account.
7. A successful login issues an MA token and applies the existing redirect allowlist and
   external-return consent behavior. A successful link returns a simple success page and never
   issues a new MA token or turns the callback into a login.

## Account linking, unlinking and administration

`POST /auth/oidc/link/start` is the only HTTP endpoint that starts account linking. It requires
an enabled authenticated user, a valid bearer session, `CONFIG_PROVIDERS_OWN`, and an explicit
`confirmed: true` request value. It returns only the authorization URL and sets a random,
state-specific, ten-minute HttpOnly `SameSite=Lax` cookie. The cookie is marked `Secure` when the
fixed callback uses HTTPS. Pending server state stores hashes of the cookie value and MA session
token, along with the initiating user ID; it does not expose the binding or PKCE verifier in the
response. Link callbacks are browser-only and must return to the fixed OIDC callback URI.

The link-start HTTP route supports credentialed browser CORS for the Music Assistant Remote
Access origin, the configured `base_url` and `external_url`, loopback and private-network origins,
and the fixed Home Assistant origins used by local clients. It echoes only a trusted requesting
origin, includes `Access-Control-Allow-Credentials`, and rejects untrusted preflights. The short-
lived callback cookie can still be affected by browser third-party-cookie restrictions when the
frontend and server are on different sites.

The WebSocket/API commands are:

| Command | Scope | Purpose |
| --- | --- | --- |
| `auth/user/providers` | `CONFIG_PROVIDERS_OWN` | List the current user's linked methods. Builtin password hashes and encoded OIDC identities are hidden. |
| `auth/oidc/unlink` | `CONFIG_PROVIDERS_OWN` | Remove one OIDC link by `link_id`; requires `confirmed: true` and a current session issued within the last five minutes. |
| `auth/oidc/registration_policy` | `USERS_MANAGE` | Read whether OIDC registration is enabled. |
| `auth/oidc/registration_policy/set` | `USERS_MANAGE` | Persist the OIDC registration policy in webserver configuration. |
| `auth/user/unlink_provider` | `USERS_MANAGE` | Administrator override to remove a provider type from a selected user; requires confirmation and a recent admin session. |

Unlinking is idempotent. The operation refuses to remove the last login method that is currently
usable on the server. It removes only the selected provider link; it preserves the MA account,
other links, tokens and user data. An administrator can remove another user's provider link only
through the explicit admin command.

The registration policy is also available as the advanced webserver configuration entry
`auth_oidc_allow_registration`, defaulting to disabled. It does not change Home Assistant's
`auth_allow_self_registration` policy. New usernames are sanitized from `preferred_username` or
derived from a digest of the issuer-qualified identity, then made unique. A collision never
attaches OIDC to the existing MA account.

Discovery is cached for 15 minutes and JWKS for five minutes, with concurrent refreshes
coalesced. An unknown `kid` triggers one JWKS refresh; a signature failure also gets one refreshed
key set before failing closed. HTTP requests use the shared MA `aiohttp` session, have ten-second
total, five-second connect and five-second read timeouts, cap response bodies at 1 MiB, and reject
redirects. Token, key and userinfo failures map to generic login errors; authorization codes,
tokens, client secrets and PKCE verifiers are not logged or included in HTTP errors.

The provider does not advertise `supports_remote_app`, so Remote Access app sign-in remains
disabled even though the frontend branch understands the `oidc` provider type.

## Identity storage and models

The [`woobble/music-assistant-models` fork](https://github.com/woobble/music-assistant-models)
defines `AuthProviderType.OIDC = "oidc"` in commit
`c2884424c419d8ae0279455aa7d2755de0ea2c3a`, package version
`1.1.236+woobble.oidc.1`. The existing serialized values remain `builtin` and `homeassistant`;
the unknown-value fallback to `BUILTIN` is unchanged. A `UserAuthProvider` with the OIDC value
round-trips through model JSON serialization.

The server development environment uses the fork in editable mode:

```sh
uv pip install -e ../music-assistant-models --config-settings editable_mode=strict
```

The normal server dependency remains pinned to the upstream `1.1.236` package. It does not contain
this enum, so an OIDC server build must include the fork wheel described below. No PyPI release or
production deployment is part of this work.

The auth database already has a unique constraint on
`(provider_type, provider_user_id)`. OIDC stores an unambiguous versioned base64url encoding of a
compact JSON `[issuer, sub]` pair as `provider_user_id`, so issuers cannot collide on the same
subject. There is no table or column change and no database migration is required. The existing
unknown-enum fallback means an older server/model build would interpret an OIDC link as `builtin`
and serialize it back as `builtin`. Keep models versions aligned across the server and any client
that deserializes these links. Do not run OIDC links on a build that lacks the new enum, and treat
rollback to such a build as unsupported until a rollback strategy exists.

Account linking and optional provisioning use the existing database uniqueness constraint on
`(provider_type, provider_user_id)`. Link creation and new-user creation plus link insertion run
atomically. A repeated link by its existing owner is idempotent; a link owned by another user is
rejected. The server database transaction serializes local writes, while SQLite's uniqueness
constraint remains authoritative for competing requests from separate connections. A failed
provisioning transaction leaves neither an orphan MA user nor an orphan provider link.

## Tests

The local `MockOIDCIssuer` fixture runs on loopback with generated signing keys. It supports
discovery overrides, authorization denial, PKCE-checked code exchange, signed ID-token claim
changes, UserInfo subject changes, endpoint failures and key rotation. It requires no live
identity provider or credentials.

Focused coverage lives in:

- `tests/controllers/webserver/test_oidc_auth.py`
- `tests/controllers/webserver/test_oidc_issuer.py`
- `tests/controllers/webserver/test_login_flow.py`
- `tests/controllers/webserver/test_auth_callback.py`
- `tests/controllers/webserver/test_ingress_auth.py`
- `tests/test_webserver_auth.py`
- Shared model coverage in `tests/test_auth.py` in the models repository

The Goal 3 cases also cover authenticated linking, cookie and session binding, link/login state
separation, cross-user conflicts, repeated and concurrent linking, unlink safeguards, registration
policy, username collisions and concurrent provisioning.

Run the focused backend tests with:

```sh
pytest tests/controllers/webserver/test_oidc_auth.py \
  tests/controllers/webserver/test_oidc_issuer.py \
  tests/controllers/webserver/test_login_flow.py \
  tests/controllers/webserver/test_auth_callback.py \
  tests/controllers/webserver/test_auth_logout.py \
  tests/controllers/webserver/test_command_impersonation.py \
  tests/controllers/webserver/test_roles.py \
  tests/controllers/webserver/test_ingress_auth.py \
  tests/test_webserver_auth.py
```

## Integrated OIDC Docker image

Build, verification, staging, licensing, and rollback instructions for the combined server,
frontend, and models image are in
[`oidc-docker-build.md`](oidc-docker-build.md). The models wheel remains the pure Python artifact
from commit `c2884424c419d8ae0279455aa7d2755de0ea2c3a`, version
`1.1.236+woobble.oidc.1`; the integrated image workflow records the wheel hash from each run.
