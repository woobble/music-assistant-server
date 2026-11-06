# OpenID Connect authentication design

## Scope

This document prepares native OpenID Connect (OIDC) sign-in for Music Assistant (MA), with
Pocket ID as a deployment example. The provider must remain generic: the issuer, client ID, and
client credentials are configuration, and there must be no Pocket ID-specific endpoints or
claim rules. This work does not implement the login flow or change the frontend.

## Current authentication architecture

`AuthenticationManager` owns a `login_providers` registry keyed by `provider_id`. Its
`LoginProvider` base class supports credential authentication and optional redirect methods:
`build_authorization_url()` and `complete_authorization()`. `builtin` is always registered.
`homeassistant` is registered only while an available Home Assistant music provider supplies a
usable URL. The `/auth/providers` endpoint and `auth/providers` WebSocket command expose the
provider IDs and whether a provider needs redirects or supports the Remote Access app.

### Built-in username and password

For built-in first-time setup, the administrator is created by `POST /setup` through
`BuiltinLoginProvider.create_user_with_password()`. Later user creation is an authenticated
administrative operation. A normal login uses `POST /auth/login` or the unauthenticated
`auth/login` WebSocket command with `provider_id="builtin"` (the default). The provider
normalizes the username, applies per-username failure delays, hashes the password with PBKDF2,
and looks up the matching `builtin` provider link. Unknown and incorrect usernames use the same
password-hashing path. Disabled users and invalid credentials fail without receiving a token.

Successful HTTP, WebSocket, OAuth, and Remote Access sign-ins all issue an MA token with
`AuthenticationManager.create_token()`. It is an MA-signed JWT with a database row; the database
stores a SHA-256 token hash. Regular login tokens are short-lived, auto-renew on use, and have an
absolute lifetime cap. External IdP tokens must never be returned as MA tokens.

### Home Assistant OAuth in the browser

1. A client calls `GET /auth/authorize?provider_id=homeassistant` or
   `auth/authorization_url`. The latter may also carry a validated `return_url`. The manager
   selects the callback base from MA's configured base/external URL and validated transport
   details, then starts a `PendingLogin` and asks the provider for its authorization URL.
2. `PendingLoginStore` creates a random `w.` state (or `n.` for a native-app return URL), keeps
   the provider ID, redirect URI, transport, return URL, and IdP PKCE verifier in memory, and
   expires the entry after ten minutes. Each state is usable once; at most 100 may be pending.
   Starting another while full raises `RateLimited` (HTTP 429 on the HTTP route).
3. Home Assistant receives the exact callback URI, the callback origin as `client_id`, the
   state, and an S256 PKCE challenge. On callback, the server requires `code`, `state`, and
   `provider_id`; `handle_oauth_callback()` pops the state before checking provider match,
   target, and the authorization-code character set. It then exchanges the code with Home
   Assistant using the stored verifier.
4. The provider gets the HA user ID from the OAuth access token over HA's authenticated
   WebSocket `auth/current_user` command. It does not decode a JWT or trust a user ID supplied
   in a callback. Profile details come from the configured HA provider connection.
5. The provider first looks up the `homeassistant` link. If none exists, it may link an
   unlinked MA user by normalized username. If there is no such user, the global
   `auth_allow_self_registration` setting controls creation; it currently defaults to true.
   New users receive an HA-derived admin/user role. Disabled users are refused.
6. The HTTP handler issues an MA token and serves `oauth_callback.html`. A validated
   same-origin, local, configured, or allowlisted return URL can receive the token; an
   otherwise external return URL requires consent. The page posts to an opener for an
   internal popup, otherwise navigates to the return URL with the token in its `code`
   parameter. The HTTP callback currently reports a missing code/state/provider ID as HTTP
   400 and renders provider failures as an escaped error page.

The HA provider's `supports_remote_app()` only advertises Remote Access when a browser can
reach a public HA URL. HA URL lookups are cached and concurrent lookups are coalesced.

### Home Assistant OAuth through Remote Access

The Remote Access client calls `auth/authorization_url` with `redirect_target="app"`, an S256
client challenge, and its remote WebSocket session. The manager verifies that the connection
really belongs to a live Remote Access gateway session and that the provider advertises remote
support. The provider redirects to `https://app.music-assistant.io/auth/callback/` without a
`provider_id`; the app callback uses `state` to associate the response with the pending login.
The client then calls `auth/exchange(state, code, code_verifier)`. MA pops the state, validates
the client PKCE verifier and code syntax, completes provider authentication with the separate
IdP PKCE verifier, and returns a new MA token in the WebSocket response. Failed exchanges are
rate-limited per connection. This path does not place an MA token in a URL.

### Existing persistence and registration rules

`user_auth_providers` already stores many-to-many provider links with a unique
`(provider_type, provider_user_id)` pair. `UserAuthProvider` deserialization uses the
`AuthProviderType` enum from the external `music-assistant-models` package. Today that enum
contains only `builtin` and `homeassistant`; its `_missing_()` fallback maps unknown values to
`builtin`. Therefore, writing `provider_type="oidc"` before the shared model supports it would
misreport OIDC links as built-in links in user-provider results.

## Proposed generic OIDC provider

Add an `OIDCLoginProvider(LoginProvider)` and register it from the webserver's server-level
authentication configuration. For the first implementation, use one configurable instance with
a stable API ID such as `oidc`. It is enabled only when a valid issuer and client ID have been
configured. Keep the provider ID stable because it is sent through `/auth/authorize`, returned
by `/auth/providers`, and included in the browser callback query. Pocket ID is configured by
entering its issuer URL and registered MA client credentials; no Pocket ID branch belongs in
the provider implementation.

The current core configuration model supports scalar and simple-list entries, not arbitrary
maps of provider instances. A single generic issuer fits that model using separate webserver
entries: issuer URL, client ID, secure client secret, and an OIDC-specific self-registration
boolean defaulting to **false**. Do not inherit HA's global self-registration default. Mark
authentication settings as requiring reload, or explicitly synchronize the registry after
config changes. Supporting several independent issuers later needs an explicit multi-instance
configuration model and stable per-instance `provider_id`s; do not encode an undocumented JSON
blob in a string setting.

Use OIDC discovery metadata for the configured issuer. Validate that its reported `issuer`
matches the configured issuer exactly. Require HTTPS for issuer metadata and token/JWKS requests,
keep certificate validation enabled, use bounded timeouts and response sizes, and reject
unexpected redirects. Use MA's existing configured callback-base selection; do not derive the
callback from `Forwarded`, `X-Forwarded-*`, or other unauthenticated proxy headers.

## Authorization and identity handling

Use Authorization Code with S256 PKCE. `PendingLoginStore` already provides random state,
single-use expiry, provider binding, callback URI storage, and the IdP verifier. Extend the
pending object with an independent random OIDC nonce; never derive nonce from state or store it
in a process-global provider dictionary. Send `openid` and only the profile scopes needed by MA.
At the token endpoint, use the configured client authentication method and the exact redirect
URI and verifier from the pending login. Do not return or persist the IdP access or refresh token.

Verify the ID token before reading identity or profile claims. The verifier must use the
discovered JWKS, select a signing key by `kid`, and use a fixed allow-list of supported
asymmetric signing algorithms. Reject `none`, symmetric algorithms, missing/unknown keys, and
algorithm/key mismatches. Require and validate the signature, exact issuer, client audience,
expiry, issued-at, non-empty subject, and nonce. When `aud` has multiple values, require
`azp` to identify this client. Apply only a small documented clock leeway. Never treat a
decoded-but-unverified token or access token as identity. On key rotation, refresh JWKS at most
once for an unknown `kid`, then fail closed. Cache discovery/JWKS responses and coalesce refreshes
so requests do not fetch the same metadata repeatedly.

Use `(issuer, sub)` as the external identity. Persist an unambiguous encoding of that exact pair
as `provider_user_id` under a shared `AuthProviderType.OIDC` value; do not use email, username,
display name, or the client-supplied provider ID as identity. First resolve the exact provider
link, including disabled users. A disabled linked user is refused. If there is no link, never
auto-link an MA account by email or username, even for `email_verified=true`. If this OIDC
instance has self-registration explicitly enabled, create a regular MA user and link the pair;
otherwise fail with the existing self-registration-disabled error. A colliding username must
not silently attach to an existing account. OIDC claims must not grant MA administrator role or
permissions. Account linking to an existing MA account needs a separate authenticated,
single-use flow bound to the initiating MA user and explicit user confirmation.

If profile claims are fetched from UserInfo instead of the verified ID token, require its `sub`
to exactly match the ID token subject before using any returned claims.

Use the existing MA token issuance path after the OIDC identity resolves. The only persistent
authentication state should be the normal MA token row and any new user/provider-link rows, under
existing database constraints. Do not persist IdP tokens or modify existing users, tokens, roles,
or provider links.

## Callback compatibility and known gaps

The browser callback can carry the configured provider ID because `get_authorization_url()`
currently builds `/auth/callback?provider_id=<provider_id>` for server callbacks. It accepts the
provider's `code` and state and returns through the existing safe redirect/token page. The
Remote Access callback intentionally omits `provider_id`; the server resolves provider from the
pending state when `auth/exchange` runs. Successful OIDC code callbacks fit both existing
server-side paths without changing the frontend API.

There are two gaps to address or explicitly scope out in Goal 2:

- An IdP denial normally returns `error` and `state` without `code`. The current HTTP handler
  rejects the request before popping/consuming state because it requires a code. Add safe
  callback-error handling that consumes and validates state, does not render untrusted
  `error_description`, and does not issue a token.
- `auth/exchange` requires a code string, and the app callback behavior is in the separate
  frontend package, which is not present in this repository. The server API supports the
  successful Remote Access path, but cancellation/error behavior for the real browser and
  mobile clients cannot be confirmed here. Goal 2 should either keep OIDC to server callbacks
  initially or coordinate a frontend change for error responses; no frontend change is part of
  this preparation.

The currently configured MA `base_url` can be HTTP for local networks. Use the same callback URI
selection as existing sign-in, but register the precise URI with the IdP. The IdP's issuer,
discovery, JWKS, token, and userinfo connections must retain normal TLS verification.

## Dependencies

The project already depends on `pyjwt[crypto]` and `cryptography`; no OIDC-specific runtime
dependency is needed for the proposed implementation. Use the existing `aiohttp` session for
async discovery, token, JWKS, and optional UserInfo requests, and PyJWT for signature and
standard claim verification. Avoid PyJWT's synchronous `PyJWKClient` in request handling; fetch
JWKS asynchronously, then resolve keys with PyJWT's JWK types. Keep OAuth state, redirects, and
PKCE in the existing MA abstractions instead of introducing a second client state store.

Authlib is a maintained alternative: its async OAuth client supports PKCE and its OIDC support
parses and validates ID tokens. Its documented async client is backed by HTTPX, which would add
another HTTP client alongside MA's shared `aiohttp` session. It is not selected for this design
unless implementation review demonstrates a concrete OIDC validation benefit that outweighs
that integration cost. Neither option removes the need to bind nonce/state to MA's pending-login
record and apply MA's account policy.

The declared PyJWT floor was `2.10.1`, which permits releases with known JWK/JWT verification
issues. The project minimum is raised to `2.15.1` in `pyproject.toml` and `requirements_all.txt`;
the active test environment already has 2.15.1. Recheck the supported minimum against PyJWT's
security advisories when implementing OIDC.

## Configuration and migration

The proposed OIDC identity fits the existing `user_auth_providers` table and its unique
provider-identity constraint, so no auth-database schema migration is needed if the issuer/subject
pair stays in `provider_user_id`. Adding `AuthProviderType.OIDC` requires a coordinated
`music-assistant-models` change and dependency update before server code stores or deserializes
OIDC links. Do not use a fallback string value while the model's `_missing_()` maps it to
`builtin`.

New additive webserver config entries should have safe defaults and must not rename, move, or
reinterpret existing settings. If implementation changes stored config shape or adds auth DB
columns/tables, stop and design an idempotent migration before treating the work as complete.
Preserve all existing MA users, tokens, roles, and permissions.

## Test plan

The isolated `MockOIDCIssuer` fixture in `tests/controllers/webserver/oidc_issuer.py` serves local
discovery metadata, a generated RSA JWKS, authorization redirects (including denial responses),
a PKCE-checked authorization-code token response, a signed ID token, and UserInfo. It uses an
ephemeral loopback HTTP server and makes no internet calls. Goal 2 should use it to cover:

- Discovery issuer mismatch, unavailable/malformed metadata, TLS/redirect/timeout failures, and
  metadata/JWKS caching and rotation.
- Authorization URL parameters, exact redirect URI, state/provider binding, nonce, IdP PKCE,
  Remote Access client PKCE, expiry, replay, cancellation, and unknown `kid` behavior.
- Valid and invalid ID-token signatures, algorithms, issuer, audience/`azp`, expiry, issued-at,
  nonce, subject, and verified/unverified profile claims.
- Existing linked, disabled, unlinked, registration-disabled, username-collision, and
  explicitly linked accounts; ensure email equality alone never links.
- HTTP callback and Remote Access exchange token issuance, safe failure behavior, and unchanged
  built-in/HA login behavior.

For the preparation fixture itself, run:

```sh
pytest tests/controllers/webserver/test_oidc_issuer.py
```

Also retain focused existing coverage in `tests/test_webserver_auth.py`,
`tests/controllers/webserver/test_ingress_auth.py`, `tests/controllers/webserver/test_login_flow.py`,
and `tests/controllers/webserver/test_auth_callback.py`.

## Goal 2 implementation sequence

1. Coordinate and release the shared `AuthProviderType.OIDC` model change; decide whether the
   initial product supports one issuer or funds a true multi-instance config model.
2. Add safe OIDC config entries and register a generic `OIDCLoginProvider` without changing the
   built-in or HA provider behavior.
3. Add discovery/JWKS caching and Authorization Code + PKCE with nonce in the existing
   `PendingLogin` object. Keep callback URIs and provider lookup compatible with the existing
   HTTP and Remote Access paths.
4. Validate ID tokens with PyJWT and enforce the issuer/audience/expiry/signature/nonce rules
   before resolving `(issuer, sub)`.
5. Implement OIDC-specific registration defaults and an authenticated explicit account-link
   flow. Do not auto-link by email or username.
6. Handle IdP callback errors safely. Decide whether Remote Access cancellation needs a
   frontend change before advertising OIDC support there.
7. Use the mock issuer fixture for offline security and policy tests, then run the focused auth
   suites and repository pre-commit checks.

## References

- [PyJWT usage and JWKS verification](https://pyjwt.readthedocs.io/en/stable/usage.html)
- [PyJWT changelog](https://pyjwt.readthedocs.io/en/stable/changelog.html)
- [PyJWT security advisories](https://github.com/jpadilla/pyjwt/security/advisories)
- [Authlib async OAuth and OpenID Connect client docs](https://docs.authlib.org/en/stable/oauth2/client/http/index.html)
