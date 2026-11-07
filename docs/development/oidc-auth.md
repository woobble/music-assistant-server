# OpenID Connect authentication

## Status and scope

The webserver has a generic OIDC login provider with one configured issuer, registered as
`provider_id="oidc"`. It uses the existing `LoginProvider`, `PendingLoginStore`, callback handler,
and MA token issuance path. Pocket ID is one possible issuer; the implementation has no
Pocket ID-specific URLs, claim names, or identity rules.

This is backend-only. OIDC sign-in currently works for enabled MA users whose OIDC identity has
already been explicitly linked. The provider does not create users, attach an identity by email or
username, grant roles from OIDC claims, or advertise Remote Access app sign-in. Account linking
and new-user provisioning are Goal 3 work. Browser, desktop and mobile callback compatibility,
including cancellation behavior in the separate frontend package, remains Goal 4 work.

## Configuration

Configure these advanced entries under **Settings → System → Webserver**:

| Key | Purpose |
| --- | --- |
| `auth_oidc_issuer` | Exact issuer URL from the provider's discovery document. |
| `auth_oidc_client_id` | Client ID registered for Music Assistant. |
| `auth_oidc_client_secret` | Confidential client secret, stored as a secure string. |
| `auth_oidc_scopes` | Space-separated scopes, defaulting to `openid profile email`. Only those three scopes are accepted; `openid` is required. |

OIDC is disabled until issuer, client ID and client secret are all set and valid. The registration
policy for this goal is fixed to **linked users only**; the Home Assistant
`auth_allow_self_registration` setting does not change it. New-user registration is not available
yet.

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

1. The client starts the existing `GET /auth/authorize?provider_id=oidc` route or
   `auth/authorization_url` command. The provider obtains authorization, token, UserInfo and JWKS
   endpoints from the configured issuer's discovery document and checks that the discovered
   `issuer` exactly matches configuration.
2. `PendingLoginStore` creates independent random state, OIDC nonce and IdP PKCE verifier values.
   The pending record is server-side, expires after ten minutes, is usable once, and is subject
   to the existing limit of 100 pending sign-ins. The authorization request uses PKCE S256 and
   requests only the configured OIDC profile scopes.
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
   match the verified ID token. Profile claims are not used to change the MA account. The exact
   `(issuer, sub)` pair is resolved through `AuthProviderType.OIDC`; disabled users are refused,
   and unlinked identities fail. OIDC roles and profile claims never grant MA privileges.
7. On success, the existing callback handler issues an MA token and applies the existing
   redirect allowlist and external-return consent behavior.

Discovery is cached for 15 minutes and JWKS for five minutes, with concurrent refreshes
coalesced. An unknown `kid` triggers one JWKS refresh; a signature failure also gets one refreshed
key set before failing closed. HTTP requests use the shared MA `aiohttp` session, have ten-second
total, five-second connect and five-second read timeouts, cap response bodies at 1 MiB, and reject
redirects. Token, key and userinfo failures map to generic login errors; authorization codes,
tokens, client secrets and PKCE verifiers are not logged or included in HTTP errors.

The provider does not advertise `supports_remote_app` yet. The existing app callback omits the
provider ID and is implemented in the separate frontend package; Goal 4 must verify its callback
and cancellation/error behavior before OIDC is exposed over Remote Access.

## Identity storage and models

The shared [`music-assistant/models` repository](https://github.com/music-assistant/models)
contains `AuthProviderType.OIDC = "oidc"`. The existing serialized values remain `builtin` and
`homeassistant`; the unknown-value fallback to `BUILTIN` is unchanged. A `UserAuthProvider` with
the OIDC value round-trips through model serialization. The server development environment uses
an editable checkout of the shared models source until a published models release includes the
enum; a normal server install must use that updated shared package before OIDC login is enabled.

The auth database already has a unique constraint on
`(provider_type, provider_user_id)`. OIDC stores an unambiguous versioned base64url encoding of a
compact JSON `[issuer, sub]` pair as `provider_user_id`, so issuers cannot collide on the same
subject. There is no table or column change and no database migration is required. The existing
unknown-enum fallback means an older server/model build would interpret an OIDC link as `builtin`;
do not run OIDC links on a build that lacks the new enum, and treat rollback to such a build as
unsupported until a rollback strategy exists.

The OIDC flow only reads an existing provider link, so it does not create or race to insert links.
Account linking in Goal 3 must use the database uniqueness constraint and handle concurrent
attempts without attaching a link to a different user.

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

Run the focused backend tests with:

```sh
pytest tests/controllers/webserver/test_oidc_auth.py \
  tests/controllers/webserver/test_oidc_issuer.py \
  tests/controllers/webserver/test_login_flow.py \
  tests/controllers/webserver/test_auth_callback.py \
  tests/controllers/webserver/test_ingress_auth.py
```

## Remaining work

- **Goal 3:** authenticated account linking with explicit user confirmation, safe account
  provisioning policy, management/removal, and concurrency handling for new links.
- **Goal 4:** frontend and mobile callback compatibility, including provider denial and
  cancellation, and an end-to-end check of token handling and Remote Access support.
- Publish the coordinated models release before deploying this server change to environments
  that install the shared package from its normal package index.
