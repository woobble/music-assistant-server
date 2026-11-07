"""Tests for generic OpenID Connect authentication."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from cryptography.hazmat.primitives.asymmetric import rsa
from music_assistant_models.auth import AuthProviderType, Scope, User, UserRole
from music_assistant_models.enums import ConfigEntryType
from music_assistant_models.errors import (
    AuthenticationFailed,
    AuthenticationRequired,
    InvalidDataError,
)

from music_assistant.constants import (
    CONF_AUTH_OIDC_ALLOW_REGISTRATION,
    CONF_AUTH_OIDC_CLIENT_ID,
    CONF_AUTH_OIDC_CLIENT_SECRET,
    CONF_AUTH_OIDC_ISSUER,
    CONF_AUTH_OIDC_SCOPES,
)
from music_assistant.controllers.webserver.auth import (
    AuthenticationManager,
    oidc_link_cookie_name,
)
from music_assistant.controllers.webserver.controller import (
    CONF_BASE_URL,
    CONF_EXTERNAL_URL,
    WebserverController,
)
from music_assistant.controllers.webserver.helpers import oidc_provider
from music_assistant.controllers.webserver.helpers.auth_middleware import (
    set_current_token,
    set_current_user,
)
from music_assistant.controllers.webserver.helpers.auth_providers import (
    get_oidc_auth_provider_type,
)
from music_assistant.controllers.webserver.helpers.oidc_provider import (
    OIDCLoginProvider,
    OIDCProviderConfig,
    is_valid_oidc_issuer_url,
    is_valid_oidc_scopes,
    oidc_identity_key,
)
from tests.controllers.webserver.oidc_issuer import (
    MOCK_CLIENT_ID,
    MOCK_CLIENT_SECRET,
    MOCK_SUBJECT,
    MockOIDCIssuer,
)


@pytest.fixture
async def oidc_auth_manager(
    mass_minimal: Any,
) -> AsyncGenerator[AuthenticationManager]:
    """Provide a configured auth database without starting the webserver listener."""
    webserver = WebserverController(mass_minimal)
    mass_minimal.webserver = webserver
    webserver.config = await mass_minimal.config.get_core_config("webserver")
    webserver.config.update({CONF_BASE_URL: "http://ma.local:8095", CONF_EXTERNAL_URL: ""})
    mass_minimal.music = MagicMock()
    mass_minimal.music.database.execute = AsyncMock()
    mass_minimal.music.database.commit = AsyncMock()
    http_session = aiohttp.ClientSession()
    mass_minimal._http_session = http_session
    await webserver.auth.setup()
    try:
        yield webserver.auth
    finally:
        await webserver.auth.close()
        await http_session.close()


def _register_oidc_provider(
    auth: AuthenticationManager, issuer: MockOIDCIssuer, *, client_id: str = MOCK_CLIENT_ID
) -> OIDCLoginProvider:
    config: OIDCProviderConfig = {
        "issuer": issuer.issuer,
        "client_id": client_id,
        "client_secret": MOCK_CLIENT_SECRET,
        "scopes": "openid profile email",
    }
    provider = OIDCLoginProvider(auth.mass, "oidc", config)
    auth.login_providers["oidc"] = provider
    return provider


async def test_oidc_provider_is_disabled_without_configuration(
    oidc_auth_manager: AuthenticationManager,
) -> None:
    """The normal server setup registers no OIDC provider until all credentials are set."""
    assert "oidc" not in oidc_auth_manager.login_providers


@pytest.mark.parametrize(
    ("issuer", "valid"),
    [
        ("https://idp.example/issuer", True),
        ("http://127.0.0.1:1234", True),
        ("http://192.168.1.10", False),
        ("https://idp.example/issuer?tenant=x", False),
        ("https://user:pass@idp.example", False),
        ("javascript:alert(1)", False),
    ],
)
def test_oidc_issuer_url_validation(issuer: str, valid: bool) -> None:
    """Only HTTPS issuer URLs are accepted, except loopback HTTP for local tests."""
    assert is_valid_oidc_issuer_url(issuer) is valid


@pytest.mark.parametrize(
    ("scopes", "valid"),
    [
        ("openid profile email", True),
        ("openid email", True),
        ("profile email", False),
        ("openid offline_access", False),
        ("openid openid", False),
    ],
)
def test_oidc_scope_validation(scopes: str, valid: bool) -> None:
    """Only the requested profile scopes are accepted, with openid required."""
    assert is_valid_oidc_scopes(scopes) is valid


async def test_oidc_configuration_uses_a_secure_secret_and_linked_only_policy(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Configured OIDC exposes only public provider metadata and keeps registration disabled."""
    auth = oidc_auth_manager
    auth.webserver.config.update(
        {
            CONF_AUTH_OIDC_ISSUER: mock_oidc_issuer.issuer,
            CONF_AUTH_OIDC_CLIENT_ID: MOCK_CLIENT_ID,
            CONF_AUTH_OIDC_CLIENT_SECRET: MOCK_CLIENT_SECRET,
            CONF_AUTH_OIDC_SCOPES: "openid profile email",
        }
    )
    await auth._setup_login_providers()

    provider = auth.login_providers["oidc"]
    assert provider.allow_self_registration is False
    assert (
        len(
            [
                item
                for item in auth.login_providers.values()
                if item.provider_type is get_oidc_auth_provider_type()
            ]
        )
        == 1
    )
    listed = await auth.get_login_providers()
    oidc_entry = next(item for item in listed if item["provider_id"] == "oidc")
    assert oidc_entry["provider_type"] == "oidc"
    assert "client_secret" not in oidc_entry
    entries = {entry.key: entry for entry in await auth.webserver.get_config_entries()}
    assert entries[CONF_AUTH_OIDC_CLIENT_SECRET].type is ConfigEntryType.SECURE_STRING


async def _start_login(
    auth: AuthenticationManager,
    issuer: MockOIDCIssuer,
) -> tuple[Any, dict[str, list[str]]]:
    started = await auth.get_authorization_url(
        "oidc", "http://ma.local:8095/#/home", request_host="attacker.example"
    )
    assert started is not None
    assert urlsplit(started[0]).netloc == urlsplit(issuer.issuer).netloc
    pending = started[1]
    assert pending.redirect_uri == "http://ma.local:8095/auth/callback?provider_id=oidc"
    async with auth.mass.http_session.get(started[0], allow_redirects=False) as response:
        assert response.status == 302
        callback_url = response.headers["Location"]
    callback_params = parse_qs(urlsplit(callback_url).query)
    return pending, callback_params


async def _linked_user(
    auth: AuthenticationManager, issuer: MockOIDCIssuer, *, disabled: bool = False
) -> User:
    user = await auth.create_user("listener", display_name="Local profile name")
    await auth.link_user_to_provider(
        user, get_oidc_auth_provider_type(), oidc_identity_key(issuer.issuer, MOCK_SUBJECT)
    )
    if disabled:
        await auth.database.update("users", {"user_id": user.user_id}, {"enabled": 0})
        await auth.database.commit()
        disabled_user = await auth.get_user(user.user_id, include_disabled=True)
        assert disabled_user is not None
        return disabled_user
    return user


async def _finish_login(
    auth: AuthenticationManager,
    pending: Any,
    callback_params: dict[str, list[str]],
) -> Any:
    assert callback_params["state"][0] == pending.state
    return await auth.handle_oauth_callback(
        "oidc",
        callback_params.get("code", [None])[0],
        callback_params["state"][0],
        callback_params.get("error", [None])[0],
    )


async def _start_link(
    auth: AuthenticationManager,
    issuer: MockOIDCIssuer,
    user: User,
    session_token: str | None = None,
) -> tuple[str, Any, dict[str, list[str]], str]:
    """Start a user-bound linking transaction and complete the issuer redirect."""
    token = session_token or await auth.create_token(user, "OIDC link test session")
    started = await auth.start_oidc_link(user, token)
    assert started is not None
    authorization_url, pending, callback_binding = started
    assert pending.intent.value == "link"
    assert pending.redirect_uri.endswith("/auth/callback?provider_id=oidc")
    assert pending.initiating_user_id == user.user_id
    assert pending.initiating_session_hash == hashlib.sha256(token.encode()).hexdigest()
    assert pending.callback_binding_hash == hashlib.sha256(callback_binding.encode()).hexdigest()
    async with auth.mass.http_session.get(authorization_url, allow_redirects=False) as response:
        assert response.status == 302
        callback_url = response.headers["Location"]
    assert urlsplit(authorization_url).netloc == urlsplit(issuer.issuer).netloc
    return token, pending, parse_qs(urlsplit(callback_url).query), callback_binding


async def _finish_link(
    auth: AuthenticationManager,
    pending: Any,
    callback_params: dict[str, list[str]],
    callback_binding: str | None,
) -> Any:
    """Complete an OIDC link callback with the browser binding from its start response."""
    assert callback_params["state"][0] == pending.state
    return await auth.handle_oauth_callback(
        "oidc",
        callback_params.get("code", [None])[0],
        callback_params["state"][0],
        callback_params.get("error", [None])[0],
        link_callback_binding=callback_binding,
    )


async def test_oidc_signs_in_an_explicitly_linked_user(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A validated OIDC subject resolves its link without changing the local profile or role."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await _linked_user(auth, mock_oidc_issuer)
    mock_oidc_issuer.id_token_claim_overrides.update(
        {"role": "admin", "groups": ["admin"], "email": "other@example.test"}
    )

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert result.success
    assert result.user is not None
    assert result.user.user_id == user.user_id
    assert result.user.role == UserRole.USER
    assert result.user.display_name == "Local profile name"
    assert pending.oidc_nonce is not None
    assert pending.oidc_nonce != pending.state
    assert pending.idp_code_verifier not in pending.state
    authorization = mock_oidc_issuer.authorization_requests[-1]
    assert authorization["scope"] == "openid profile email"
    assert authorization["redirect_uri"] == pending.redirect_uri
    assert authorization["nonce"] == pending.oidc_nonce
    assert authorization["code_challenge_method"] == "S256"
    assert mock_oidc_issuer.discovery_requests == 1
    assert mock_oidc_issuer.jwks_requests == 1


async def test_oidc_uses_a_discovered_client_secret_post_method(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A provider advertising client_secret_post receives credentials only in its TLS body."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await _linked_user(auth, mock_oidc_issuer)
    mock_oidc_issuer.token_auth_methods = ["client_secret_post"]

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert result.success
    assert result.user is not None
    assert result.user.user_id == user.user_id


async def test_oidc_email_and_username_never_auto_link_or_provision(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Matching profile claims do not attach a new OIDC identity or create a user."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    existing = await auth.create_user("mock-listener", display_name="Existing")
    users_before = await auth.list_users()

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert not result.success
    assert "not linked" in (result.error or "")
    assert len(await auth.list_users()) == len(users_before)
    assert await auth.get_user(existing.user_id) is not None


async def test_oidc_refuses_a_disabled_linked_user(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """An existing OIDC link does not enable a disabled Music Assistant account."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await _linked_user(auth, mock_oidc_issuer, disabled=True)

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert not result.success
    assert result.error == "User account is disabled"
    assert user.enabled is False


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "https://attacker.example"),
        ("aud", "another-client"),
        ("exp", "past"),
        ("iat", "future"),
        ("nbf", "future"),
        ("nonce", "wrong-nonce"),
        ("sub", None),
        ("sub", ""),
        ("iat", None),
    ],
    ids=[
        "wrong_issuer",
        "wrong_audience",
        "expired",
        "future_iat",
        "not_yet_valid",
        "wrong_nonce",
        "missing_sub",
        "empty_sub",
        "missing_iat",
    ],
)
async def test_oidc_refuses_invalid_id_token_claims(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
    claim: str,
    value: Any,
) -> None:
    """The OIDC verifier requires the configured issuer, audience and current token claims."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await _linked_user(auth, mock_oidc_issuer)
    if value == "past":
        value = int(time.time()) - 60
    elif value == "future":
        value = int(time.time()) + 60
    mock_oidc_issuer.id_token_claim_overrides[claim] = value

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert not result.success
    assert result.user is None


async def test_oidc_requires_azp_for_a_multi_audience_token(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A multi-audience ID token must identify this client as its authorized party."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await _linked_user(auth, mock_oidc_issuer)
    mock_oidc_issuer.id_token_claim_overrides.update(
        {"aud": [MOCK_CLIENT_ID, "another-client"], "azp": "another-client"}
    )

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert not result.success


async def test_oidc_refuses_unsupported_algorithms_and_bad_signatures(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Only RS256 with a matching issuer JWKS key is accepted."""
    auth = oidc_auth_manager
    provider = _register_oidc_provider(auth, mock_oidc_issuer)
    await _linked_user(auth, mock_oidc_issuer)
    mock_oidc_issuer.id_token_algorithm = "HS256"
    mock_oidc_issuer.id_token_signing_key = "attacker-controlled-test-key-long-enough"

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)
    assert not result.success

    mock_oidc_issuer.id_token_algorithm = "RS256"
    mock_oidc_issuer.id_token_signing_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    provider._jwks = ()
    provider._jwks_fetched_at = 0
    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)
    assert not result.success


async def test_oidc_requires_userinfo_subject_to_match_id_token(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Profile lookup cannot change the identity established by the verified ID token."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await _linked_user(auth, mock_oidc_issuer)
    mock_oidc_issuer.userinfo_subject = "another-subject"

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert not result.success


async def test_oidc_state_is_bound_single_use_and_expires(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Mismatched, expired and replayed callbacks cannot reuse a pending state."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await _linked_user(auth, mock_oidc_issuer)

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    wrong_state = await auth.handle_oauth_callback(
        "oidc", callback_params["code"][0], "w.invalid-state"
    )
    assert not wrong_state.success
    assert pending.state in auth.pending_logins._pending

    with patch(
        "music_assistant.controllers.webserver.helpers.login_flow.time.monotonic",
        return_value=pending.expires_at + 1,
    ):
        expired = await _finish_login(auth, pending, callback_params)
    assert not expired.success
    assert pending.state not in auth.pending_logins._pending

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)
    assert result.success
    assert result.user is not None
    assert result.user.user_id == user.user_id
    replay = await _finish_login(auth, pending, callback_params)
    assert not replay.success


async def test_oidc_provider_mismatch_consumes_the_pending_state(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A callback sent to the wrong provider cannot be retried against the right one."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await _linked_user(auth, mock_oidc_issuer)
    pending, callback_params = await _start_login(auth, mock_oidc_issuer)

    wrong_provider = await auth.handle_oauth_callback(
        "builtin", callback_params["code"][0], pending.state
    )
    replay = await _finish_login(auth, pending, callback_params)

    assert not wrong_provider.success
    assert not replay.success
    assert pending.state not in auth.pending_logins._pending


async def test_oidc_pkce_rejects_a_changed_or_reused_authorization_code(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The token request uses the stored verifier and the issuer rejects code reuse."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await _linked_user(auth, mock_oidc_issuer)
    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    pending.idp_code_verifier = "wrong-code-verifier"
    invalid_pkce = await _finish_login(auth, pending, callback_params)
    assert not invalid_pkce.success

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    first_code = callback_params["code"][0]
    first_result = await _finish_login(auth, pending, callback_params)
    assert first_result.success

    pending, _callback_params = await _start_login(auth, mock_oidc_issuer)
    reused = await auth.handle_oauth_callback("oidc", first_code, pending.state)
    assert not reused.success


async def test_oidc_rejects_malformed_authorization_code(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """An authorization code outside the accepted syntax never reaches the issuer."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    pending, _callback_params = await _start_login(auth, mock_oidc_issuer)
    token_requests_before = mock_oidc_issuer.token_requests

    result = await auth.handle_oauth_callback("oidc", "bad&code", pending.state)

    assert not result.success
    assert result.error == "Invalid authorization code"
    assert mock_oidc_issuer.token_requests == token_requests_before


async def test_oidc_handles_denial_and_cancellation_without_echoing_idp_text(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Provider denial consumes state and never returns its untrusted description."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    mock_oidc_issuer.authorization_error = "access_denied"
    mock_oidc_issuer.authorization_error_description = "secret=do-not-display"
    pending, callback_params = await _start_login(auth, mock_oidc_issuer)

    request = make_mocked_request(
        "GET",
        "/auth/callback?provider_id=oidc&state="
        f"{pending.state}&error=access_denied&error_description=secret%3Ddo-not-display",
        app=web.Application(),
    )
    response = await auth.webserver._handle_auth_callback(request)

    response_text = response.text or ""
    assert response.status == 400
    assert "Sign-in was cancelled" in response_text
    assert "secret=do-not-display" not in response_text
    assert pending.state not in auth.pending_logins._pending
    assert "code" not in callback_params


async def test_oidc_rejects_missing_code_and_consumes_state(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A malformed callback with a valid state cannot be retried later."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    pending, _callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await auth.handle_oauth_callback("oidc", None, pending.state)

    assert not result.success
    assert pending.state not in auth.pending_logins._pending


async def test_oidc_handles_jwks_key_rotation(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A cached old JWKS is refreshed once when the issuer rotates to a new kid."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await _linked_user(auth, mock_oidc_issuer)

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    first = await _finish_login(auth, pending, callback_params)
    assert first.success
    assert mock_oidc_issuer.jwks_requests == 1

    mock_oidc_issuer.rotate_signing_key()
    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    second = await _finish_login(auth, pending, callback_params)

    assert second.success
    assert second.user is not None
    assert second.user.user_id == user.user_id
    assert mock_oidc_issuer.jwks_requests == 2


async def test_oidc_identity_keys_separate_issuer_collisions(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The same subject from a different issuer cannot use an existing provider link."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("listener")
    other_issuer_key = oidc_identity_key("https://other.example/issuer", MOCK_SUBJECT)
    await auth.link_user_to_provider(user, get_oidc_auth_provider_type(), other_issuer_key)

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT) != other_issuer_key
    assert not result.success


async def test_oidc_discovery_failure_disables_the_login_start(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Mismatched and unavailable discovery documents fail closed before redirecting."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)

    mock_oidc_issuer.discovery_overrides["issuer"] = "https://attacker.example"
    assert await auth.get_authorization_url("oidc") is None
    assert not auth.pending_logins._pending

    mock_oidc_issuer.discovery_overrides.clear()
    mock_oidc_issuer.discovery_status = 503
    assert await auth.get_authorization_url("oidc") is None


async def test_oidc_http_calls_have_a_timeout_and_response_limit(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Slow or oversized issuer responses do not keep login requests unbounded."""
    auth = oidc_auth_manager
    provider = _register_oidc_provider(auth, mock_oidc_issuer)
    mock_oidc_issuer.discovery_delay = 0.05
    with (
        patch.object(oidc_provider, "HTTP_TIMEOUT", aiohttp.ClientTimeout(total=0.01)),
    ):
        assert await auth.get_authorization_url("oidc") is None
    assert not auth.pending_logins._pending

    mock_oidc_issuer.discovery_delay = 0
    provider._metadata = None
    provider._metadata_expires_at = 0
    mock_oidc_issuer.discovery_overrides["large_field"] = "x" * (1024 * 1024 + 1)
    assert await auth.get_authorization_url("oidc") is None


@pytest.mark.parametrize("endpoint", ["jwks", "userinfo", "token"])
async def test_oidc_unavailable_endpoints_fail_closed(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
    endpoint: str,
) -> None:
    """Unavailable token, JWKS and UserInfo endpoints do not authenticate a user."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await _linked_user(auth, mock_oidc_issuer)
    setattr(mock_oidc_issuer, f"{endpoint}_status", 503)

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert not result.success
    assert result.user is None


async def test_oidc_simultaneous_logins_keep_independent_state_nonce_and_verifiers(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Two parallel logins use separate state, nonce and IdP PKCE verifier values."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await _linked_user(auth, mock_oidc_issuer)
    first, second = await asyncio.gather(
        _start_login(auth, mock_oidc_issuer), _start_login(auth, mock_oidc_issuer)
    )
    first_pending, first_params = first
    second_pending, second_params = second

    assert first_pending.state != second_pending.state
    assert first_pending.oidc_nonce != second_pending.oidc_nonce
    assert first_pending.idp_code_verifier != second_pending.idp_code_verifier
    results = await asyncio.gather(
        _finish_login(auth, first_pending, first_params),
        _finish_login(auth, second_pending, second_params),
    )
    assert all(
        result.success and result.user and result.user.user_id == user.user_id for result in results
    )


async def test_oidc_linking_existing_account_is_single_use_and_enables_login(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A confirmed, session-bound OIDC transaction links without issuing a second session."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("link-owner")
    token, pending, callback_params, binding = await _start_link(auth, mock_oidc_issuer, user)

    assert pending.state.startswith("l.")
    assert pending.state != (await _start_login(auth, mock_oidc_issuer))[0].state
    assert oidc_link_cookie_name(pending.state)
    result = await _finish_link(auth, pending, callback_params, binding)

    assert result.success is True
    assert result.linked is True
    assert result.user is None
    linked_user = await auth.get_user_by_provider_link(
        get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
    )
    assert linked_user is not None
    assert linked_user.user_id == user.user_id
    assert (
        await auth.database.get_count_from_query(
            "SELECT link_id FROM user_auth_providers WHERE user_id = :user_id "
            "AND provider_type = :provider_type",
            {"user_id": user.user_id, "provider_type": get_oidc_auth_provider_type().value},
        )
        == 1
    )
    assert await auth.authenticate_with_token(token) is not None

    original_link = await auth.database.get_row(
        "user_auth_providers",
        {"user_id": user.user_id, "provider_type": get_oidc_auth_provider_type().value},
    )
    assert original_link is not None
    _token, repeat_pending, repeat_params, repeat_binding = await _start_link(
        auth, mock_oidc_issuer, user
    )
    repeated = await _finish_link(auth, repeat_pending, repeat_params, repeat_binding)
    assert repeated.success is True
    assert repeated.linked is True
    assert (
        await auth.database.get_count_from_query(
            "SELECT link_id FROM user_auth_providers WHERE user_id = :user_id "
            "AND provider_type = :provider_type",
            {"user_id": user.user_id, "provider_type": get_oidc_auth_provider_type().value},
        )
        == 1
    )
    repeated_link = await auth.database.get_row(
        "user_auth_providers",
        {"user_id": user.user_id, "provider_type": get_oidc_auth_provider_type().value},
    )
    assert repeated_link is not None
    assert repeated_link["link_id"] == original_link["link_id"]

    login_pending, login_params = await _start_login(auth, mock_oidc_issuer)
    login_result = await _finish_login(auth, login_pending, login_params)
    assert login_result.success is True
    assert login_result.user is not None
    assert login_result.user.user_id == user.user_id
    replay = await _finish_link(auth, pending, callback_params, binding)
    assert replay.success is False


async def test_oidc_link_start_requires_authentication_confirmation_and_permission(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The browser link endpoint requires a valid member session and explicit confirmation."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    unauthenticated = make_mocked_request("POST", "/auth/oidc/link/start")
    response = await auth.webserver._handle_oidc_link_start(unauthenticated)
    assert response.status == 401

    member = await auth.create_user("link-member")
    token = await auth.create_token(member, "link endpoint test")
    request = make_mocked_request(
        "POST",
        "/auth/oidc/link/start",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    request._read_bytes = b'{"confirmed":false}'
    with patch(
        "music_assistant.controllers.webserver.controller.get_authenticated_user",
        new=AsyncMock(return_value=member),
    ):
        response = await auth.webserver._handle_oidc_link_start(request)
    assert response.status == 400
    assert not auth.pending_logins._pending

    guest = await auth.create_user("link-guest", role=UserRole.GUEST)
    guest_token = await auth.create_token(guest, "guest link test")
    request = make_mocked_request(
        "POST",
        "/auth/oidc/link/start",
        headers={"Authorization": f"Bearer {guest_token}"},
    )
    with patch(
        "music_assistant.controllers.webserver.controller.get_authenticated_user",
        new=AsyncMock(return_value=guest),
    ):
        response = await auth.webserver._handle_oidc_link_start(request)
    assert response.status == 403


async def test_oidc_link_start_response_sets_only_a_short_lived_browser_binding(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The start response returns the authorization URL and keeps binding state in a cookie."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("link-start")
    token = await auth.create_token(user, "link start test")
    request = make_mocked_request(
        "POST",
        "/auth/oidc/link/start",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    request._read_bytes = b'{"confirmed":true}'
    with patch(
        "music_assistant.controllers.webserver.controller.get_authenticated_user",
        new=AsyncMock(return_value=user),
    ):
        response = await auth.webserver._handle_oidc_link_start(request)

    assert response.status == 200
    assert response.text is not None
    payload = json.loads(response.text)
    assert set(payload) == {"authorization_url"}
    assert "code_verifier" not in response.text
    assert "client_secret" not in response.text
    pending = next(iter(auth.pending_logins._pending.values()))
    cookie_name = oidc_link_cookie_name(pending.state)
    assert cookie_name is not None
    cookie = response.cookies[cookie_name]
    assert cookie["httponly"]
    assert cookie["samesite"] == "Lax"
    assert cookie["max-age"] == "600"


async def test_oidc_link_callback_returns_no_session_and_clears_binding_cookie(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The HTTP link callback confirms the link without exposing an MA session token."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("link-http-callback")
    token, pending, callback_params, binding = await _start_link(auth, mock_oidc_issuer, user)
    cookie_name = oidc_link_cookie_name(pending.state)
    assert cookie_name is not None
    request = make_mocked_request(
        "GET",
        f"/auth/callback?provider_id=oidc&state={pending.state}&code={callback_params['code'][0]}",
        headers={"Cookie": f"{cookie_name}={binding}"},
    )

    response = await auth.webserver._handle_auth_callback(request)

    assert response.status == 200
    assert response.text is not None
    assert "Account linked" in response.text
    assert "access_token" not in response.text
    assert token not in response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert response.cookies[cookie_name]["max-age"] == "0"
    linked_user = await auth.get_user_by_provider_link(
        get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
    )
    assert linked_user is not None
    assert linked_user.user_id == user.user_id


async def test_oidc_provider_list_hides_password_and_encoded_oidc_identity(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The account provider list omits password hashes and private OIDC identity keys."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("provider-list")
    await auth.link_user_to_provider(user, AuthProviderType.BUILTIN, "password-hash-secret")
    await auth.link_user_to_provider(user, AuthProviderType.HOME_ASSISTANT, "ha-user-id")
    await auth.link_user_to_provider(
        user,
        get_oidc_auth_provider_type(),
        oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT),
    )
    set_current_user(user)
    try:
        providers = await auth.get_my_providers()
    finally:
        set_current_user(None)

    by_type = {provider["provider_type"]: provider for provider in providers}
    assert by_type[AuthProviderType.BUILTIN.value]["provider_user_id"] == ""
    assert by_type[get_oidc_auth_provider_type().value]["provider_user_id"] == ""
    assert by_type[AuthProviderType.HOME_ASSISTANT.value]["provider_user_id"] == "ha-user-id"
    assert "password-hash-secret" not in json.dumps(providers)
    assert oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT) not in json.dumps(providers)
    assert getattr(auth.get_my_providers, "api_required_scope", None) is Scope.CONFIG_PROVIDERS_OWN


async def test_oidc_link_rejects_identity_owned_by_another_user(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """An OIDC identity already linked to one account cannot be attached to another."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    owner = await _linked_user(auth, mock_oidc_issuer)
    other_user = await auth.create_user("link-other")
    _token, pending, callback_params, binding = await _start_link(
        auth, mock_oidc_issuer, other_user
    )

    result = await _finish_link(auth, pending, callback_params, binding)
    assert not result.success
    assert result.user is None
    assert (
        await auth.get_user_by_provider_link(
            get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
        )
        == owner
    )
    assert (
        await auth.database.get_count_from_query(
            "SELECT link_id FROM user_auth_providers WHERE user_id = :user_id "
            "AND provider_type = :provider_type",
            {"user_id": other_user.user_id, "provider_type": get_oidc_auth_provider_type().value},
        )
        == 0
    )


async def test_oidc_concurrent_link_attempts_cannot_transfer_identity(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Concurrent callbacks for different MA users leave one unique provider owner."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    first_user = await auth.create_user("link-racer-one")
    second_user = await auth.create_user("link-racer-two")
    first = await _start_link(auth, mock_oidc_issuer, first_user)
    second = await _start_link(auth, mock_oidc_issuer, second_user)
    results = await asyncio.gather(
        _finish_link(auth, first[1], first[2], first[3]),
        _finish_link(auth, second[1], second[2], second[3]),
    )

    assert sum(result.success for result in results) == 1
    linked_user = await auth.get_user_by_provider_link(
        get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
    )
    assert linked_user is not None
    assert linked_user.user_id in {first_user.user_id, second_user.user_id}
    assert (
        await auth.database.get_count_from_query(
            "SELECT link_id FROM user_auth_providers WHERE provider_type = :provider_type",
            {"provider_type": get_oidc_auth_provider_type().value},
        )
        == 1
    )


async def test_oidc_link_rechecks_disabled_user_and_session_binding(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A revoked browser binding or disabled initiating account cannot complete a link."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("link-disabled")
    token, pending, params, binding = await _start_link(auth, mock_oidc_issuer, user)
    wrong_binding = await _finish_link(auth, pending, params, "wrong-browser")
    assert not wrong_binding.success
    replay = await _finish_link(auth, pending, params, binding)
    assert not replay.success
    assert (
        await auth.get_user_by_provider_link(
            get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
        )
        is None
    )
    assert await auth.authenticate_with_token(token) is not None

    user = await auth.create_user("link-disabled-two")
    _token, pending, params, binding = await _start_link(auth, mock_oidc_issuer, user)
    await auth.database.update("users", {"user_id": user.user_id}, {"enabled": 0})
    await auth.database.commit()
    result = await _finish_link(auth, pending, params, binding)
    assert not result.success
    assert (
        await auth.get_user_by_provider_link(
            get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
        )
        is None
    )


async def test_oidc_link_rejects_expired_state_and_login_transaction_confusion(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Login states cannot complete a link, and expired link states are consumed."""
    auth = oidc_auth_manager
    provider = _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("link-confusion")
    _token, link_pending, link_params, binding = await _start_link(auth, mock_oidc_issuer, user)
    with pytest.raises(AuthenticationFailed, match="not a sign-in"):
        await provider.complete_authorization(link_pending, {"code": link_params["code"][0]})
    expired_token, expired, expired_params, expired_binding = await _start_link(
        auth, mock_oidc_issuer, user
    )
    expired.expires_at = time.monotonic() - 1
    expired_result = await _finish_link(auth, expired, expired_params, expired_binding)
    assert not expired_result.success
    assert await auth.authenticate_with_token(expired_token) is not None

    login_pending, login_params = await _start_login(auth, mock_oidc_issuer)
    login_result = await _finish_login(auth, login_pending, login_params)
    assert login_result.success is False
    assert binding

    _token, mismatched_pending, mismatched_params, mismatched_binding = await _start_link(
        auth, mock_oidc_issuer, user
    )
    state_mismatch = await auth.handle_oauth_callback(
        "oidc",
        mismatched_params["code"][0],
        f"l.{'A' * 43}",
        link_callback_binding=mismatched_binding,
    )
    assert state_mismatch.success is False
    correctly_matched = await _finish_link(
        auth, mismatched_pending, mismatched_params, mismatched_binding
    )
    assert correctly_matched.success is True


@pytest.mark.parametrize(
    ("provider_error", "expected_message"),
    [
        ("access_denied", "Sign-in was cancelled"),
        ("server_error", "The identity provider rejected the sign-in"),
    ],
)
async def test_oidc_link_denial_and_cancellation_do_not_create_links(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
    provider_error: str,
    expected_message: str,
) -> None:
    """Provider denial or cancellation consumes the pending state without linking."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("link-denial")
    mock_oidc_issuer.authorization_error = provider_error
    mock_oidc_issuer.authorization_error_description = "do-not-display"
    _token, pending, params, binding = await _start_link(auth, mock_oidc_issuer, user)
    result = await _finish_link(auth, pending, params, binding)
    assert not result.success
    assert result.error == expected_message
    assert "do-not-display" not in (result.error or "")
    assert (
        await auth.get_user_by_provider_link(
            get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
        )
        is None
    )


async def test_oidc_unlink_is_confirmed_reauthenticated_idempotent_and_preserves_user(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Unlink removes only the selected identity and preserves sessions and the MA account."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("unlink-owner")
    await auth.link_user_to_provider(user, AuthProviderType.BUILTIN, "test-password-hash")
    oidc_link = await auth.link_user_to_provider(
        user,
        get_oidc_auth_provider_type(),
        oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT),
    )
    token = await auth.create_token(user, "recent unlink session")
    set_current_user(user)
    set_current_token(token)
    try:
        with pytest.raises(InvalidDataError, match="confirmation"):
            await auth.unlink_my_oidc_provider(oidc_link.link_id, False)
        assert await auth.unlink_my_oidc_provider(oidc_link.link_id, True)
        assert await auth.unlink_my_oidc_provider(oidc_link.link_id, True)
    finally:
        set_current_token(None)
        set_current_user(None)

    assert await auth.get_user(user.user_id) == user
    assert await auth.authenticate_with_token(token) is not None
    assert (
        await auth.get_user_by_provider_link(
            get_oidc_auth_provider_type(), oidc_link.provider_user_id
        )
        is None
    )


async def test_oidc_unlink_cannot_target_another_user_or_remove_last_login(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Self-service unlink is owner-scoped and requires another usable login method."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    owner = await auth.create_user("unlink-owner-two")
    other = await auth.create_user("unlink-other")
    other_link = await auth.link_user_to_provider(
        other,
        get_oidc_auth_provider_type(),
        oidc_identity_key(mock_oidc_issuer.issuer, "other-subject"),
    )
    await auth.link_user_to_provider(owner, AuthProviderType.BUILTIN, "owner-password-hash")
    owner_token = await auth.create_token(owner, "owner unlink session")
    set_current_user(owner)
    set_current_token(owner_token)
    try:
        with pytest.raises(InvalidDataError, match="another user"):
            await auth.unlink_my_oidc_provider(other_link.link_id, True)
    finally:
        set_current_token(None)
        set_current_user(None)

    only_oidc_user = await auth.create_user("unlink-last")
    only_link = await auth.link_user_to_provider(
        only_oidc_user,
        get_oidc_auth_provider_type(),
        oidc_identity_key(mock_oidc_issuer.issuer, "only-subject"),
    )
    only_token = await auth.create_token(only_oidc_user, "last provider session")
    set_current_user(only_oidc_user)
    set_current_token(only_token)
    try:
        with pytest.raises(InvalidDataError, match="usable login method"):
            await auth.unlink_my_oidc_provider(only_link.link_id, True)
    finally:
        set_current_token(None)
        set_current_user(None)
    assert await auth.get_user_by_provider_link(
        get_oidc_auth_provider_type(), only_link.provider_user_id
    )


async def test_oidc_unlink_requires_a_recent_session_and_admin_override_is_explicit(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Security changes need a fresh session; cross-user removal needs explicit admin consent."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    user = await auth.create_user("unlink-old-session")
    await auth.link_user_to_provider(user, AuthProviderType.BUILTIN, "test-password-hash")
    link = await auth.link_user_to_provider(
        user,
        get_oidc_auth_provider_type(),
        oidc_identity_key(mock_oidc_issuer.issuer, "old-session"),
    )
    token = await auth.create_token(user, "old unlink session")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    await auth.database.update(
        "auth_tokens",
        {"token_hash": token_hash},
        {"created_at": "2000-01-01T00:00:00+00:00"},
    )
    set_current_user(user)
    set_current_token(token)
    try:
        with pytest.raises(AuthenticationRequired, match="sign in again"):
            await auth.unlink_my_oidc_provider(link.link_id, True)
    finally:
        set_current_token(None)
        set_current_user(None)

    admin = await auth.create_user("unlink-admin", role=UserRole.ADMIN)
    admin_token = await auth.create_token(admin, "fresh admin session")
    set_current_user(admin)
    set_current_token(admin_token)
    try:
        with pytest.raises(InvalidDataError, match="confirmation"):
            await auth.unlink_provider(user.user_id, get_oidc_auth_provider_type().value, False)
        with pytest.raises(InvalidDataError, match="Unknown authentication provider"):
            await auth.unlink_provider(user.user_id, "unknown-provider", True)
        assert await auth.unlink_provider(user.user_id, get_oidc_auth_provider_type().value, True)
    finally:
        set_current_token(None)
        set_current_user(None)
    assert (
        await auth.get_user_by_provider_link(get_oidc_auth_provider_type(), link.provider_user_id)
        is None
    )
    assert await auth.get_user(user.user_id) is not None


async def test_oidc_registration_is_disabled_by_default_and_admin_policy_is_scoped(
    oidc_auth_manager: AuthenticationManager,
) -> None:
    """OIDC registration is independent of HA policy and policy commands are admin-only."""
    auth = oidc_auth_manager
    entries = {entry.key: entry for entry in await auth.webserver.get_config_entries()}
    assert entries[CONF_AUTH_OIDC_ALLOW_REGISTRATION].default_value is False
    assert auth.webserver.config.get_value(CONF_AUTH_OIDC_ALLOW_REGISTRATION, False) is False
    assert (
        getattr(auth.get_oidc_registration_policy, "api_required_scope", None) is Scope.USERS_MANAGE
    )
    assert (
        getattr(auth.set_oidc_registration_policy, "api_required_scope", None) is Scope.USERS_MANAGE
    )
    assert (
        getattr(auth.unlink_my_oidc_provider, "api_required_scope", None)
        is Scope.CONFIG_PROVIDERS_OWN
    )

    async def save_webserver_config(domain: str, values: dict[str, Any]) -> None:
        assert domain == "webserver"
        auth.webserver.config.update(values)

    with patch.object(
        auth.mass.config,
        "save_core_config",
        new=AsyncMock(side_effect=save_webserver_config),
    ) as save_core_config:
        assert await auth.set_oidc_registration_policy(True) == {"enabled": True}
    save_core_config.assert_awaited_once_with(
        "webserver", {CONF_AUTH_OIDC_ALLOW_REGISTRATION: True}
    )


async def test_oidc_registration_provisions_only_regular_users_after_verification(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Verified OIDC registration creates a regular linked user regardless of role claims."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await auth.create_user("registration-admin", role=UserRole.ADMIN)
    auth.webserver.config.update({CONF_AUTH_OIDC_ALLOW_REGISTRATION: True})
    mock_oidc_issuer.id_token_claim_overrides["role"] = "admin"

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert result.success
    assert result.user is not None
    assert result.user.role == UserRole.USER
    assert result.user.username == "mock-listener"
    assert (
        await auth.get_user_by_provider_link(
            get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
        )
        == result.user
    )


async def test_oidc_registration_username_collision_never_links_by_profile(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """A preferred-username collision creates a unique account without modifying its owner."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await auth.create_user("registration-admin", role=UserRole.ADMIN)
    existing = await auth.create_user("mock-listener", display_name="Unrelated local account")
    auth.webserver.config.update({CONF_AUTH_OIDC_ALLOW_REGISTRATION: True})

    pending, callback_params = await _start_login(auth, mock_oidc_issuer)
    result = await _finish_login(auth, pending, callback_params)

    assert result.success
    assert result.user is not None
    assert result.user.user_id != existing.user_id
    assert result.user.username == "mock-listener-2"
    assert (await auth.get_user(existing.user_id)) == existing
    assert (
        await auth.get_user_by_provider_link(
            get_oidc_auth_provider_type(), oidc_identity_key(mock_oidc_issuer.issuer, MOCK_SUBJECT)
        )
        == result.user
    )


async def test_oidc_concurrent_registration_creates_one_user_and_link(
    oidc_auth_manager: AuthenticationManager,
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """Simultaneous first sign-ins for an identity return the same atomically created user."""
    auth = oidc_auth_manager
    _register_oidc_provider(auth, mock_oidc_issuer)
    await auth.create_user("registration-admin", role=UserRole.ADMIN)
    auth.webserver.config.update({CONF_AUTH_OIDC_ALLOW_REGISTRATION: True})
    first, second = await asyncio.gather(
        _start_login(auth, mock_oidc_issuer), _start_login(auth, mock_oidc_issuer)
    )
    results = await asyncio.gather(
        _finish_login(auth, first[0], first[1]), _finish_login(auth, second[0], second[1])
    )

    assert all(result.success and result.user for result in results)
    assert results[0].user == results[1].user
    assert (
        await auth.database.get_count_from_query(
            "SELECT user_id FROM users WHERE username LIKE 'mock-listener%'"
        )
        == 1
    )
    assert (
        await auth.database.get_count_from_query(
            "SELECT link_id FROM user_auth_providers WHERE provider_type = :provider_type",
            {"provider_type": get_oidc_auth_provider_type().value},
        )
        == 1
    )
