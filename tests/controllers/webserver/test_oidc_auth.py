"""Tests for generic OpenID Connect authentication."""

from __future__ import annotations

import asyncio
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
from music_assistant_models.auth import AuthProviderType, User, UserRole
from music_assistant_models.enums import ConfigEntryType

from music_assistant.constants import (
    CONF_AUTH_OIDC_CLIENT_ID,
    CONF_AUTH_OIDC_CLIENT_SECRET,
    CONF_AUTH_OIDC_ISSUER,
    CONF_AUTH_OIDC_SCOPES,
)
from music_assistant.controllers.webserver.auth import AuthenticationManager
from music_assistant.controllers.webserver.controller import (
    CONF_BASE_URL,
    CONF_EXTERNAL_URL,
    WebserverController,
)
from music_assistant.controllers.webserver.helpers import oidc_provider
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
                if item.provider_type is AuthProviderType.OIDC
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
        user, AuthProviderType.OIDC, oidc_identity_key(issuer.issuer, MOCK_SUBJECT)
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
    await auth.link_user_to_provider(user, AuthProviderType.OIDC, other_issuer_key)

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
