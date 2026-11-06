"""Tests for the isolated OIDC issuer used by authentication tests."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import aiohttp
import jwt

from music_assistant.helpers.pkce import pkce_challenge
from tests.controllers.webserver.oidc_issuer import (
    MOCK_CLIENT_ID,
    MOCK_KID,
    MOCK_SUBJECT,
    MockOIDCIssuer,
)


async def test_mock_issuer_serves_discovery_jwks_and_pkce_authorization_code(
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The local issuer supports the response shapes an OIDC flow needs to test offline."""
    issuer = mock_oidc_issuer
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{issuer.issuer}/.well-known/openid-configuration") as response:
            metadata = await response.json()

        assert metadata["issuer"] == issuer.issuer
        assert metadata["authorization_endpoint"] == f"{issuer.issuer}/authorize"
        assert metadata["token_endpoint"] == f"{issuer.issuer}/token"
        assert metadata["jwks_uri"] == f"{issuer.issuer}/jwks"

        async with session.get(f"{issuer.issuer}/jwks") as response:
            jwks = await response.json()
        assert jwks["keys"] == [issuer.public_jwk]

        verifier = "test-code-verifier-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        state = "w.test-state"
        nonce = "test-nonce"
        redirect_uri = "http://ma.local:8095/auth/callback?provider_id=oidc"
        async with session.get(
            metadata["authorization_endpoint"],
            params={
                "response_type": "code",
                "client_id": MOCK_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": pkce_challenge(verifier),
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
        ) as response:
            assert response.status == 302
            callback = urlsplit(response.headers["Location"])
            callback_query = parse_qs(callback.query)

        callback_base = f"{callback.scheme}://{callback.netloc}{callback.path}"
        assert callback_base == redirect_uri.split("?", 1)[0]
        assert callback_query["provider_id"] == ["oidc"]
        assert callback_query["state"] == [state]
        code = callback_query["code"][0]

        async with session.post(
            metadata["token_endpoint"],
            headers={"Authorization": issuer.client_authorization},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": MOCK_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        ) as response:
            assert response.status == 200
            token_response = await response.json()

        signing_key = jwt.PyJWK.from_dict(jwks["keys"][0])
        claims = jwt.decode(
            token_response["id_token"],
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer.issuer,
            audience=MOCK_CLIENT_ID,
        )
        assert claims["sub"] == MOCK_SUBJECT
        assert claims["nonce"] == nonce
        assert claims["email_verified"] is True
        assert jwt.get_unverified_header(token_response["id_token"])["kid"] == MOCK_KID

        async with session.get(
            metadata["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {token_response['access_token']}"},
        ) as response:
            userinfo = await response.json()
        assert userinfo["sub"] == claims["sub"]


async def test_mock_issuer_returns_standard_authorization_denial(
    mock_oidc_issuer: MockOIDCIssuer,
) -> None:
    """The issuer can return error and state without a code for denial tests."""
    issuer = mock_oidc_issuer
    issuer.authorization_error = "access_denied"
    issuer.authorization_error_description = "User cancelled"
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{issuer.issuer}/authorize",
            params={
                "response_type": "code",
                "client_id": MOCK_CLIENT_ID,
                "redirect_uri": "https://ma.example/auth/callback?provider_id=oidc",
                "scope": "openid",
                "state": "w.denied-state",
                "nonce": "denied-nonce",
                "code_challenge": pkce_challenge(
                    "test-code-verifier-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                ),
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
        ) as response:
            assert response.status == 302
            query = parse_qs(urlsplit(response.headers["Location"]).query)

        assert query["error"] == ["access_denied"]
        assert query["error_description"] == ["User cancelled"]
        assert query["state"] == ["w.denied-state"]
        assert "code" not in query
