"""A local, deterministic OIDC issuer for authentication tests."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Self
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp
import jwt
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric import rsa

from music_assistant.helpers.pkce import pkce_challenge

MOCK_CLIENT_ID = "ma-oidc-test-client"
MOCK_CLIENT_SECRET = "test-only-secret"
MOCK_SUBJECT = "mock-subject-123"
MOCK_KID = "mock-rsa-key"
MOCK_ACCESS_TOKEN = "mock-oidc-access-token"


class MockOIDCIssuer:
    """Serve local OIDC discovery, authorization, token, JWKS, and UserInfo endpoints."""

    def __init__(self) -> None:
        """Create an issuer with a fresh signing key and no network listener."""
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._codes: dict[str, dict[str, str]] = {}
        self.authorization_requests: list[dict[str, str]] = []
        self.authorization_error: str | None = None
        self.authorization_error_description: str | None = None
        self.issuer = ""
        self.app = web.Application()
        self.app.router.add_get("/.well-known/openid-configuration", self._discovery)
        self.app.router.add_get("/authorize", self._authorize)
        self.app.router.add_post("/token", self._token)
        self.app.router.add_get("/jwks", self._jwks)
        self.app.router.add_get("/userinfo", self._userinfo)
        self.server = TestServer(self.app, host="127.0.0.1")

    async def __aenter__(self) -> Self:
        """Start the issuer on an ephemeral loopback port."""
        await self.server.start_server()
        self.issuer = str(self.server.make_url("/")).rstrip("/")
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Stop the local issuer."""
        await self.server.close()

    @property
    def client_authorization(self) -> str:
        """Return the mock confidential client's token-endpoint authorization header."""
        return aiohttp.encode_basic_auth(MOCK_CLIENT_ID, MOCK_CLIENT_SECRET)

    @property
    def public_jwk(self) -> dict[str, Any]:
        """Return the public signing key in JWK form."""
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self._private_key.public_key(), as_dict=True)
        jwk.update({"kid": MOCK_KID, "use": "sig", "alg": "RS256"})
        return jwk

    async def _discovery(self, _request: web.Request) -> web.Response:
        """Return metadata for an authorization-code OIDC client."""
        return web.json_response(
            {
                "issuer": self.issuer,
                "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token",
                "jwks_uri": f"{self.issuer}/jwks",
                "userinfo_endpoint": f"{self.issuer}/userinfo",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "grant_types_supported": ["authorization_code"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            }
        )

    async def _authorize(self, request: web.Request) -> web.Response:
        """Record an authorization request and redirect with code/state or an OAuth error."""
        params = dict(request.query.items())
        self.authorization_requests.append(params)
        redirect_uri = params.get("redirect_uri", "")
        if (
            params.get("client_id") != MOCK_CLIENT_ID
            or params.get("response_type") != "code"
            or "openid" not in params.get("scope", "").split()
            or params.get("code_challenge_method") != "S256"
            or not params.get("code_challenge")
            or not params.get("state")
            or not params.get("nonce")
            or not redirect_uri
        ):
            raise web.HTTPBadRequest(text="Invalid authorization request")

        if self.authorization_error:
            response_params = {"error": self.authorization_error, "state": params["state"]}
            if self.authorization_error_description:
                response_params["error_description"] = self.authorization_error_description
        else:
            code = secrets.token_urlsafe(24)
            self._codes[code] = {
                "client_id": params["client_id"],
                "redirect_uri": redirect_uri,
                "code_challenge": params["code_challenge"],
                "nonce": params["nonce"],
            }
            response_params = {"code": code, "state": params["state"]}

        parsed_uri = urlsplit(redirect_uri)
        callback_query = [
            *parse_qsl(parsed_uri.query, keep_blank_values=True),
            *response_params.items(),
        ]
        callback_uri = urlunsplit(parsed_uri._replace(query=urlencode(callback_query)))
        raise web.HTTPFound(callback_uri)

    async def _token(self, request: web.Request) -> web.Response:
        """Check the client, code, redirect URI, and PKCE verifier before issuing tokens."""
        expected_auth = self.client_authorization
        if request.headers.get("Authorization") != expected_auth:
            return web.json_response({"error": "invalid_client"}, status=401)

        form = await request.post()
        code = str(form.get("code", ""))
        code_data = self._codes.get(code)
        if (
            form.get("grant_type") != "authorization_code"
            or not code_data
            or form.get("client_id") != MOCK_CLIENT_ID
            or form.get("redirect_uri") != code_data["redirect_uri"]
            or pkce_challenge(str(form.get("code_verifier", ""))) != code_data["code_challenge"]
        ):
            return web.json_response({"error": "invalid_grant"}, status=400)

        del self._codes[code]
        now = datetime.now(UTC)
        id_token = jwt.encode(
            {
                "iss": self.issuer,
                "sub": MOCK_SUBJECT,
                "aud": MOCK_CLIENT_ID,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=5)).timestamp()),
                "nonce": code_data["nonce"],
                "email": "listener@example.test",
                "email_verified": True,
                "preferred_username": "mock-listener",
                "name": "Mock Listener",
            },
            self._private_key,
            algorithm="RS256",
            headers={"kid": MOCK_KID},
        )
        return web.json_response(
            {
                "access_token": MOCK_ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": id_token,
            }
        )

    async def _jwks(self, _request: web.Request) -> web.Response:
        """Return the public signing key only."""
        return web.json_response({"keys": [self.public_jwk]})

    async def _userinfo(self, request: web.Request) -> web.Response:
        """Return claims for the mock access token."""
        if request.headers.get("Authorization") != f"Bearer {MOCK_ACCESS_TOKEN}":
            return web.json_response({"error": "invalid_token"}, status=401)
        return web.json_response(
            {
                "sub": MOCK_SUBJECT,
                "email": "listener@example.test",
                "email_verified": True,
                "preferred_username": "mock-listener",
                "name": "Mock Listener",
            }
        )
