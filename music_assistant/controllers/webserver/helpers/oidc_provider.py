"""Generic OpenID Connect login provider."""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

import aiohttp
import jwt
from jwt.exceptions import InvalidSignatureError, PyJWTError
from music_assistant_models.auth import AuthProviderType
from music_assistant_models.errors import AuthenticationFailed

from music_assistant.constants import CONF_AUTH_OIDC_ALLOW_REGISTRATION
from music_assistant.controllers.webserver.helpers.auth_providers import (
    AuthResult,
    LoginProvider,
    LoginProviderConfig,
)
from music_assistant.controllers.webserver.helpers.login_flow import (
    AuthTransactionIntent,
    PendingLogin,
)
from music_assistant.helpers.pkce import pkce_challenge

if TYPE_CHECKING:
    from music_assistant_models.auth import User

    from music_assistant import MusicAssistant

DISCOVERY_TTL = 900
JWKS_TTL = 300
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5, sock_read=5)
MAX_RESPONSE_SIZE = 1024 * 1024
ID_TOKEN_ALGORITHMS = ("RS256",)
OIDC_SCOPES = frozenset({"openid", "profile", "email"})


class OIDCProviderConfig(LoginProviderConfig):
    """Configuration for the single generic OIDC provider."""

    issuer: str
    client_id: str
    client_secret: str
    scopes: str


@dataclass(frozen=True)
class VerifiedOIDCIdentity:
    """An OIDC identity whose token and UserInfo response have been verified."""

    provider_user_id: str
    preferred_username: str | None
    display_name: str | None


def is_valid_oidc_issuer_url(value: Any) -> bool:
    """Return whether a configured issuer is a safe HTTP(S) URL."""
    if not isinstance(value, str) or not _is_safe_endpoint_url(value, allow_http_loopback=True):
        return False
    return "?" not in value


def is_valid_oidc_client_id(value: Any) -> bool:
    """Return whether a client ID is a bounded, non-empty printable value."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= 512
        and not any(char.isspace() or ord(char) < 33 for char in value)
    )


def is_valid_oidc_client_id_config(value: Any) -> bool:
    """Return whether an optional client ID is empty or valid."""
    return value is None or value == "" or is_valid_oidc_client_id(value)


def is_valid_oidc_issuer_config(value: Any) -> bool:
    """Return whether an optional issuer setting is empty or a safe issuer URL."""
    return value is None or value == "" or is_valid_oidc_issuer_url(value)


def is_valid_oidc_scopes(value: Any) -> bool:
    """Return whether the requested scopes are limited to OIDC profile data."""
    if not isinstance(value, str):
        return False
    scopes = value.split()
    return (
        bool(scopes)
        and len(scopes) == len(set(scopes))
        and set(scopes) <= OIDC_SCOPES
        and ("openid" in scopes)
    )


def oidc_identity_key(issuer: str, subject: str) -> str:
    """Encode the exact issuer and subject pair as an unambiguous provider identity."""
    encoded = json.dumps([issuer, subject], ensure_ascii=False, separators=(",", ":")).encode()
    return "v1." + base64.urlsafe_b64encode(encoded).decode().rstrip("=")


@dataclass(frozen=True)
class _OIDCMetadata:
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    token_auth_methods: tuple[str, ...]


class _OIDCError(Exception):
    """An OIDC protocol or remote-server failure safe to map to a generic login error."""


class OIDCLoginProvider(LoginProvider):
    """Authenticate users through one administrator-configured OIDC issuer."""

    def __init__(self, mass: MusicAssistant, provider_id: str, config: OIDCProviderConfig) -> None:
        """
        Initialize the OIDC login provider.

        :param mass: MusicAssistant instance.
        :param provider_id: Stable provider ID exposed through the authentication API.
        :param config: Issuer, client credentials and requested scopes.
        """
        if (
            not is_valid_oidc_issuer_url(config["issuer"])
            or not is_valid_oidc_client_id(config["client_id"])
            or not config["client_secret"]
            or len(config["client_secret"]) > 4096
            or not is_valid_oidc_scopes(config["scopes"])
        ):
            raise ValueError("Invalid OIDC provider configuration")
        super().__init__(mass, provider_id, config)
        self.issuer = config["issuer"]
        self._allow_http_loopback = _is_loopback_http(self.issuer)
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.scopes = tuple(config["scopes"].split())
        self._metadata: _OIDCMetadata | None = None
        self._metadata_expires_at = 0.0
        self._metadata_lock = asyncio.Lock()
        self._jwks: tuple[dict[str, Any], ...] = ()
        self._jwks_fetched_at = 0.0
        self._jwks_lock = asyncio.Lock()

    @property
    def provider_type(self) -> AuthProviderType:
        """Return the OIDC auth provider type."""
        return AuthProviderType.OIDC

    @property
    def requires_redirect(self) -> bool:
        """Return True because OIDC sign-in uses a browser redirect."""
        return True

    @property
    def fixed_callback_base_url(self) -> str:
        """Return the configured server URL used for the registered OIDC callback."""
        return self.mass.webserver.external_url or self.mass.webserver.base_url

    async def authenticate(self, credentials: dict[str, Any]) -> AuthResult:
        """
        Reject credential-based authentication for this redirect provider.

        :param credentials: Unused.
        """
        return AuthResult(success=False, error="Use the OIDC redirect sign-in")

    async def build_authorization_url(self, pending: PendingLogin) -> str | None:
        """
        Build an authorization request using the issuer's discovered endpoint.

        :param pending: The server-side pending sign-in state.
        """
        if not pending.oidc_nonce:
            return None
        callback_base = self.fixed_callback_base_url
        expected_redirect_uri = (
            f"{callback_base}/auth/callback?provider_id={self.provider_id}"
            if callback_base and _is_valid_callback_base(callback_base)
            else ""
        )
        if pending.redirect_uri != expected_redirect_uri or not _is_valid_redirect_uri(
            pending.redirect_uri
        ):
            return None
        try:
            metadata = await self._get_metadata()
        except _OIDCError:
            self.logger.warning("OIDC discovery is unavailable for the configured issuer")
            return None

        query = dict(parse_qsl(urlsplit(metadata.authorization_endpoint).query))
        query.update(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": pending.redirect_uri,
                "scope": " ".join(self.scopes),
                "state": pending.state,
                "nonce": pending.oidc_nonce,
                "code_challenge": pkce_challenge(pending.idp_code_verifier),
                "code_challenge_method": "S256",
            }
        )
        parsed = urlsplit(metadata.authorization_endpoint)
        return urlunsplit(parsed._replace(query=urlencode(query)))

    async def complete_authorization(
        self, pending: PendingLogin, params: Mapping[str, str]
    ) -> User:
        """
        Exchange and validate an OIDC authorization response for a linked MA user.

        :param pending: The single-use server-side sign-in state.
        :param params: The authorization code returned by the issuer.
        :raises AuthenticationFailed: If the OIDC identity can not authenticate.
        """
        if pending.intent is not AuthTransactionIntent.LOGIN:
            raise AuthenticationFailed("This OIDC transaction is not a sign-in")
        identity = await self.verify_identity(pending, params)
        user = await self.auth_manager.get_user_by_provider_link(
            AuthProviderType.OIDC, identity.provider_user_id, include_disabled=True
        )
        if user is not None:
            if not user.enabled:
                raise AuthenticationFailed(
                    "User account is disabled", translation_key="user_account_disabled"
                )
            return user
        if not self.allow_user_registration:
            raise AuthenticationFailed("This OIDC account is not linked to a Music Assistant user")
        return await self.auth_manager.create_or_get_oidc_user(identity)

    @property
    def allow_user_registration(self) -> bool:
        """Return whether OIDC-specific account provisioning is enabled."""
        config = getattr(self.mass.webserver, "config", None)
        return bool(config and config.get_value(CONF_AUTH_OIDC_ALLOW_REGISTRATION, False))

    async def verify_identity(
        self, pending: PendingLogin, params: Mapping[str, str]
    ) -> VerifiedOIDCIdentity:
        """
        Exchange and validate an OIDC authorization response without resolving its MA account.

        :param pending: The single-use server-side authorization state.
        :param params: The authorization code returned by the issuer.
        :raises AuthenticationFailed: If the OIDC identity can not be verified.
        """
        code = params.get("code")
        if not code or not pending.oidc_nonce:
            raise AuthenticationFailed("The OIDC authorization response is incomplete")
        try:
            metadata = await self._get_metadata()
            token_response = await self._exchange_code(metadata, pending, code)
            id_token = token_response.get("id_token")
            access_token = token_response.get("access_token")
            token_type = token_response.get("token_type")
            if not isinstance(id_token, str) or not isinstance(access_token, str):
                raise _OIDCError  # noqa: TRY301 - mapped to a fixed public error below
            if not access_token or len(access_token) > 16_384:
                raise _OIDCError  # noqa: TRY301 - mapped to a fixed public error below
            if not isinstance(token_type, str) or token_type.lower() != "bearer":
                raise _OIDCError  # noqa: TRY301 - mapped to a fixed public error below

            claims = await self._validate_id_token(metadata, id_token, pending.oidc_nonce)
            subject = claims.get("sub")
            userinfo = await self._get_userinfo(metadata, access_token)
            if (
                not isinstance(subject, str)
                or not subject
                or len(subject) > 255
                or userinfo.get("sub") != subject
            ):
                raise _OIDCError  # noqa: TRY301 - mapped to a fixed public error below
            identity_key = oidc_identity_key(self.issuer, subject)
        except Exception as err:
            self.logger.warning("OIDC authorization failed (%s)", type(err).__name__)
            raise AuthenticationFailed("The OIDC authorization could not be completed") from err
        preferred_username = userinfo.get("preferred_username") or claims.get("preferred_username")
        display_name = userinfo.get("name") or claims.get("name")
        return VerifiedOIDCIdentity(
            provider_user_id=identity_key,
            preferred_username=(
                preferred_username
                if isinstance(preferred_username, str) and len(preferred_username) <= 256
                else None
            ),
            display_name=(
                display_name if isinstance(display_name, str) and len(display_name) <= 128 else None
            ),
        )

    async def _get_metadata(self) -> _OIDCMetadata:
        now = time.monotonic()
        if self._metadata and self._metadata_expires_at > now:
            return self._metadata
        async with self._metadata_lock:
            now = time.monotonic()
            if self._metadata and self._metadata_expires_at > now:
                return self._metadata
            issuer_url = self.issuer.rstrip("/")
            discovery_url = f"{issuer_url}/.well-known/openid-configuration"
            data = await self._request_json("GET", discovery_url)
            if data.get("issuer") != self.issuer:
                raise _OIDCError
            auth_endpoint = _required_endpoint(
                data, "authorization_endpoint", self._allow_http_loopback
            )
            token_endpoint = _required_endpoint(data, "token_endpoint", self._allow_http_loopback)
            userinfo_endpoint = _required_endpoint(
                data, "userinfo_endpoint", self._allow_http_loopback
            )
            jwks_uri = _required_endpoint(data, "jwks_uri", self._allow_http_loopback)
            algorithms = data.get("id_token_signing_alg_values_supported")
            if not isinstance(algorithms, list) or not any(
                algorithm in algorithms for algorithm in ID_TOKEN_ALGORITHMS
            ):
                raise _OIDCError
            response_types = data.get("response_types_supported")
            if not isinstance(response_types, list) or "code" not in response_types:
                raise _OIDCError
            auth_methods = data.get(
                "token_endpoint_auth_methods_supported", ["client_secret_basic"]
            )
            if (
                not isinstance(auth_methods, list)
                or not all(isinstance(method, str) for method in auth_methods)
                or not {"client_secret_basic", "client_secret_post"}.intersection(auth_methods)
            ):
                raise _OIDCError
            self._metadata = _OIDCMetadata(
                authorization_endpoint=auth_endpoint,
                token_endpoint=token_endpoint,
                userinfo_endpoint=userinfo_endpoint,
                jwks_uri=jwks_uri,
                token_auth_methods=tuple(auth_methods),
            )
            self._metadata_expires_at = time.monotonic() + DISCOVERY_TTL
            return self._metadata

    async def _exchange_code(
        self, metadata: _OIDCMetadata, pending: PendingLogin, code: str
    ) -> dict[str, Any]:
        if not _AUTH_CODE_RE.fullmatch(code):
            raise _OIDCError
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": pending.redirect_uri,
            "code_verifier": pending.idp_code_verifier,
            "client_id": self.client_id,
        }
        headers: dict[str, str] = {}
        if "client_secret_basic" in metadata.token_auth_methods:
            credentials = f"{quote_plus(self.client_id)}:{quote_plus(self.client_secret)}".encode()
            headers["Authorization"] = f"Basic {base64.b64encode(credentials).decode()}"
        elif "client_secret_post" in metadata.token_auth_methods:
            form["client_secret"] = self.client_secret
        else:
            raise _OIDCError
        return await self._request_json("POST", metadata.token_endpoint, data=form, headers=headers)

    async def _validate_id_token(
        self, metadata: _OIDCMetadata, token: str, expected_nonce: str
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except (PyJWTError, TypeError, ValueError) as err:
            raise _OIDCError from err
        algorithm = header.get("alg")
        kid = header.get("kid")
        if algorithm not in ID_TOKEN_ALGORITHMS or not isinstance(kid, str) or not kid:
            raise _OIDCError

        key = await self._get_signing_key(metadata, kid, algorithm)
        jwks_fetched_at = self._jwks_fetched_at
        try:
            claims = self._decode_id_token(token, key)
        except InvalidSignatureError:
            keys = await self._get_jwks(metadata, refresh_after=jwks_fetched_at)
            key = _key_for_kid(keys, kid, algorithm)
            try:
                claims = self._decode_id_token(token, key)
            except (PyJWTError, TypeError, ValueError) as err:
                raise _OIDCError from err
        except (PyJWTError, TypeError, ValueError) as err:
            raise _OIDCError from err

        subject = claims.get("sub")
        nonce = claims.get("nonce")
        audience = claims.get("aud")
        authorized_party = claims.get("azp")
        if not isinstance(subject, str) or not subject or len(subject) > 255:
            raise _OIDCError
        if (
            not isinstance(nonce, str)
            or not nonce.isascii()
            or not hmac.compare_digest(nonce, expected_nonce)
        ):
            raise _OIDCError
        if isinstance(audience, list) and len(audience) > 1 and authorized_party != self.client_id:
            raise _OIDCError
        if authorized_party is not None and authorized_party != self.client_id:
            raise _OIDCError
        return claims

    async def _get_userinfo(self, metadata: _OIDCMetadata, access_token: str) -> dict[str, Any]:
        data = await self._request_json(
            "GET",
            metadata.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if not isinstance(data.get("sub"), str):
            raise _OIDCError
        return data

    async def _get_signing_key(self, metadata: _OIDCMetadata, kid: str, algorithm: str) -> Any:
        keys = await self._get_jwks(metadata)
        try:
            return _key_for_kid(keys, kid, algorithm)
        except _OIDCError:
            keys = await self._get_jwks(metadata, refresh_after=self._jwks_fetched_at)
            return _key_for_kid(keys, kid, algorithm)

    async def _get_jwks(
        self, metadata: _OIDCMetadata, *, refresh_after: float | None = None
    ) -> tuple[dict[str, Any], ...]:
        now = time.monotonic()
        if refresh_after is None and self._jwks and self._jwks_fetched_at + JWKS_TTL > now:
            return self._jwks
        async with self._jwks_lock:
            now = time.monotonic()
            if refresh_after is not None and self._jwks_fetched_at > refresh_after:
                return self._jwks
            if refresh_after is None and self._jwks and self._jwks_fetched_at + JWKS_TTL > now:
                return self._jwks
            data = await self._request_json("GET", metadata.jwks_uri)
            keys = data.get("keys")
            if (
                not isinstance(keys, list)
                or not keys
                or not all(isinstance(item, dict) for item in keys)
            ):
                raise _OIDCError
            self._jwks = tuple(keys)
            self._jwks_fetched_at = time.monotonic()
            return self._jwks

    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if not _is_safe_endpoint_url(url, allow_http_loopback=self._allow_http_loopback):
            raise _OIDCError
        try:
            async with self.mass.http_session.request(
                method,
                url,
                data=data,
                headers=headers,
                allow_redirects=False,
                timeout=HTTP_TIMEOUT,
            ) as response:
                status = response.status
                too_large = (
                    response.content_length is not None
                    and response.content_length > MAX_RESPONSE_SIZE
                )
                body = bytearray()
                if status == 200 and not too_large:
                    async for chunk in response.content.iter_chunked(64 * 1024):
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_SIZE:
                            too_large = True
                            break
        except (aiohttp.ClientError, TimeoutError, OSError) as err:
            raise _OIDCError from err
        if status != 200 or too_large:
            raise _OIDCError
        try:
            result = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise _OIDCError from err
        if not isinstance(result, dict):
            raise _OIDCError
        return result

    def _decode_id_token(self, token: str, key: Any) -> dict[str, Any]:
        return jwt.decode(
            token,
            key,
            algorithms=ID_TOKEN_ALGORITHMS,
            audience=self.client_id,
            issuer=self.issuer,
            leeway=30,
            options={
                "require": ["iss", "sub", "aud", "exp", "iat", "nonce"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_sub": True,
            },
        )


def _is_safe_endpoint_url(value: str, *, allow_http_loopback: bool) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if (
            not hostname
            or parsed.username is not None
            or parsed.password is not None
            or "#" in value
            or "\\" in value
            or any(char.isspace() or ord(char) < 33 for char in value)
            or len(value) > 2048
        ):
            return False
        port = parsed.port
    except ValueError:
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http" or not allow_http_loopback:
        return False
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _is_valid_redirect_uri(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return bool(
            parsed.scheme in ("http", "https")
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and "#" not in value
            and "\\" not in value
            and not any(char.isspace() or ord(char) < 33 for char in value)
            and len(value) <= 2048
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        return False


def _is_valid_callback_base(value: str) -> bool:
    return _is_valid_redirect_uri(value) and "?" not in value


def _required_endpoint(data: dict[str, Any], key: str, allow_http_loopback: bool) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not _is_safe_endpoint_url(
        value, allow_http_loopback=allow_http_loopback
    ):
        raise _OIDCError
    return value


def _is_loopback_http(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "http" or not parsed.hostname:
            return False
        if parsed.hostname == "localhost":
            return True
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def _key_for_kid(keys: tuple[dict[str, Any], ...], kid: str, algorithm: str) -> Any:
    matches = [item for item in keys if item.get("kid") == kid]
    if len(matches) != 1:
        raise _OIDCError
    jwk = matches[0]
    if (
        jwk.get("use", "sig") != "sig"
        or (
            "key_ops" in jwk
            and (not isinstance(jwk["key_ops"], list) or "verify" not in jwk["key_ops"])
        )
        or (jwk.get("alg") is not None and jwk.get("alg") != algorithm)
    ):
        raise _OIDCError
    try:
        return jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
    except (PyJWTError, TypeError, ValueError) as err:
        raise _OIDCError from err


_AUTH_CODE_RE = re.compile(r"[A-Za-z0-9._~-]{1,512}")
