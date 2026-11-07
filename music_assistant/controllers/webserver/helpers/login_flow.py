"""Shared building blocks of the redirect based sign-in flow."""

from __future__ import annotations

import hmac
import re
import secrets
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

from music_assistant_models.errors import RateLimited

from music_assistant.helpers.pkce import pkce_challenge

# Seconds a sign-in may take, and how many may be pending at once
PENDING_LOGIN_TTL: Final = 600
MAX_PENDING_LOGINS: Final = 100
# URL scheme of the Music Assistant mobile app
NATIVE_APP_SCHEME: Final = "musicassistant://"
# base64url (unpadded) SHA-256 digest, the only code challenge form accepted
PKCE_CHALLENGE_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")
# a PKCE code verifier (RFC 7636: 43 to 128 unreserved characters)
PKCE_VERIFIER_RE: Final = re.compile(r"[A-Za-z0-9._~-]{43,128}")
# an authorization code as identity providers issue them (URL safe characters only)
AUTH_CODE_RE: Final = re.compile(r"[A-Za-z0-9._~-]{1,512}")

type RedirectTarget = Literal["server", "app"]


class AuthTransport(StrEnum):
    """How a client reaches the server."""

    DIRECT = "direct"  # browser or app talks to the server over HTTP(S)
    REMOTE = "remote"  # remote app over the WebRTC data channel
    INGRESS = "ingress"  # Home Assistant ingress (already signed in)


class AuthTransactionIntent(StrEnum):
    """Purpose of a pending authorization transaction."""

    LOGIN = "login"
    LINK = "link"


@dataclass(frozen=True)
class PendingLinkContext:
    """Session and browser binding fields for a pending account-linking transaction."""

    initiating_user_id: str
    initiating_session_hash: str
    callback_binding_hash: str


@dataclass
class PendingLogin:
    """An authorization transaction that waits for the browser to return."""

    state: str  # "w.<token>" (web), "n.<token>" (native app) or "l.<token>" (link)
    provider_id: str
    transport: AuthTransport
    redirect_uri: str  # exactly what was sent to the identity provider
    redirect_target: RedirectTarget
    expires_at: float  # monotonic
    idp_code_verifier: str
    oidc_nonce: str | None = None
    return_url: str | None = None
    client_code_challenge: str | None = None  # S256 only
    intent: AuthTransactionIntent = AuthTransactionIntent.LOGIN
    initiating_user_id: str | None = None
    initiating_session_hash: str | None = None
    callback_binding_hash: str | None = None


class PendingLoginStore:
    """In-memory store of pending authorization transactions, each usable once."""

    def __init__(self) -> None:
        """Initialize an empty store."""
        self._pending: dict[str, PendingLogin] = {}

    def start(
        self,
        provider_id: str,
        transport: AuthTransport,
        redirect_uri: str,
        idp_code_verifier: str,
        *,
        redirect_target: RedirectTarget = "server",
        return_url: str | None = None,
        client_code_challenge: str | None = None,
        intent: AuthTransactionIntent = AuthTransactionIntent.LOGIN,
        link_context: PendingLinkContext | None = None,
    ) -> PendingLogin:
        """
        Start an authorization transaction and return it, with a new state.

        :param provider_id: The id of the login provider the sign-in is for.
        :param transport: How the client that starts the sign-in reaches the server.
        :param redirect_uri: The callback URL sent to the identity provider.
        :param idp_code_verifier: The PKCE code verifier for the identity provider.
        :param redirect_target: Whether the browser returns to the server or the remote app.
        :param return_url: The validated URL the client returns to after signing in.
        :param client_code_challenge: The client's PKCE S256 code challenge, if any.
        :param intent: The purpose of this authorization transaction.
        :param link_context: Session and browser binding values for account linking.
        :raises RateLimited: If too many sign-ins are pending.
        """
        now = time.monotonic()
        # anyone can start a sign-in without logging in, so abandoned ones expire and new
        # ones are refused while the limit is reached, keeping the pending ones valid
        for expired in [key for key, entry in self._pending.items() if entry.expires_at <= now]:
            del self._pending[expired]
        if len(self._pending) >= MAX_PENDING_LOGINS:
            raise RateLimited("Too many sign-ins are pending")
        prefix = (
            "l"
            if intent is AuthTransactionIntent.LINK
            else "n"
            if return_url and return_url.startswith(NATIVE_APP_SCHEME)
            else "w"
        )
        pending = PendingLogin(
            state=f"{prefix}.{secrets.token_urlsafe(32)}",
            provider_id=provider_id,
            transport=transport,
            redirect_uri=redirect_uri,
            redirect_target=redirect_target,
            expires_at=now + PENDING_LOGIN_TTL,
            idp_code_verifier=idp_code_verifier,
            oidc_nonce=secrets.token_urlsafe(32),
            return_url=return_url,
            client_code_challenge=client_code_challenge,
            intent=intent,
            initiating_user_id=link_context.initiating_user_id if link_context else None,
            initiating_session_hash=(
                link_context.initiating_session_hash if link_context else None
            ),
            callback_binding_hash=link_context.callback_binding_hash if link_context else None,
        )
        self._pending[pending.state] = pending
        return pending

    def pop(self, state: str) -> PendingLogin | None:
        """
        Remove a pending sign-in and return it, unless it is unknown or expired.

        :param state: The state of the sign-in.
        """
        pending = self._pending.pop(state, None)
        if pending is None or pending.expires_at <= time.monotonic():
            return None
        return pending


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """
    Return whether a code verifier matches a PKCE S256 code challenge.

    :param code_verifier: The code verifier presented by the client.
    :param code_challenge: The code challenge the client started the sign-in with.
    """
    if not PKCE_VERIFIER_RE.fullmatch(code_verifier):
        return False
    return hmac.compare_digest(pkce_challenge(code_verifier), code_challenge)
