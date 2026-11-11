"""Agent identity: issuing and verifying short-lived JWTs.

Every caller (a person or an AI agent) gets its own token. The token's `sub` names the agent and
its `scope` claim lists exactly which tool scopes it may use, so access is decided per identity
rather than per server.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt
from mcp.server.auth.provider import AccessToken

from .config import Settings

MAX_TOKEN_LIFETIME_SECONDS = 60 * 60  # tokens longer-lived than an hour are refused


@dataclass(frozen=True)
class Identity:
    """Who is calling, as established by a verified token."""

    subject: str
    client_id: str
    scopes: frozenset[str]
    token_id: str | None = None

    @classmethod
    def from_access_token(cls, token: AccessToken) -> "Identity":
        claims = token.claims or {}
        return cls(
            subject=token.subject or token.client_id,
            client_id=token.client_id,
            scopes=frozenset(token.scopes),
            token_id=claims.get("jti"),
        )


def issue_token(
    settings: Settings,
    subject: str,
    scopes: list[str],
    *,
    client_id: str | None = None,
    ttl_seconds: int = 900,
) -> str:
    """Issue a signed token for one agent. Intended for local development and tests.

    In production, tokens come from your identity provider (Entra ID, Okta, Auth0, ...); the
    verifier below only needs the matching key, issuer and audience.
    """
    if ttl_seconds > MAX_TOKEN_LIFETIME_SECONDS:
        raise ValueError(f"ttl_seconds must be <= {MAX_TOKEN_LIFETIME_SECONDS}")
    now = int(time.time())
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": subject,
        "client_id": client_id or subject,
        "scope": " ".join(sorted(set(scopes))),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(settings: Settings, token: str) -> AccessToken | None:
    """Validate signature, issuer, audience and expiry. Returns None for any invalid token."""
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],  # pinned: never trust the token's own `alg`
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            leeway=30,
        )
    except jwt.PyJWTError:
        return None

    if claims["exp"] - claims["iat"] > MAX_TOKEN_LIFETIME_SECONDS:
        return None

    scopes = [s for s in str(claims.get("scope", "")).split() if s]
    return AccessToken(
        token=token,
        client_id=str(claims.get("client_id", claims["sub"])),
        scopes=scopes,
        expires_at=int(claims["exp"]),
        resource=settings.jwt_audience,
        subject=str(claims["sub"]),
        claims={k: claims[k] for k in ("iss", "jti", "iat") if k in claims},
    )


class JwtTokenVerifier:
    """Plugs into the MCP SDK's bearer-auth middleware for the HTTP transport."""

    def __init__(self, settings: Settings):
        self._settings = settings

    async def verify_token(self, token: str) -> AccessToken | None:
        return decode_token(self._settings, token)
