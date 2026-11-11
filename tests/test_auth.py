from __future__ import annotations

import time
from dataclasses import replace

import jwt
import pytest

from secure_mcp_server.auth import Identity, decode_token, issue_token


def test_valid_token_carries_identity_and_scopes(settings):
    token = issue_token(settings, "research-agent", ["notes:read"])
    access = decode_token(settings, token)
    assert access is not None
    identity = Identity.from_access_token(access)
    assert identity.subject == "research-agent"
    assert identity.scopes == {"notes:read"}
    assert identity.token_id


def test_wrong_audience_is_rejected(settings):
    other = replace(settings, jwt_audience="some-other-server")
    token = issue_token(other, "agent", ["notes:read"])
    assert decode_token(settings, token) is None


def test_wrong_signing_key_is_rejected(settings):
    forged = replace(settings, jwt_secret="attacker-" + "y" * 40)
    token = issue_token(forged, "agent", ["tickets:admin"])
    assert decode_token(settings, token) is None


def test_expired_token_is_rejected(settings):
    now = int(time.time())
    token = jwt.encode(
        {"iss": settings.jwt_issuer, "aud": settings.jwt_audience, "sub": "agent",
         "scope": "notes:read", "iat": now - 600, "exp": now - 300},
        settings.jwt_secret, algorithm="HS256",
    )
    assert decode_token(settings, token) is None


def test_unsigned_alg_none_token_is_rejected(settings):
    now = int(time.time())
    token = jwt.encode(
        {"iss": settings.jwt_issuer, "aud": settings.jwt_audience, "sub": "agent",
         "scope": "tickets:admin", "iat": now, "exp": now + 60},
        key=None, algorithm="none",
    )
    assert decode_token(settings, token) is None


def test_long_lived_tokens_are_refused(settings):
    with pytest.raises(ValueError):
        issue_token(settings, "agent", ["notes:read"], ttl_seconds=24 * 3600)

    now = int(time.time())
    token = jwt.encode(
        {"iss": settings.jwt_issuer, "aud": settings.jwt_audience, "sub": "agent",
         "scope": "notes:read", "iat": now, "exp": now + 7 * 24 * 3600},
        settings.jwt_secret, algorithm="HS256",
    )
    assert decode_token(settings, token) is None
