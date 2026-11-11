"""Tamper-evident audit log.

Every tool call, allowed or denied, is appended as one JSON line. Each entry stores the hash of
the previous entry, so deleting or editing a line breaks the chain and `verify_chain` reports it.
Arguments are never logged raw: sensitive keys are redacted and values are fingerprinted.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .auth import Identity

GENESIS_HASH = "0" * 64
SENSITIVE_KEYS = ("password", "secret", "token", "api_key", "apikey", "authorization", "body")


def _fingerprint(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, default=str).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Keep argument names for context; replace values with redaction markers or fingerprints."""
    redacted: dict[str, Any] = {}
    for key, value in arguments.items():
        if any(marker in key.lower() for marker in SENSITIVE_KEYS):
            redacted[key] = "[REDACTED]"
        elif isinstance(value, (int, float, bool)) or value is None:
            redacted[key] = value
        else:
            redacted[key] = _fingerprint(value)
    return redacted


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self.path.open() as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def record(
        self,
        *,
        identity: Identity | None,
        tool: str,
        arguments: dict[str, Any],
        decision: str,
        outcome: str,
        duration_ms: float,
        detail: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "id": uuid.uuid4().hex,
                "ts": round(time.time(), 3),
                "subject": identity.subject if identity else None,
                "client_id": identity.client_id if identity else None,
                "token_id": identity.token_id if identity else None,
                "tool": tool,
                "arguments": redact_arguments(arguments),
                "decision": decision,  # "allow" | "deny"
                "outcome": outcome,  # "ok" | "error" | "denied"
                "duration_ms": round(duration_ms, 2),
                "detail": detail,
                "prev_hash": self._last_hash,
            }
            entry["hash"] = _entry_hash(entry)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
            self._last_hash = entry["hash"]
            return entry


def verify_chain(path: Path) -> tuple[bool, int, str | None]:
    """Check every entry's hash and link. Returns (ok, entries_checked, problem)."""
    if not path.exists():
        return True, 0, None
    prev = GENESIS_HASH
    count = 0
    with path.open() as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False, count, f"line {lineno}: chain broken (entry removed or reordered)"
            if _entry_hash(entry) != entry.get("hash"):
                return False, count, f"line {lineno}: entry was modified"
            prev = entry["hash"]
            count += 1
    return True, count, None
