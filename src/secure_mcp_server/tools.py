"""The demo tools. They are deliberately ordinary; the point is the controls around them.

Each tool validates its own inputs (sizes, characters, paths) instead of trusting the model,
because tool arguments are written by an LLM and may carry prompt-injected content.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from itertools import count
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError

MAX_QUERY_LEN = 200
MAX_TITLE_LEN = 120
MAX_BODY_LEN = 4_000
MAX_FILE_BYTES = 256 * 1024
TICKET_ID = re.compile(r"^T-\d{1,8}$")


@dataclass
class TicketStore:
    """In-memory store so the demo needs no database."""

    tickets: dict[str, dict[str, str]] = field(default_factory=dict)
    _ids: count = field(default_factory=lambda: count(1))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def create(self, title: str, body: str, owner: str) -> dict[str, str]:
        with self._lock:
            ticket_id = f"T-{next(self._ids)}"
            ticket = {"id": ticket_id, "title": title, "body": body, "owner": owner}
            self.tickets[ticket_id] = ticket
            return ticket

    def delete(self, ticket_id: str) -> None:
        with self._lock:
            if ticket_id not in self.tickets:
                raise ToolError(f"ticket {ticket_id} not found")
            del self.tickets[ticket_id]


def resolve_in_sandbox(sandbox: Path, relative_path: str) -> Path:
    """Resolve a caller-supplied path, refusing anything that escapes the sandbox.

    Blocks `../` traversal, absolute paths, symlinks pointing outside, and null bytes.
    """
    if not relative_path or "\x00" in relative_path:
        raise ToolError("invalid path")
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ToolError("absolute paths are not allowed")
    root = sandbox.resolve()
    target = (root / candidate).resolve()
    if not target.is_relative_to(root):
        raise ToolError("path escapes the sandbox")
    return target


def search_notes(sandbox: Path, query: str) -> list[str]:
    query = query.strip()
    if not query or len(query) > MAX_QUERY_LEN:
        raise ToolError(f"query must be 1-{MAX_QUERY_LEN} characters")
    needle = query.lower()
    root = sandbox.resolve()
    hits: list[str] = []
    for path in sorted(root.rglob("*.md")):
        if not path.resolve().is_relative_to(root) or path.stat().st_size > MAX_FILE_BYTES:
            continue
        if needle in path.read_text(errors="ignore").lower():
            hits.append(str(path.relative_to(root)))
    return hits


def read_note(sandbox: Path, path: str) -> str:
    target = resolve_in_sandbox(sandbox, path)
    if not target.is_file():
        raise ToolError("file not found")
    if target.stat().st_size > MAX_FILE_BYTES:
        raise ToolError("file too large")
    return target.read_text(errors="replace")


def validate_ticket(title: str, body: str) -> tuple[str, str]:
    title, body = title.strip(), body.strip()
    if not title or len(title) > MAX_TITLE_LEN:
        raise ToolError(f"title must be 1-{MAX_TITLE_LEN} characters")
    if len(body) > MAX_BODY_LEN:
        raise ToolError(f"body must be at most {MAX_BODY_LEN} characters")
    return title, body


def validate_ticket_id(ticket_id: str) -> str:
    if not TICKET_ID.match(ticket_id):
        raise ToolError("ticket_id must look like T-123")
    return ticket_id
