"""Wires the tools to the controls: identity -> policy check -> tool -> audit entry.

Every tool goes through `_guard`, so there is exactly one code path where access is decided and
recorded. A tool cannot run without a verified identity, a matching scope and an audit line.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import tools
from .audit import AuditLog
from .auth import Identity, JwtTokenVerifier, decode_token
from .config import Settings
from .policy import AccessDenied, Policy

T = TypeVar("T")

INSTRUCTIONS = (
    "Notes and ticket tools behind per-agent JWT scopes. Calls outside your token's scopes are "
    "refused and every call is audited."
)


class Guard:
    """Resolves the caller, enforces the policy and writes the audit entry."""

    def __init__(self, policy: Policy, audit: AuditLog, stdio_identity: Identity | None = None):
        self.policy = policy
        self.audit = audit
        self.stdio_identity = stdio_identity

    def current_identity(self) -> Identity | None:
        token = get_access_token()  # set by the SDK's bearer middleware on HTTP requests
        if token is not None:
            return Identity.from_access_token(token)
        return self.stdio_identity

    def run(self, tool: str, arguments: dict[str, Any], fn: Callable[[Identity], T]) -> T:
        identity = self.current_identity()
        started = time.perf_counter()
        try:
            self.policy.authorize(identity, tool)
        except AccessDenied as exc:
            self.audit.record(
                identity=identity, tool=tool, arguments=arguments, decision="deny",
                outcome="denied", duration_ms=(time.perf_counter() - started) * 1000,
                detail=str(exc),
            )
            raise ToolError(f"access denied: {exc}") from None

        assert identity is not None  # authorize() refuses a missing identity
        try:
            result = fn(identity)
        except ToolError as exc:
            self.audit.record(
                identity=identity, tool=tool, arguments=arguments, decision="allow",
                outcome="error", duration_ms=(time.perf_counter() - started) * 1000,
                detail=str(exc),
            )
            raise
        except Exception:
            self.audit.record(
                identity=identity, tool=tool, arguments=arguments, decision="allow",
                outcome="error", duration_ms=(time.perf_counter() - started) * 1000,
                detail="internal error",
            )
            raise ToolError("internal error") from None  # never leak stack traces to the model

        self.audit.record(
            identity=identity, tool=tool, arguments=arguments, decision="allow",
            outcome="ok", duration_ms=(time.perf_counter() - started) * 1000,
        )
        return result


def build_server(
    settings: Settings,
    *,
    policy: Policy | None = None,
    audit: AuditLog | None = None,
    stdio_identity: Identity | None = None,
    http: bool = False,
) -> MCPServer:
    policy = policy or Policy.load(settings.policy_path)
    audit = audit or AuditLog(settings.audit_log_path)
    sandbox = Path(settings.sandbox_dir)
    store = tools.TicketStore()
    guard = Guard(policy, audit, stdio_identity)

    auth_kwargs: dict[str, Any] = {}
    if http:
        auth_kwargs = {
            "token_verifier": JwtTokenVerifier(settings),
            "auth": AuthSettings(
                issuer_url=settings.public_url,
                resource_server_url=f"{settings.public_url}/mcp",
                validate_token_resource=False,  # our verifier checks `aud` itself
            ),
        }

    server = MCPServer(
        name="secure-mcp-server", instructions=INSTRUCTIONS, version="0.1.0", **auth_kwargs
    )

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def search_notes(query: str) -> list[str]:
        """Find notes in the sandbox whose text contains the query. Returns relative paths."""
        return guard.run("search_notes", {"query": query},
                         lambda _: tools.search_notes(sandbox, query))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def read_note(path: str) -> str:
        """Read one note from the sandbox by its relative path."""
        return guard.run("read_note", {"path": path}, lambda _: tools.read_note(sandbox, path))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    def create_ticket(title: str, body: str = "") -> dict[str, str]:
        """Open a ticket owned by the calling agent."""
        def _create(identity: Identity) -> dict[str, str]:
            clean_title, clean_body = tools.validate_ticket(title, body)
            return store.create(clean_title, clean_body, owner=identity.subject)
        return guard.run("create_ticket", {"title": title, "body": body}, _create)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
    def delete_ticket(ticket_id: str) -> str:
        """Delete a ticket. Requires the admin scope."""
        def _delete(_: Identity) -> str:
            store.delete(tools.validate_ticket_id(ticket_id))
            return f"deleted {ticket_id}"
        return guard.run("delete_ticket", {"ticket_id": ticket_id}, _delete)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def whoami() -> dict[str, Any]:
        """Show which identity and scopes this connection is using."""
        def _who(identity: Identity) -> dict[str, Any]:
            return {"subject": identity.subject, "client_id": identity.client_id,
                    "scopes": sorted(identity.scopes)}
        return guard.run("whoami", {}, _who)

    server.guard = guard  # type: ignore[attr-defined]  # exposed for tests
    return server


def stdio_identity_from_settings(settings: Settings) -> Identity:
    """On stdio there is no Authorization header, so the agent's token comes from the environment."""
    if not settings.stdio_token:
        raise RuntimeError("MCP_AGENT_TOKEN must hold a valid token for the stdio transport")
    access = decode_token(settings, settings.stdio_token)
    if access is None:
        raise RuntimeError("MCP_AGENT_TOKEN is invalid or expired")
    return Identity.from_access_token(access)
