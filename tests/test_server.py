"""End-to-end: a real MCP client talking to the server, in-process and over streamable HTTP."""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import replace

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from secure_mcp_server.audit import verify_chain
from secure_mcp_server.auth import Identity, issue_token
from secure_mcp_server.server import build_server

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _text(result) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)


async def test_read_only_agent_can_read_but_not_write(settings, policy, audit):
    reader = Identity("research-agent", "research-agent", frozenset({"notes:read"}))
    server = build_server(settings, policy=policy, audit=audit, stdio_identity=reader)

    async with Client(server) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"search_notes", "read_note", "create_ticket", "delete_ticket", "whoami"} <= names

        found = await client.call_tool("search_notes", {"query": "runbook"})
        assert not found.is_error and "runbook-mcp-onboarding.md" in _text(found)

        denied = await client.call_tool("create_ticket", {"title": "hello"})
        assert denied.is_error and "access denied" in _text(denied)

        escape = await client.call_tool("read_note", {"path": "../../etc/passwd"})
        assert escape.is_error

    entries = [json.loads(line) for line in audit.path.read_text().splitlines()]
    assert [e["decision"] for e in entries] == ["allow", "deny", "allow"]
    assert entries[1]["tool"] == "create_ticket" and entries[1]["subject"] == "research-agent"
    assert entries[2]["outcome"] == "error"
    assert verify_chain(audit.path)[0]


async def test_admin_agent_full_ticket_lifecycle(settings, policy, audit):
    admin = Identity("ops-agent", "ops-agent", frozenset({"tickets:write", "tickets:admin"}))
    server = build_server(settings, policy=policy, audit=audit, stdio_identity=admin)
    async with Client(server) as client:
        created = await client.call_tool("create_ticket", {"title": "Rotate keys", "body": "q3"})
        assert not created.is_error
        ticket_id = created.structured_content["id"]
        deleted = await client.call_tool("delete_ticket", {"ticket_id": ticket_id})
        assert not deleted.is_error


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def http_server(settings, policy, audit):
    port = _free_port()
    cfg = replace(settings, port=port, public_url=f"http://127.0.0.1:{port}")
    app = build_server(cfg, policy=policy, audit=audit, http=True).streamable_http_app()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield cfg
    server.should_exit = True
    thread.join(timeout=5)


async def test_http_rejects_missing_and_forged_tokens(http_server):
    url = f"{http_server.public_url}/mcp"
    async with httpx2.AsyncClient() as http:
        assert (await http.post(url, json={})).status_code == 401
        forged = issue_token(replace(http_server, jwt_secret="z" * 48), "intruder", ["tickets:admin"])
        resp = await http.post(url, json={}, headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401


async def test_http_scoped_token_end_to_end(http_server, audit):
    token = issue_token(http_server, "research-agent", ["notes:read"])
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"})
    transport = streamable_http_client(f"{http_server.public_url}/mcp", http_client=http)
    async with http, Client(transport) as client:
        who = await client.call_tool("whoami", {})
        assert not who.is_error and who.structured_content["subject"] == "research-agent"
        denied = await client.call_tool("delete_ticket", {"ticket_id": "T-1"})
        assert denied.is_error
    subjects = {json.loads(line)["subject"] for line in audit.path.read_text().splitlines()}
    assert subjects == {"research-agent"}
