from __future__ import annotations

import json

import pytest

from secure_mcp_server.audit import redact_arguments, verify_chain
from secure_mcp_server.auth import Identity
from secure_mcp_server.policy import AccessDenied

reader = Identity(subject="reader", client_id="reader", scopes=frozenset({"notes:read"}))


def test_policy_allows_granted_scope(policy):
    assert policy.authorize(reader, "search_notes").required_scope == "notes:read"


@pytest.mark.parametrize("tool", ["create_ticket", "delete_ticket"])
def test_policy_denies_missing_scope(policy, tool):
    with pytest.raises(AccessDenied):
        policy.authorize(reader, tool)


def test_policy_denies_unknown_tools_by_default(policy):
    admin = Identity("admin", "admin", frozenset({"tickets:admin", "notes:read"}))
    with pytest.raises(AccessDenied, match="deny by default"):
        policy.authorize(admin, "run_shell")


def test_policy_denies_missing_identity(policy):
    with pytest.raises(AccessDenied):
        policy.authorize(None, "search_notes")


def test_audit_redacts_sensitive_and_fingerprints_values():
    out = redact_arguments({"api_key": "sk-live-123", "query": "payroll", "limit": 5})
    assert out["api_key"] == "[REDACTED]"
    assert out["query"].startswith("sha256:") and "payroll" not in out["query"]
    assert out["limit"] == 5


def _write_entries(audit, n=3):
    for i in range(n):
        audit.record(identity=reader, tool="search_notes", arguments={"query": f"q{i}"},
                     decision="allow", outcome="ok", duration_ms=1.0)


def test_audit_chain_verifies(audit):
    _write_entries(audit)
    assert verify_chain(audit.path) == (True, 3, None)


def test_audit_detects_edited_entry(audit):
    _write_entries(audit)
    lines = audit.path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["decision"] = "deny"  # someone rewrites history
    lines[1] = json.dumps(entry, sort_keys=True)
    audit.path.write_text("\n".join(lines) + "\n")
    ok, _, problem = verify_chain(audit.path)
    assert not ok and "modified" in problem


def test_audit_detects_deleted_entry(audit):
    _write_entries(audit)
    lines = audit.path.read_text().splitlines()
    audit.path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _, problem = verify_chain(audit.path)
    assert not ok and "chain broken" in problem
