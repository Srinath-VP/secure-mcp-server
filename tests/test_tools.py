from __future__ import annotations

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from secure_mcp_server import tools


def test_read_note_inside_sandbox(sandbox):
    assert "Runbook" in tools.read_note(sandbox, "runbook-mcp-onboarding.md")


@pytest.mark.parametrize("path", ["../secrets.txt", "../../etc/passwd", "a/../../x", "/etc/passwd", "a\x00b"])
def test_path_escapes_are_blocked(sandbox, path):
    with pytest.raises(ToolError):
        tools.read_note(sandbox, path)


def test_symlink_out_of_sandbox_is_blocked(sandbox, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    (sandbox / "link.md").symlink_to(secret)
    with pytest.raises(ToolError, match="escapes"):
        tools.read_note(sandbox, "link.md")


def test_search_skips_symlinked_files_outside_sandbox(sandbox, tmp_path):
    secret = tmp_path / "secret.md"
    secret.write_text("runbook leak")
    (sandbox / "leak.md").symlink_to(secret)
    assert "leak.md" not in tools.search_notes(sandbox, "runbook")


def test_input_limits():
    with pytest.raises(ToolError):
        tools.validate_ticket("x" * 500, "")
    with pytest.raises(ToolError):
        tools.validate_ticket_id("T-1; DROP TABLE tickets")
