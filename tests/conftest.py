from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from secure_mcp_server.audit import AuditLog
from secure_mcp_server.config import Settings
from secure_mcp_server.policy import Policy

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    target = tmp_path / "sandbox"
    shutil.copytree(REPO / "sandbox", target)
    return target


@pytest.fixture
def settings(tmp_path: Path, sandbox: Path) -> Settings:
    return Settings(
        jwt_secret="test-secret-" + "x" * 40,
        policy_path=REPO / "policy.yaml",
        audit_log_path=tmp_path / "audit.log.jsonl",
        sandbox_dir=sandbox,
    )


@pytest.fixture
def policy(settings: Settings) -> Policy:
    return Policy.load(settings.policy_path)


@pytest.fixture
def audit(settings: Settings) -> AuditLog:
    return AuditLog(settings.audit_log_path)
