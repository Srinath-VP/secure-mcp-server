"""Runtime settings, read from environment variables so nothing secret lives in code."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    jwt_issuer: str = "secure-mcp-dev"
    jwt_audience: str = "secure-mcp-server"
    jwt_algorithm: str = "HS256"
    policy_path: Path = Path("policy.yaml")
    audit_log_path: Path = Path("audit.log.jsonl")
    sandbox_dir: Path = Path("sandbox")
    host: str = "127.0.0.1"
    port: int = 8000
    public_url: str = "http://127.0.0.1:8000"
    # Token used to identify the caller on the stdio transport, where there is no HTTP header.
    stdio_token: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> "Settings":
        secret = os.environ.get("MCP_JWT_SECRET")
        if not secret or len(secret) < 32:
            raise RuntimeError(
                "MCP_JWT_SECRET must be set to a random value of at least 32 characters "
                "(for example: python -c 'import secrets; print(secrets.token_urlsafe(48))')."
            )
        host = os.environ.get("MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("MCP_PORT", "8000"))
        return cls(
            jwt_secret=secret,
            jwt_issuer=os.environ.get("MCP_JWT_ISSUER", "secure-mcp-dev"),
            jwt_audience=os.environ.get("MCP_JWT_AUDIENCE", "secure-mcp-server"),
            policy_path=Path(os.environ.get("MCP_POLICY_PATH", "policy.yaml")),
            audit_log_path=Path(os.environ.get("MCP_AUDIT_LOG", "audit.log.jsonl")),
            sandbox_dir=Path(os.environ.get("MCP_SANDBOX_DIR", "sandbox")),
            host=host,
            port=port,
            public_url=os.environ.get("MCP_PUBLIC_URL", f"http://{host}:{port}"),
            stdio_token=os.environ.get("MCP_AGENT_TOKEN"),
        )
