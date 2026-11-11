"""Command line: run the server, mint dev tokens, verify the audit chain.

    python -m secure_mcp_server serve --transport stdio
    python -m secure_mcp_server serve --transport http
    python -m secure_mcp_server token --sub research-agent --scope notes:read
    python -m secure_mcp_server verify-audit
"""

from __future__ import annotations

import argparse
import sys

from .audit import verify_chain
from .auth import issue_token
from .config import Settings
from .server import build_server, stdio_identity_from_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secure-mcp-server")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the MCP server")
    serve.add_argument("--transport", choices=["stdio", "http"], default="stdio")

    token = sub.add_parser("token", help="issue a development token for one agent")
    token.add_argument("--sub", required=True, help="agent identity, e.g. research-agent")
    token.add_argument("--scope", action="append", default=[], help="repeat for each scope")
    token.add_argument("--ttl", type=int, default=900, help="lifetime in seconds (max 3600)")

    sub.add_parser("verify-audit", help="check the audit log hash chain")

    args = parser.parse_args(argv)
    settings = Settings.from_env()

    if args.command == "token":
        print(issue_token(settings, args.sub, args.scope, ttl_seconds=args.ttl))
        return 0

    if args.command == "verify-audit":
        ok, n, problem = verify_chain(settings.audit_log_path)
        print(f"{'OK' if ok else 'TAMPERED'}: {n} entries verified" + (f" - {problem}" if problem else ""))
        return 0 if ok else 1

    if args.transport == "stdio":
        server = build_server(settings, stdio_identity=stdio_identity_from_settings(settings))
        server.run("stdio")
    else:
        import uvicorn

        server = build_server(settings, http=True)
        uvicorn.run(server.streamable_http_app(host=settings.host), host=settings.host, port=settings.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
