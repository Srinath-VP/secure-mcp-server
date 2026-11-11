# Runbook: onboarding a new MCP server

1. Pick the transport: stdio for local tools, streamable HTTP for shared services.
2. Issue the agent its own token with only the scopes it needs.
3. Add each tool to policy.yaml with exactly one required scope.
4. Run `verify-audit` after the first calls to confirm entries are being chained.
