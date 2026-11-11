"""Least-privilege tool policy.

The policy file maps each tool to the scope a caller must hold. Anything not listed is denied,
so adding a new tool to the server does nothing until someone grants it on purpose.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .auth import Identity


class PolicyError(Exception):
    """The policy file is missing or malformed."""


class AccessDenied(Exception):
    """The caller's token does not grant the scope this tool needs."""


@dataclass(frozen=True)
class ToolRule:
    required_scope: str
    destructive: bool = False


@dataclass(frozen=True)
class Policy:
    rules: dict[str, ToolRule]

    @classmethod
    def load(cls, path: Path) -> "Policy":
        if not path.exists():
            raise PolicyError(f"policy file not found: {path}")
        data = yaml.safe_load(path.read_text()) or {}
        tools = data.get("tools")
        if not isinstance(tools, dict) or not tools:
            raise PolicyError("policy must define a non-empty 'tools' mapping")
        rules: dict[str, ToolRule] = {}
        for name, rule in tools.items():
            if not isinstance(rule, dict) or not rule.get("scope"):
                raise PolicyError(f"tool '{name}' must declare a 'scope'")
            rules[name] = ToolRule(
                required_scope=str(rule["scope"]),
                destructive=bool(rule.get("destructive", False)),
            )
        return cls(rules=rules)

    def authorize(self, identity: Identity | None, tool: str) -> ToolRule:
        """Return the rule if the call is allowed; raise AccessDenied otherwise."""
        if identity is None:
            raise AccessDenied("no authenticated identity")
        rule = self.rules.get(tool)
        if rule is None:
            raise AccessDenied(f"tool '{tool}' is not in the policy (deny by default)")
        if rule.required_scope not in identity.scopes:
            raise AccessDenied(f"tool '{tool}' requires scope '{rule.required_scope}'")
        return rule
