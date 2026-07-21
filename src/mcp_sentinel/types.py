"""Core data types shared across MCP Sentinel.

These mirror the shapes that flow across the Model Context Protocol (MCP):
tool definitions announced by a server, tool calls issued by an agent, and the
results a server returns. Sentinel inspects all three.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity so thresholds can be compared numerically."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


class Action(enum.Enum):
    """What Sentinel decided to do with a message."""

    ALLOW = "allow"
    SANITIZE = "sanitize"  # forward, but with injected spans neutralized
    BLOCK = "block"        # refuse: the agent never sees the payload


class Source(enum.Enum):
    """Where a finding was observed. Tool descriptions are a real attack
    surface ("tool poisoning"): a server can smuggle instructions into the
    metadata an agent reads before it ever calls the tool."""

    TOOL_DESCRIPTION = "tool_description"
    ARGUMENTS = "arguments"
    TOOL_RESULT = "tool_result"


@dataclass(frozen=True)
class ToolDef:
    """A tool as advertised by an MCP server."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    """An invocation issued by the agent toward a tool."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""
    session_id: str = "default"


@dataclass(frozen=True)
class ToolResult:
    """The content a server returns for a call. `text` is the flattened,
    agent-visible payload — the part that can carry an injection."""

    text: str
    call_id: str = ""
    session_id: str = "default"
    is_error: bool = False


@dataclass(frozen=True)
class Finding:
    """A single suspicious observation."""

    rule_id: str
    severity: Severity
    source: Source
    message: str
    span: str = ""  # the matched substring, truncated for logging

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "source": self.source.value,
            "message": self.message,
            "span": self.span,
        }


@dataclass(frozen=True)
class Decision:
    """The outcome Sentinel returns for an inspected message."""

    action: Action
    findings: tuple[Finding, ...] = ()
    reason: str = ""
    # Present when a policy rule (not the detector) drove the decision.
    policy_rule: str | None = None
    # For SANITIZE decisions: the cleaned text safe to forward.
    sanitized_text: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "policy_rule": self.policy_rule,
            "max_severity": self.max_severity.name,
            "findings": [f.to_dict() for f in self.findings],
        }
