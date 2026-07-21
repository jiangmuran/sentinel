"""MCP Sentinel — a security & reliability layer for the Model Context Protocol.

Sits between an AI agent and the (untrusted) MCP servers it talks to, and:
  * detects prompt injection in tool descriptions and tool results,
  * enforces least-privilege policy on tool calls,
  * records every decision to a replayable audit log.

Public API is intentionally small; see `Sentinel` for the entry point.
"""

from .actions import ActionClass, ActionClassifier
from .audit import AuditLog
from .detector import (
    CallableDetector,
    CompositeDetector,
    SignatureDetector,
    strip_obfuscation,
)
from .provenance import ProvenanceTracker, Taint
from .policy import Policy, PolicyEngine, ToolRule
from .sentinel import Sentinel, SentinelConfig
from .types import (
    Action,
    Decision,
    Finding,
    Severity,
    Source,
    ToolCall,
    ToolDef,
    ToolResult,
)

__version__ = "0.1.0"

__all__ = [
    "Sentinel",
    "SentinelConfig",
    "SignatureDetector",
    "CompositeDetector",
    "CallableDetector",
    "strip_obfuscation",
    "ProvenanceTracker",
    "Taint",
    "ActionClassifier",
    "ActionClass",
    "Policy",
    "PolicyEngine",
    "ToolRule",
    "AuditLog",
    "Action",
    "Decision",
    "Finding",
    "Severity",
    "Source",
    "ToolCall",
    "ToolDef",
    "ToolResult",
    "__version__",
]
