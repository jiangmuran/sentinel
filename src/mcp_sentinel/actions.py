"""Classify the *blast radius* of a tool call.

Not every action deserves the same scrutiny. A weather lookup is cheap and
reversible; a wire transfer, an outbound email, a shell command, or delegating
authority to another agent is high-stakes and irreversible. Provenance gating
(see `provenance.py`) is applied to high-stakes actions: those are where an
injection turns into real-world damage.

Classification is by tool-name convention with a sensible default set, and is
fully overridable per tool via policy (`stakes: "high" | "low"`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .types import ToolCall

# tool-name patterns → the kind of high-stakes action, most damaging first.
_HIGH_STAKES: tuple[tuple[str, str], ...] = (
    ("payment", r"pay|payment|transfer|remit|wire|charge|refund|checkout|"
                r"purchase|order|invoice|send_money|send_funds|settle"),
    ("exec",    r"\bexec\b|execute|run_shell|shell|command|spawn_process|eval|deploy"),
    ("delete",  r"delete|drop|remove|destroy|wipe|revoke|terminate"),
    ("send",    r"send_email|send_message|send_sms|email|sms|post_message|publish|notify"),
    ("delegate", r"delegate|spawn_agent|invoke_agent|handoff|grant|authorize|approve"),
    ("write",   r"write_file|overwrite|update_record|set_config|modify"),
)
_COMPILED = tuple((kind, re.compile(pat, re.IGNORECASE)) for kind, pat in _HIGH_STAKES)


@dataclass(frozen=True)
class ActionClass:
    high_stakes: bool
    kind: str  # "payment" | "exec" | ... | "read" (low-stakes default)


class ActionClassifier:
    """Decides whether a call is high-stakes. `overrides` maps a tool name to
    an explicit stakes level, taking precedence over name heuristics."""

    def __init__(self, overrides: dict[str, str] | None = None):
        self.overrides = {k: v.lower() for k, v in (overrides or {}).items()}

    def classify(self, call: ToolCall) -> ActionClass:
        override = self.overrides.get(call.tool)
        if override == "high":
            return ActionClass(True, _name_kind(call.tool) or "action")
        if override == "low":
            return ActionClass(False, "read")
        for kind, pat in _COMPILED:
            if pat.search(call.tool):
                return ActionClass(True, kind)
        return ActionClass(False, "read")


def _name_kind(name: str) -> str:
    for kind, pat in _COMPILED:
        if pat.search(name):
            return kind
    return ""
