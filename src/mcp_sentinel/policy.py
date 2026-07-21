"""Least-privilege policy engine for tool calls.

The detector answers "is this content trying to hijack me?". The policy engine
answers the complementary question "is this agent even *allowed* to do this?".
Defense in depth: even a call the detector deems clean is denied if it violates
least privilege (a disallowed tool, an argument matching a deny pattern, or a
rate limit). Policy is data, loaded from JSON so it can live in review/CI.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .types import Action, Decision, ToolCall


@dataclass
class ToolRule:
    """Constraints for a single tool."""

    allow: bool = True
    # arg name -> list of regexes; a match on the stringified value denies.
    deny_arg_patterns: dict[str, list[str]] = field(default_factory=dict)
    max_calls_per_minute: int | None = None
    # "high" | "low" | None — overrides the action classifier's heuristic so
    # provenance gating can be forced on/off per tool.
    stakes: str | None = None

    _compiled: dict[str, list[re.Pattern]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._compiled = {
            arg: [re.compile(p, re.IGNORECASE) for p in pats]
            for arg, pats in self.deny_arg_patterns.items()
        }


@dataclass
class Policy:
    default_allow: bool = True
    tools: dict[str, ToolRule] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        tools = {}
        for name, raw in (data.get("tools") or {}).items():
            tools[name] = ToolRule(
                allow=raw.get("allow", True),
                deny_arg_patterns=raw.get("deny_arg_patterns", {}) or {},
                max_calls_per_minute=raw.get("max_calls_per_minute"),
                stakes=raw.get("stakes"),
            )
        return cls(default_allow=data.get("default_allow", True), tools=tools)

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        return cls.from_dict(json.loads(Path(path).read_text()))


class PolicyEngine:
    """Evaluates a `ToolCall` against a `Policy`.

    `clock` is injectable so rate-limit behaviour is deterministic in tests.
    """

    def __init__(self, policy: Policy, clock: Callable[[], float] | None = None):
        self.policy = policy
        import time
        self._clock = clock or time.monotonic
        # (session, tool) -> sliding window of call timestamps
        self._calls: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def evaluate(self, call: ToolCall) -> Decision:
        rule = self.policy.tools.get(call.tool)

        # 1. Allow-list / default posture.
        if rule is None:
            if not self.policy.default_allow:
                return Decision(
                    Action.BLOCK, reason=f"tool {call.tool!r} not in allow-list",
                    policy_rule="default_deny",
                )
        elif not rule.allow:
            return Decision(
                Action.BLOCK, reason=f"tool {call.tool!r} explicitly denied",
                policy_rule=f"{call.tool}.allow=false",
            )

        # 2. Argument deny-patterns (e.g. path traversal, secret paths).
        if rule is not None:
            for arg, patterns in rule._compiled.items():
                value = _stringify(call.arguments.get(arg))
                for pat in patterns:
                    if pat.search(value):
                        return Decision(
                            Action.BLOCK,
                            reason=f"argument {arg!r} matched deny pattern "
                                   f"{pat.pattern!r}",
                            policy_rule=f"{call.tool}.deny_arg_patterns.{arg}",
                        )

        # 3. Rate limiting.
        if rule is not None and rule.max_calls_per_minute is not None:
            now = self._clock()
            window = self._calls[(call.session_id, call.tool)]
            while window and now - window[0] > 60.0:
                window.popleft()
            if len(window) >= rule.max_calls_per_minute:
                return Decision(
                    Action.BLOCK,
                    reason=f"rate limit {rule.max_calls_per_minute}/min exceeded "
                           f"for {call.tool!r}",
                    policy_rule=f"{call.tool}.max_calls_per_minute",
                )
            window.append(now)

        return Decision(Action.ALLOW, reason="policy: allowed")


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)
