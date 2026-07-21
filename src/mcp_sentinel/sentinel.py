"""The Sentinel core: the decision brain that ties detector + policy + audit
together. Transport-agnostic on purpose — the stdio proxy (`proxy.py`), the
benchmark runner, and the unit tests all drive this same object.

Three inspection points map onto the three trust boundaries of MCP:

  * `inspect_tools`     — at discovery, before the agent reads tool metadata
                          (defends against *tool poisoning*).
  * `guard_call`        — before a call leaves for the server
                          (least privilege + argument injection).
  * `scrutinize_result` — after the server answers, before the agent sees it
                          (defends against injected tool results).
"""

from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLog
from .detector import Detector, SignatureDetector, strip_obfuscation
from .policy import Policy, PolicyEngine
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


@dataclass
class SentinelConfig:
    # Findings at or above this severity cause a BLOCK.
    block_threshold: Severity = Severity.HIGH
    # Below block_threshold but >= this: SANITIZE (forward, neutralized).
    sanitize_threshold: Severity = Severity.MEDIUM
    # Drop poisoned tools from discovery entirely rather than surfacing them.
    quarantine_poisoned_tools: bool = True


class Sentinel:
    def __init__(
        self,
        policy: Policy | None = None,
        detector: Detector | None = None,
        audit: AuditLog | None = None,
        config: SentinelConfig | None = None,
    ):
        self.config = config or SentinelConfig()
        self.detector = detector or SignatureDetector()
        self.policy = PolicyEngine(policy or Policy())
        self.audit = audit

    # -- Discovery boundary ---------------------------------------------------
    def inspect_tools(self, tools: list[ToolDef]) -> tuple[list[ToolDef], list[Decision]]:
        """Screen advertised tools. Returns (safe_tools, decisions).

        A tool whose description carries an injection is quarantined (dropped)
        when configured, so the agent never reads the poisoned metadata."""
        safe: list[ToolDef] = []
        decisions: list[Decision] = []
        for tool in tools:
            findings = self.detector.scan(tool.description, Source.TOOL_DESCRIPTION)
            decision = self._decide(findings, context=f"tool:{tool.name}")
            decisions.append(decision)
            if self.audit:
                self.audit.record("inspect_tool", decision,
                                  extra={"tool": tool.name})
            if decision.blocked and self.config.quarantine_poisoned_tools:
                continue
            safe.append(tool)
        return safe, decisions

    # -- Request boundary -----------------------------------------------------
    def guard_call(self, call: ToolCall) -> Decision:
        """Screen an outbound call: least privilege first, then argument
        content. Policy denial short-circuits before content scanning."""
        policy_decision = self.policy.evaluate(call)
        if policy_decision.blocked:
            if self.audit:
                self.audit.record("guard_call", policy_decision, call=call)
            return policy_decision

        findings: list[Finding] = []
        for arg, value in call.arguments.items():
            if isinstance(value, str):
                findings.extend(self.detector.scan(value, Source.ARGUMENTS))
        decision = self._decide(findings, context=f"call:{call.tool}")
        if not decision.findings:
            decision = policy_decision  # keep the "policy: allowed" reason
        if self.audit:
            self.audit.record("guard_call", decision, call=call)
        return decision

    # -- Response boundary ----------------------------------------------------
    def scrutinize_result(self, result: ToolResult) -> Decision:
        """Screen a tool result before the agent ingests it. This is where
        most real-world injections land."""
        findings = self.detector.scan(result.text, Source.TOOL_RESULT)
        decision = self._decide(findings, context="result")
        if decision.action is Action.SANITIZE:
            decision = Decision(
                Action.SANITIZE, decision.findings, decision.reason,
                sanitized_text=strip_obfuscation(result.text),
            )
        if self.audit:
            self.audit.record(
                "scrutinize_result", decision,
                call=ToolCall(tool="<result>", call_id=result.call_id,
                              session_id=result.session_id),
            )
        return decision

    # -- Decision policy ------------------------------------------------------
    def _decide(self, findings: list[Finding], context: str) -> Decision:
        if not findings:
            return Decision(Action.ALLOW, reason="clean")
        max_sev = max(f.severity for f in findings)
        top = max(findings, key=lambda f: f.severity)
        findings_t = tuple(findings)
        if max_sev >= self.config.block_threshold:
            return Decision(
                Action.BLOCK, findings_t,
                reason=f"blocked [{context}]: {top.rule_id} {top.message}",
            )
        if max_sev >= self.config.sanitize_threshold:
            return Decision(
                Action.SANITIZE, findings_t,
                reason=f"sanitized [{context}]: {top.rule_id} {top.message}",
            )
        return Decision(Action.ALLOW, findings_t, reason=f"observed [{context}]")
