"""GuardTeam Skills — the reusable capabilities each Agent (Worker) calls.

Per the GOAI 新智基座 track, Skills are a mandatory, first-class deliverable:
each has a clear input/output, invocation condition, dependency, failure mode,
and reuse value. These wrap the (already built, tested, benchmarked) Sentinel
engine so the multi-agent team gets provable security + audit for free.

In an AgentTeams deployment these are exposed to Workers over MCP; here they are
plain callables so the closed loop runs anywhere with zero dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_sentinel import Mandate, Sentinel, TransactionGuard, ToolCall
from mcp_sentinel.types import Severity, Source, ToolResult


@dataclass(frozen=True)
class SkillSpec:
    name: str
    description: str
    inputs: str
    outputs: str
    invocation: str
    failure: str
    reuse: str


@dataclass
class SkillResult:
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# ---- injection.scan -------------------------------------------------------
class InjectionScanSkill:
    spec = SkillSpec(
        name="injection.scan",
        description="检测不可信文本中的提示注入(中英文, 20+ 类)",
        inputs="text: str",
        outputs="{flagged: bool, findings: [rule_id], severity: str}",
        invocation="摄入任何外部/上游不可信数据时",
        failure="内部异常 → ok=False, error 说明; 不阻断主流程",
        reuse="通用注入防护, 可跨 Team/Agent 复用",
    )

    def __init__(self, detector):
        self.detector = detector

    def run(self, text: str) -> SkillResult:
        try:
            fs = self.detector.scan(text, Source.TOOL_RESULT)
            sev = max((f.severity for f in fs), default=Severity.INFO)
            return SkillResult(True, {
                "flagged": bool(fs),
                "findings": [f.rule_id for f in fs],
                "severity": sev.name,
            })
        except Exception as e:  # noqa: BLE001 - skills degrade, never crash the team
            return SkillResult(False, {}, str(e))


# ---- provenance.trace -----------------------------------------------------
class ProvenanceSkill:
    spec = SkillSpec(
        name="provenance.trace",
        description="追踪不可信内容 → 高危动作参数的数据流(污点传播)",
        inputs="ingest(session, text) 打污点; trace(session, values) 查溯源",
        outputs="trace → {tainted: bool, matches: [{taint_id, token}]}",
        invocation="摄入不可信信号时 ingest; 处置/放款前 trace",
        failure="无污点源 → tainted=False(默认放行)",
        reuse="反注入、反欺诈、越权检测",
    )

    def __init__(self, sentinel: Sentinel):
        self.sentinel = sentinel

    def ingest(self, session: str, text: str) -> SkillResult:
        # scrutinize_result records a taint for the session when content is flagged
        d = self.sentinel.scrutinize_result(ToolResult(session_id=session, text=text))
        return SkillResult(True, {"action": d.action.value})

    def trace(self, session: str, values: list[str]) -> SkillResult:
        hits = self.sentinel.provenance.trace(session, [v for v in values if v])
        return SkillResult(True, {
            "tainted": bool(hits),
            "matches": [{"taint_id": t.taint_id, "token": tok} for t, tok in hits],
        })


# ---- mandate.check + receipt.sign (composed by the enforcement guard) -----
class EnforcementSkill:
    """Composes mandate.check + provenance.trace + receipt.sign — the runtime
    gate applied before any payout settles."""

    spec = SkillSpec(
        name="mandate.check + receipt.sign",
        description="结算前强制校验签名授权(额度/白名单/有效期/累计预算)+ 产出防篡改签名回执",
        inputs="action: {to, amount}",
        outputs="Receipt{decision: approved|blocked, reasons, signature}",
        invocation="每一笔高危动作(放款/转账)执行前",
        failure="越权/超预算/签名不符/污点溯源 → blocked + 理由 + 签名回执",
        reuse="任何'agent 花钱'场景; 回执可用于合规审计与纠纷取证",
    )

    def __init__(self, guard: TransactionGuard):
        self.guard = guard

    def run(self, session: str, to: str, amount: str):
        call = ToolCall(session_id=session, tool="create_payment",
                        arguments={"to": to, "amount": str(amount)})
        return self.guard.authorize(call)


# Registry (used by the proposal + tests to prove Skills are first-class).
SKILL_SPECS = [
    InjectionScanSkill.spec,
    ProvenanceSkill.spec,
    EnforcementSkill.spec,
]
