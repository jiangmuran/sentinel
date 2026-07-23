"""GuardTeam — a native multi-agent risk-control closed loop.

Not a pipeline dressed up as agents: a **Manager** routes messages to four
autonomous **Workers**, each with a distinct role and its own decision logic,
communicating through a shared room (transcript + blackboard) and a *shared
provenance session* — mirroring AgentTeams' Manager-Workers + Matrix-room +
shared-file-system model, so it ports onto AgentTeams for 复赛.

Closed loop (track direction #4 金融风控与理赔自动化):
    ① 信号聚合  →  ② 风险定位  →  ③ 处置方案  →  ④ 合规审计
Every high-stakes payout is enforced by Sentinel before it settles; a blocked
action escalates to a human (human-in-the-loop), with a signed receipt as evidence.

Each Worker's `decide()` is deterministic here (runs anywhere, no API keys) but is
a drop-in seam for an LLM brain (QwenPaw / OpenClaw runtime on AgentTeams).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_sentinel import Mandate, Sentinel, TransactionGuard
from mcp_sentinel.policy import Policy, ToolRule

from .skills import EnforcementSkill, InjectionScanSkill, ProvenanceSkill


# ---- messaging + shared room ---------------------------------------------
@dataclass
class Message:
    frm: str
    to: str            # agent name | "manager" | "human"
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class Room:
    """Shared state for one case: transcript (Matrix-room analogue), blackboard
    (MinIO-shared-FS analogue), and the shared Sentinel session + guard."""

    case_id: str
    sentinel: Sentinel
    guard: TransactionGuard
    blackboard: dict[str, Any] = field(default_factory=dict)
    transcript: list[Message] = field(default_factory=list)

    def post(self, msg: Message) -> None:
        self.transcript.append(msg)


class Agent:
    name = "agent"

    def handle(self, msg: Message, room: Room) -> list[Message]:
        raise NotImplementedError


# ---- ① 信号聚合 Agent ------------------------------------------------------
class SignalAggregator(Agent):
    name = "aggregator"

    def __init__(self, scan: InjectionScanSkill, prov: ProvenanceSkill):
        self.scan = scan
        self.prov = prov

    def handle(self, msg: Message, room: Room) -> list[Message]:
        signals = msg.payload["signals"]
        room.blackboard["proposed_payout"] = msg.payload["proposed_payout"]
        normalized, flagged = [], []
        for s in signals:
            res = self.scan.run(s["text"])
            is_flagged = bool(res.data.get("flagged"))
            # Untrusted content is taint-tracked into the shared provenance session.
            if not s.get("trusted", False):
                self.prov.ingest(room.case_id, s["text"])
            normalized.append({"source": s["source"], "flagged": is_flagged,
                               "findings": res.data.get("findings", [])})
            if is_flagged:
                flagged.append(s["source"])
        room.blackboard["signals"] = normalized
        return [Message(self.name, "locator", "case.normalized",
                        {"flagged_sources": flagged})]


# ---- ② 风险定位 Agent ------------------------------------------------------
class RiskLocator(Agent):
    name = "locator"

    def __init__(self, prov: ProvenanceSkill):
        self.prov = prov

    def handle(self, msg: Message, room: Room) -> list[Message]:
        payout = room.blackboard["proposed_payout"]
        trace = self.prov.trace(room.case_id, [str(payout.get("to", "")),
                                               str(payout.get("amount", ""))])
        tainted = trace.data.get("tainted")
        flagged = msg.payload["flagged_sources"]
        findings = []
        if tainted:
            m = trace.data["matches"][0]
            findings.append(f"收款方溯源到不可信信号 (污点 {m['taint_id']}, 命中 {m['token']!r})")
        if flagged:
            findings.append(f"{len(flagged)} 条信号被标记为可疑: {', '.join(flagged)}")
        level = "high" if (tainted or flagged) else "low"
        room.blackboard["risk"] = {"level": level, "findings": findings}
        return [Message(self.name, "planner", "risk.assessed",
                        {"level": level, "findings": findings})]


# ---- ③ 处置方案 Agent ------------------------------------------------------
class DispositionPlanner(Agent):
    name = "planner"

    def handle(self, msg: Message, room: Room) -> list[Message]:
        payout = room.blackboard["proposed_payout"]
        level = msg.payload["level"]
        # The planner proposes an action. Note: even if the planner is wrong or
        # itself hijacked, the auditor's runtime enforcement is the backstop.
        disposition = "review" if level == "high" else "pay"
        room.blackboard["disposition"] = disposition
        room.blackboard["action"] = {"to": payout["to"], "amount": payout["amount"]}
        return [Message(self.name, "auditor", "disposition.proposed",
                        {"disposition": disposition})]


# ---- ④ 合规审计 Agent ------------------------------------------------------
class ComplianceAuditor(Agent):
    name = "auditor"

    def __init__(self, enforce: EnforcementSkill):
        self.enforce = enforce

    def handle(self, msg: Message, room: Room) -> list[Message]:
        action = room.blackboard["action"]
        receipt = self.enforce.run(room.case_id, action["to"], action["amount"])
        room.blackboard["receipt"] = receipt
        final = {
            "decision": receipt.decision,
            "reasons": list(receipt.reasons),
            "recipient": receipt.recipient,
            "amount": receipt.amount,
            "signature": receipt.signature[:16] + "…",
            "disposition": room.blackboard.get("disposition"),
        }
        out = [Message(self.name, "manager", "final", final)]
        # Human-in-the-loop: a blocked payout is escalated with signed evidence.
        if not receipt.approved:
            out.insert(0, Message(self.name, "human", "handoff", final))
        return out


# ---- Manager (orchestrator) ----------------------------------------------
class Manager:
    def __init__(self, agents: list[Agent], max_steps: int = 50):
        self.agents = {a.name: a for a in agents}
        self.max_steps = max_steps

    def run(self, room: Room, initial: Message) -> dict:
        queue: list[Message] = [initial]
        final: dict = {}
        steps = 0
        while queue and steps < self.max_steps:
            msg = queue.pop(0)
            room.post(msg)
            if msg.to == "manager" and msg.kind == "final":
                final = msg.payload
                continue
            if msg.to == "human":
                room.blackboard["handoff"] = msg.payload
                continue
            agent = self.agents.get(msg.to)
            if agent is None:
                continue
            queue.extend(agent.handle(msg, room))
            steps += 1
        room.blackboard["final"] = final
        return final


# ---- assembly -------------------------------------------------------------
class GuardTeam:
    """Builds the Manager + 4 Workers, wired to Sentinel Skills."""

    def __init__(self, mandate: Mandate, secret: str):
        self.mandate = mandate
        self.secret = secret

    def _room(self, case_id: str) -> Room:
        sentinel = Sentinel(policy=Policy(tools={"create_payment": ToolRule(stakes="high")}))
        guard = TransactionGuard(sentinel, self.mandate, self.secret)
        return Room(case_id, sentinel, guard)

    def handle_case(self, case_id: str, signals: list[dict],
                    proposed_payout: dict) -> tuple[dict, Room]:
        room = self._room(case_id)
        scan = InjectionScanSkill(room.sentinel.detector)
        prov = ProvenanceSkill(room.sentinel)
        enforce = EnforcementSkill(room.guard)
        manager = Manager([
            SignalAggregator(scan, prov),
            RiskLocator(prov),
            DispositionPlanner(),
            ComplianceAuditor(enforce),
        ])
        init = Message("manager", "aggregator", "case.new",
                       {"signals": signals, "proposed_payout": proposed_payout})
        final = manager.run(room, init)
        return final, room
