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

from .brain import Brain, NullBrain
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

    def __init__(self, prov: ProvenanceSkill, brain: Brain | None = None,
                 screener: "RiskScreener | None" = None):
        self.prov = prov
        self.brain = brain or NullBrain()
        self.screener = screener

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
        # Deterministic provenance is authoritative; the LLM brain may only
        # *raise* risk and add narrative — it can never lower it.
        level = "high" if (tainted or flagged) else "low"
        # Domain risk screening — blocklist / velocity / duplicate / amount anomaly.
        if self.screener is not None:
            sc = self.screener.assess(str(payout.get("to", "")), payout.get("amount"))
            if sc["findings"]:
                findings.extend(sc["findings"])
            if sc["level"] == "high":
                level = "high"
        b = self.brain.decide("locator", {"payout": payout, "flagged": flagged,
                                          "det_level": level})
        if isinstance(b, dict):
            if b.get("level") == "high":
                level = "high"
            if b.get("reason"):
                findings.append(f"LLM: {b['reason']}")
        room.blackboard["risk"] = {"level": level, "findings": findings}
        return [Message(self.name, "planner", "risk.assessed",
                        {"level": level, "findings": findings})]


# ---- ③ 处置方案 Agent ------------------------------------------------------
class DispositionPlanner(Agent):
    name = "planner"

    def __init__(self, brain: Brain | None = None):
        self.brain = brain or NullBrain()

    def handle(self, msg: Message, room: Room) -> list[Message]:
        payout = room.blackboard["proposed_payout"]
        level = msg.payload["level"]
        # The planner proposes an action. Note: even if the planner (or its LLM
        # brain) is wrong or itself hijacked into proposing "pay", the auditor's
        # runtime enforcement is the backstop — LLM proposes, Sentinel disposes.
        disposition = "review" if level == "high" else "pay"
        b = self.brain.decide("planner", {"level": level, "payout": payout})
        if isinstance(b, dict) and b.get("disposition") in ("pay", "review", "reject"):
            disposition = b["disposition"]
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
        disposition = room.blackboard.get("disposition")
        risk = room.blackboard.get("risk", {})
        # Three-way outcome:
        #   blocked  — enforcement (mandate/provenance) rejected it (hard, signed)
        #   held     — enforcement clears it, but risk screening flagged it → a
        #              human must approve before it settles (not auto-paid)
        #   approved — clean and low-risk
        if not receipt.approved:
            decision, reasons = "blocked", list(receipt.reasons)
        elif disposition == "review":
            decision = "held"
            reasons = list(risk.get("findings", [])) or ["flagged for manual review"]
        else:
            decision, reasons = "approved", list(receipt.reasons)
        final = {
            "decision": decision,
            "enforcement": receipt.decision,
            "reasons": reasons,
            "recipient": receipt.recipient,
            "amount": receipt.amount,
            "signature": receipt.signature[:16] + "…",
            "disposition": disposition,
        }
        out = [Message(self.name, "manager", "final", final)]
        # Human-in-the-loop: anything not auto-approved escalates with evidence.
        if decision != "approved":
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
    """Builds the Manager + 4 Workers, wired to Sentinel Skills.

    Pass `brain` (an LLM brain) to make the analysis agents autonomous; the
    compliance auditor's enforcement stays deterministic regardless."""

    def __init__(self, mandate: Mandate, secret: str, brain: Brain | None = None,
                 screener: "RiskScreener | None" = None):
        self.mandate = mandate
        self.secret = secret
        self.brain = brain or NullBrain()
        self.screener = screener

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
            RiskLocator(prov, self.brain, self.screener),
            DispositionPlanner(self.brain),
            ComplianceAuditor(enforce),
        ])
        init = Message("manager", "aggregator", "case.new",
                       {"signals": signals, "proposed_payout": proposed_payout})
        final = manager.run(room, init)
        return final, room
