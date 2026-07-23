"""GuardTeam — a native multi-agent financial risk-control closed loop,
secured by Sentinel. Built for the GOAI 新智基座 track (direction #4)."""

import sys as _sys
from pathlib import Path as _Path

# Allow running from a fresh clone with no install step.
_src = str(_Path(__file__).resolve().parent.parent / "src")
if _src not in _sys.path:
    _sys.path.insert(0, _src)

from .brain import Brain, CallableBrain, LLMBrain, NullBrain  # noqa: E402
from .claude_brain import ClaudeBrain  # noqa: E402
from .skills import (  # noqa: E402
    EnforcementSkill,
    InjectionScanSkill,
    ProvenanceSkill,
    SkillResult,
    SkillSpec,
    SKILL_SPECS,
)
from .team import (  # noqa: E402
    Agent,
    ComplianceAuditor,
    DispositionPlanner,
    GuardTeam,
    Manager,
    Message,
    RiskLocator,
    Room,
    SignalAggregator,
)

__all__ = [
    "GuardTeam", "Manager", "Room", "Message", "Agent",
    "SignalAggregator", "RiskLocator", "DispositionPlanner", "ComplianceAuditor",
    "InjectionScanSkill", "ProvenanceSkill", "EnforcementSkill",
    "SkillSpec", "SkillResult", "SKILL_SPECS",
    "Brain", "NullBrain", "CallableBrain", "LLMBrain", "ClaudeBrain",
]
