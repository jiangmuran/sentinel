"""Score a Sentinel configuration against SentinelBench.

    python -m benchmark.runner            # human-readable report
    python -m benchmark.runner --json     # machine-readable

Reports detection rate (recall on malicious cases), false-positive rate (on
benign controls), and a per-category breakdown. A layer that blocks everything
scores 100% detection but 100% FPR — both numbers are always shown together so
that trade-off can't be hidden.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass

from mcp_sentinel import Sentinel
from mcp_sentinel.types import ToolDef, ToolResult

from .corpus import CASES, AttackCase, Boundary, stats


@dataclass
class CaseOutcome:
    case: AttackCase
    blocked: bool
    correct: bool
    reason: str


def _evaluate_case(sentinel: Sentinel, case: AttackCase) -> CaseOutcome:
    if case.boundary is Boundary.TOOL_DESCRIPTION:
        _, decisions = sentinel.inspect_tools(
            [ToolDef(name=case.id, description=case.payload)]
        )
        decision = decisions[0]
    else:
        decision = sentinel.scrutinize_result(ToolResult(text=case.payload))
    blocked = decision.blocked
    return CaseOutcome(case, blocked, blocked == case.expected_block, decision.reason)


def _rate(num: int, den: int) -> float:
    return num / den if den else 0.0


def run(sentinel: Sentinel | None = None) -> dict:
    sentinel = sentinel or Sentinel()
    outcomes = [_evaluate_case(sentinel, c) for c in CASES]

    mal = [o for o in outcomes if o.case.expected_block]
    ben = [o for o in outcomes if not o.case.expected_block]
    core = [o for o in mal if o.case.tier == "core"]
    hard = [o for o in mal if o.case.tier == "hard"]
    detected = sum(1 for o in mal if o.blocked)
    core_detected = sum(1 for o in core if o.blocked)
    hard_detected = sum(1 for o in hard if o.blocked)
    false_pos = sum(1 for o in ben if o.blocked)

    by_cat: dict[str, dict[str, int]] = {}
    for o in outcomes:
        c = by_cat.setdefault(o.case.category, {"total": 0, "correct": 0})
        c["total"] += 1
        c["correct"] += int(o.correct)

    # A "regression" is a core-tier miss or a false positive. Hard-tier misses
    # are expected and reported, not treated as failures.
    regressions = [
        o for o in outcomes if not o.correct
        and not (o.case.expected_block and o.case.tier == "hard")
    ]

    return {
        "corpus": stats(),
        "detection_rate": _rate(detected, len(mal)),
        "core_detection_rate": _rate(core_detected, len(core)),
        "hard_detection_rate": _rate(hard_detected, len(hard)),
        "false_positive_rate": _rate(false_pos, len(ben)),
        "detected": detected, "malicious_total": len(mal),
        "core_detected": core_detected, "core_total": len(core),
        "hard_detected": hard_detected, "hard_total": len(hard),
        "false_positives": false_pos, "benign_total": len(ben),
        "accuracy": _rate(sum(o.correct for o in outcomes), len(outcomes)),
        "by_category": by_cat,
        "regressions": [
            {"id": o.case.id, "tier": o.case.tier,
             "expected_block": o.case.expected_block,
             "blocked": o.blocked, "desc": o.case.description}
            for o in regressions
        ],
        "hard_misses": [
            {"id": o.case.id, "category": o.case.category, "desc": o.case.description}
            for o in hard if not o.blocked
        ],
    }


def _print_report(r: dict) -> None:
    c = r["corpus"]
    print("SentinelBench v0")
    print(f"  corpus: {c['total']} cases "
          f"({c['malicious']} malicious / {c['benign']} benign), "
          f"{c['categories']} categories\n")
    print(f"  CORE detection      : {r['core_detection_rate']:6.1%}  "
          f"({r['core_detected']}/{r['core_total']} signature-tier attacks blocked)")
    print(f"  HARD detection      : {r['hard_detection_rate']:6.1%}  "
          f"({r['hard_detected']}/{r['hard_total']} semantic-tier — LLM tier's job)")
    print(f"  false-positive rate : {r['false_positive_rate']:6.1%}  "
          f"({r['false_positives']}/{r['benign_total']} benign blocked)")
    print(f"  overall detection   : {r['detection_rate']:6.1%}\n")
    if r["hard_misses"]:
        print("  hard-tier misses (expected; motivate the LLM detector tier):")
        for m in r["hard_misses"]:
            print(f"    · {m['id']} [{m['category']}] {m['desc']}")
    if r["regressions"]:
        print("\n  REGRESSIONS (core miss or false positive):")
        for f in r["regressions"]:
            kind = "missed core attack" if f["expected_block"] else "false positive"
            print(f"    [{kind}] {f['id']}: {f['desc']}")
    else:
        print("\n  no regressions: core tier clean, zero false positives.")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    report = run()
    if "--json" in argv:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_report(report)
    # Exit non-zero only on a real regression (core miss / false positive).
    return 0 if not report["regressions"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
