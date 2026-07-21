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


def run(sentinel: Sentinel | None = None) -> dict:
    sentinel = sentinel or Sentinel()
    outcomes = [_evaluate_case(sentinel, c) for c in CASES]

    mal = [o for o in outcomes if o.case.expected_block]
    ben = [o for o in outcomes if not o.case.expected_block]
    detected = sum(1 for o in mal if o.blocked)
    false_pos = sum(1 for o in ben if o.blocked)

    by_cat: dict[str, dict[str, int]] = {}
    for o in outcomes:
        c = by_cat.setdefault(o.case.category, {"total": 0, "correct": 0})
        c["total"] += 1
        c["correct"] += int(o.correct)

    return {
        "corpus": stats(),
        "detection_rate": detected / len(mal) if mal else 0.0,
        "false_positive_rate": false_pos / len(ben) if ben else 0.0,
        "detected": detected,
        "malicious_total": len(mal),
        "false_positives": false_pos,
        "benign_total": len(ben),
        "accuracy": sum(o.correct for o in outcomes) / len(outcomes),
        "by_category": by_cat,
        "failures": [
            {"id": o.case.id, "expected_block": o.case.expected_block,
             "blocked": o.blocked, "desc": o.case.description}
            for o in outcomes if not o.correct
        ],
    }


def _print_report(r: dict) -> None:
    c = r["corpus"]
    print("SentinelBench v0")
    print(f"  corpus: {c['total']} cases "
          f"({c['malicious']} malicious / {c['benign']} benign), "
          f"{c['categories']} categories\n")
    print(f"  detection rate      : {r['detection_rate']:6.1%}  "
          f"({r['detected']}/{r['malicious_total']} attacks blocked)")
    print(f"  false-positive rate : {r['false_positive_rate']:6.1%}  "
          f"({r['false_positives']}/{r['benign_total']} benign blocked)")
    print(f"  overall accuracy    : {r['accuracy']:6.1%}\n")
    print("  by category:")
    for cat, s in sorted(r["by_category"].items()):
        print(f"    {cat:20s} {s['correct']}/{s['total']}")
    if r["failures"]:
        print("\n  FAILURES:")
        for f in r["failures"]:
            kind = "missed attack" if f["expected_block"] else "false positive"
            print(f"    [{kind}] {f['id']}: {f['desc']}")
    else:
        print("\n  no failures.")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    report = run()
    if "--json" in argv:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_report(report)
    # Exit non-zero if anything regressed — usable as a CI gate.
    return 0 if not report["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
