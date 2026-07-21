"""SentinelBench — an open, versioned corpus for measuring how well an MCP
security layer resists prompt injection delivered through tool metadata and
tool results, without over-blocking benign traffic.

The corpus is the reference asset: the point is a *shared, citable* way to score
agent/gateway robustness. Detection rate alone is meaningless without a
false-positive rate on benign controls, so both are first-class here.
"""

import sys as _sys
from pathlib import Path as _Path

# Allow `python -m benchmark.runner` from a fresh clone with no install step.
_src = str(_Path(__file__).resolve().parent.parent / "src")
if _src not in _sys.path:
    _sys.path.insert(0, _src)

from .corpus import CASES, AttackCase, Boundary

__all__ = ["CASES", "AttackCase", "Boundary"]
