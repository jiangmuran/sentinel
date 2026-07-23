"""Risk screening — the domain heuristics a fraud/claims team actually runs.

Sentinel's mandate + provenance are the *hard* enforcement (a payment is
cryptographically allowed or not). Screening is the *soft, explainable* risk
layer the Risk-Locator agent consults: blocklist hits, velocity spikes,
duplicate/double-claim, and amount anomalies. High risk routes a payment to a
human (held-for-review), even when it's within its mandate.

Deterministic and dependency-free; `clock` is injectable for tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


def _amount(v) -> float:
    try:
        return float(str(v).replace(",", "").strip() or 0)
    except (TypeError, ValueError):
        return 0.0


@dataclass
class RiskScreener:
    blocklist: frozenset[str] = frozenset()
    velocity_max: int = 5             # max payments to one recipient per window
    velocity_window: float = 3600.0   # seconds
    duplicate_window: float = 600.0   # seconds
    amount_alert: float | None = None  # amount strictly above this is anomalous
    clock: Callable[[], float] | None = None

    _hist: dict[str, list[float]] = field(default_factory=dict, repr=False)
    _recent: dict[tuple, float] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: dict) -> "RiskScreener":
        return cls(
            blocklist=frozenset(data.get("blocklist", ())),
            velocity_max=data.get("velocity_max", 5),
            velocity_window=data.get("velocity_window", 3600.0),
            duplicate_window=data.get("duplicate_window", 600.0),
            amount_alert=data.get("amount_alert"),
        )

    def _now(self) -> float:
        if self.clock:
            return self.clock()
        import time
        return time.time()

    def assess(self, recipient: str, amount, now: float | None = None) -> dict:
        """Score one payment. Records the attempt so velocity/duplicate build up."""
        now = self._now() if now is None else now
        amt = _amount(amount)
        findings: list[str] = []

        if recipient in self.blocklist:
            findings.append(f"收款方 {recipient!r} 命中风险名单")

        ts = [t for t in self._hist.get(recipient, []) if now - t <= self.velocity_window]
        if len(ts) >= self.velocity_max:
            findings.append(f"收款方交易频次超限 (≥{self.velocity_max}/窗口)")
        ts.append(now)
        self._hist[recipient] = ts

        key = (recipient, round(amt, 2))
        last = self._recent.get(key)
        if last is not None and now - last <= self.duplicate_window:
            findings.append("疑似重复支付(相同收款方+金额)")
        self._recent[key] = now

        if self.amount_alert is not None and amt > self.amount_alert:
            findings.append(f"金额异常 (>¥{self.amount_alert:g})")

        return {"level": "high" if findings else "low", "findings": findings}
