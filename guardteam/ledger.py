"""Tamper-evident audit ledger for GuardTeam decisions.

Every case the team handles produces a structured record; the ledger chains them
by hash (each entry commits to the previous entry's hash) and optionally HMAC-signs
each link. The result is an append-only, replayable compliance trail: change,
reorder, or drop any past decision and `verify()` pinpoints the break — exactly
what an auditor or regulator needs for an automated-payments system.

Deterministic and standard-library only; `clock` is injectable for tests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

GENESIS = "0" * 64


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def case_record(case_id: str, final: dict, room) -> dict:
    """Distil one case's outcome into a ledger record."""
    receipt = room.blackboard.get("receipt")
    return {
        "case_id": case_id,
        "decision": final.get("decision"),
        "enforcement": final.get("enforcement"),
        "recipient": final.get("recipient"),
        "amount": final.get("amount"),
        "reasons": list(final.get("reasons", [])),
        "receipt_signature": getattr(receipt, "signature", None),
        "transcript": [{"from": m.frm, "to": m.to, "kind": m.kind}
                       for m in room.transcript],
    }


@dataclass
class AuditLedger:
    secret: str | None = None
    clock: Callable[[], float] | None = None
    entries: list[dict] = field(default_factory=list)

    def _now(self) -> float:
        if self.clock:
            return self.clock()
        import time
        return time.time()

    @property
    def head(self) -> str:
        return self.entries[-1]["entry_hash"] if self.entries else GENESIS

    def _entry_hash(self, prev: str, record: dict, ts: float, seq: int) -> str:
        return _sha(f"{prev}|{_canon(record)}|{ts}|{seq}")

    def append(self, record: dict) -> dict:
        prev, seq, ts = self.head, len(self.entries), round(self._now(), 3)
        eh = self._entry_hash(prev, record, ts, seq)
        entry = {"seq": seq, "prev_hash": prev, "ts": ts, "record": record,
                 "entry_hash": eh}
        if self.secret:
            entry["signature"] = hmac.new(
                self.secret.encode(), eh.encode(), hashlib.sha256).hexdigest()
        self.entries.append(entry)
        return entry

    def verify(self) -> dict:
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.get("seq") != i or e.get("prev_hash") != prev:
                return {"ok": False, "broken_at": i, "reason": "chain link mismatch"}
            eh = self._entry_hash(prev, e["record"], e["ts"], e["seq"])
            if eh != e.get("entry_hash"):
                return {"ok": False, "broken_at": i, "reason": "record tampered"}
            if self.secret:
                sig = hmac.new(self.secret.encode(), eh.encode(),
                               hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig, e.get("signature", "")):
                    return {"ok": False, "broken_at": i, "reason": "signature invalid"}
            prev = e["entry_hash"]
        return {"ok": True, "entries": len(self.entries), "head": self.head}

    def to_jsonl(self) -> str:
        return "\n".join(_canon(e) for e in self.entries)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_jsonl() + ("\n" if self.entries else ""),
                              encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, secret: str | None = None) -> "AuditLedger":
        led = cls(secret=secret)
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                led.entries.append(json.loads(line))
        return led
