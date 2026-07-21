"""Provenance / taint tracking — the core idea that lifts Sentinel from a
content filter to a *trust runtime* for agent actions.

The root cause behind EchoLeak (CVE-2025-32711), the GitHub-MCP leak, and the
whole indirect-injection class is what Aim Security named **LLM Scope
Violation**: *untrusted content ends up driving a privileged action.* Scanning
text for bad words is a weak proxy for that. The strong signal is a **data-flow**
one:

    did the parameters of this high-stakes action (a payment recipient, a
    destination address, a shell command) originate from content Sentinel
    already flagged as untrusted/injected?

`ProvenanceTracker` answers exactly that. When a tool result is scrutinized and
found suspicious, its distinctive tokens are *tainted* for the session. When the
agent later issues a high-stakes call, we check whether the call's arguments
carry any tainted token — i.e. the attacker's account number, URL, or address
that appeared in a poisoned page is now flowing into a wire transfer.

This is a deterministic, dependency-free runtime approximation of taint
tracking for agents. It is complementary to the signature detector: signatures
catch the injection; provenance catches the *consequence*.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .types import Finding, Severity, Source

# A token is "distinctive" enough to trace if it is long AND not just a common
# lowercase word — account ids, emails, URLs, hex, ALLCAPS markers all qualify,
# while "following"/"instructions" do not (which would cause false traces).
_TOKEN = re.compile(r"[A-Za-z0-9_.:/@=+-]{6,}")
_HAS_MARK = re.compile(r"[0-9@:/._=+-]")


def _distinctive_tokens(text: str) -> set[str]:
    out: set[str] = set()
    for tok in _TOKEN.findall(text):
        stripped = tok.strip("._-:/")
        if len(stripped) < 6:
            continue
        if _HAS_MARK.search(stripped) or stripped != stripped.lower():
            out.add(stripped.lower())
    return out


@dataclass(frozen=True)
class Taint:
    """A record that some untrusted content entered the session."""

    taint_id: str
    source: Source
    severity: Severity
    reason: str
    tokens: frozenset[str]
    preview: str  # short human-readable snippet for the audit trail

    def to_dict(self) -> dict:
        return {
            "taint_id": self.taint_id,
            "source": self.source.value,
            "severity": self.severity.name,
            "reason": self.reason,
            "preview": self.preview,
        }


@dataclass
class ProvenanceTracker:
    """Per-session store of tainted content + a data-flow check for actions."""

    _taints: dict[str, list[Taint]] = field(default_factory=lambda: defaultdict(list))
    _seq: int = 0

    def record(
        self,
        session_id: str,
        text: str,
        source: Source,
        findings: list[Finding],
        reason: str = "",
    ) -> Taint | None:
        """Taint the distinctive tokens of some untrusted content. Returns the
        Taint (or None if there was nothing distinctive to track)."""
        tokens = _distinctive_tokens(text)
        if not tokens:
            return None
        self._seq += 1
        sev = max((f.severity for f in findings), default=Severity.LOW)
        taint = Taint(
            taint_id=f"taint-{self._seq:04d}",
            source=source,
            severity=sev,
            reason=reason or (findings[0].message if findings else "untrusted content"),
            tokens=frozenset(tokens),
            preview=_preview(text),
        )
        self._taints[session_id].append(taint)
        return taint

    def trace(self, session_id: str, arg_values: list[str]) -> list[tuple[Taint, str]]:
        """Return (taint, matched_token) for every tainted token that appears in
        any of the given argument values — i.e. the action's parameters derive
        from untrusted content."""
        hits: list[tuple[Taint, str]] = []
        haystacks = [v.lower() for v in arg_values if v]
        for taint in self._taints.get(session_id, ()):
            for tok in taint.tokens:
                if any(tok in h for h in haystacks):
                    hits.append((taint, tok))
                    break
        return hits

    def clear(self, session_id: str) -> None:
        self._taints.pop(session_id, None)


def _preview(text: str, n: int = 80) -> str:
    t = " ".join(text.split())
    return t if len(t) <= n else t[: n - 1] + "…"
