"""The runtime enforcement layer for agent payments.

The payment industry (Stripe MPP, Coinbase x402, Google AP2, Mastercard/Google
*Verifiable Intent*) is building the **rails** — how an agent pays, how identity
and a spending *mandate* are signed, and how a transaction is *recorded* for
later dispute. What none of them do is **enforce, at runtime, before settlement**,
that a given transaction actually stays within its signed mandate *and* was not
induced by injected content.

That is exactly this layer. `TransactionGuard` sits between the agent and the
payment rail and, for each transaction:

  1. checks it against a **signed Mandate** (amount cap, recipient allow-list,
     expiry, tamper-evident signature),
  2. checks **provenance** — did the amount/recipient trace back to untrusted
     content? (reuses Sentinel's taint tracking), and
  3. emits a **signed Receipt** — an approve/block record that is complementary
     to Verifiable Intent's dispute trail, but produced *before* the money moves.

Rail-agnostic: it guards the *decision to transact*, whatever protocol settles it.
Deterministic, standard-library only (HMAC-SHA256 for signatures).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .sentinel import Sentinel
from .types import Action, ToolCall


def _sign(secret: str, payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Mandate:
    """A signed spending authorization for an agent — the runtime analogue of an
    AP2 / Verifiable-Intent mandate."""

    agent_id: str
    max_amount: float
    currency: str
    allowed_recipients: tuple[str, ...]
    expires_at: float          # epoch seconds
    nonce: str
    signature: str = ""        # HMAC over the payload; set via issue()

    def _payload(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "max_amount": self.max_amount,
            "currency": self.currency,
            "allowed_recipients": list(self.allowed_recipients),
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    @classmethod
    def issue(cls, secret: str, **kw) -> "Mandate":
        m = cls(signature="", **kw)
        return cls(signature=_sign(secret, m._payload()), **kw)

    def verify(self, secret: str) -> bool:
        return hmac.compare_digest(self.signature, _sign(secret, self._payload()))

    def violations(self, recipient: str, amount: float, now: float,
                   secret: str) -> list[str]:
        out: list[str] = []
        if not self.verify(secret):
            out.append("mandate signature invalid (tampered or wrong key)")
        if now > self.expires_at:
            out.append("mandate expired")
        if amount > self.max_amount:
            out.append(f"amount {amount:g} exceeds mandate cap "
                       f"{self.max_amount:g} {self.currency}")
        if recipient not in self.allowed_recipients:
            out.append(f"recipient {recipient!r} not in mandate allow-list")
        return out


@dataclass(frozen=True)
class Receipt:
    """A signed, tamper-evident record of a transaction decision — produced
    *before* settlement, usable in a dispute."""

    decision: str              # "approved" | "blocked"
    action: str                # tool name
    recipient: str
    amount: float
    currency: str
    reasons: tuple[str, ...]
    mandate_nonce: str
    ts: float
    signature: str = ""

    def _payload(self) -> dict:
        return {
            "decision": self.decision, "action": self.action,
            "recipient": self.recipient, "amount": self.amount,
            "currency": self.currency, "reasons": list(self.reasons),
            "mandate_nonce": self.mandate_nonce, "ts": self.ts,
        }

    @classmethod
    def signed(cls, secret: str, **kw) -> "Receipt":
        r = cls(signature="", **kw)
        return cls(signature=_sign(secret, r._payload()), **kw)

    def verify(self, secret: str) -> bool:
        return hmac.compare_digest(self.signature, _sign(secret, self._payload()))

    @property
    def approved(self) -> bool:
        return self.decision == "approved"

    def to_dict(self) -> dict[str, Any]:
        d = self._payload()
        d["signature"] = self.signature
        return d


class TransactionGuard:
    """Enforces a signed Mandate + provenance on payment actions, before
    settlement, and returns a signed Receipt."""

    def __init__(
        self,
        sentinel: Sentinel,
        mandate: Mandate,
        secret: str,
        clock: Callable[[], float] | None = None,
        amount_arg: str = "amount",
        recipient_arg: str = "to",
    ):
        self.sentinel = sentinel
        self.mandate = mandate
        self.secret = secret
        self._clock = clock or time.time
        self.amount_arg = amount_arg
        self.recipient_arg = recipient_arg

    def authorize(self, call: ToolCall) -> Receipt:
        recipient = str(call.arguments.get(self.recipient_arg, ""))
        amount = _to_float(call.arguments.get(self.amount_arg))
        now = self._clock()

        reasons = self.mandate.violations(recipient, amount, now, self.secret)

        # Provenance: does a transaction parameter trace to untrusted content?
        pdecision = self.sentinel.guard_call(call)
        if pdecision.action is Action.BLOCK and pdecision.policy_rule == "provenance.taint":
            reasons.append(pdecision.reason)

        return Receipt.signed(
            self.secret,
            decision="blocked" if reasons else "approved",
            action=call.tool,
            recipient=recipient,
            amount=amount,
            currency=self.mandate.currency,
            reasons=tuple(reasons),
            mandate_nonce=self.mandate.nonce,
            ts=round(now, 3),
        )


def _to_float(v: Any) -> float:
    try:
        return float(str(v).replace(",", "").strip() or 0)
    except (TypeError, ValueError):
        return 0.0
