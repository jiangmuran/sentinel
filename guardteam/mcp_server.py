"""Sentinel Skills as a real MCP server — the AgentTeams bridge.

AgentTeams Workers consume tools over MCP. This exposes the four Sentinel Skills
as MCP tools so any Worker (or any MCP client) can call them:

    injection_scan     — detect prompt injection in untrusted text
    taint_untrusted    — record a taint for untrusted content (provenance source)
    authorize_payment  — enforce mandate + provenance before settlement → signed receipt
    verify_receipt     — check a receipt's tamper-evident signature
    mandate_info       — the active spending mandate (no secret)

Run it (requires `pip install "mcp>=1.2"`):

    python -m guardteam.mcp_server

then point an MCP client (or the AgentTeams gateway) at it. The signing secret
lives on the server (env GUARDTEAM_SECRET) — Workers never see it, mirroring the
Higress-gateway credential-isolation model.

FOR DEFENSIVE USE. The injection strings clients send are inspected, never run.
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from mcp_sentinel import (
    Mandate,
    Sentinel,
    ToolCall,
    TransactionGuard,
)
from mcp_sentinel.commerce import Receipt
from mcp_sentinel.policy import Policy, ToolRule
from mcp_sentinel.types import Severity, Source, ToolResult

_SECRET = os.getenv("GUARDTEAM_SECRET", "issuer-signing-key")

_sentinel = Sentinel(policy=Policy(tools={"create_payment": ToolRule(stakes="high")}))
_mandate = Mandate.issue(
    _SECRET,
    agent_id=os.getenv("GUARDTEAM_AGENT_ID", "claims-bot"),
    max_amount=float(os.getenv("GUARDTEAM_MAX_AMOUNT", "5000")),
    currency=os.getenv("GUARDTEAM_CURRENCY", "CNY"),
    allowed_recipients=tuple(
        os.getenv("GUARDTEAM_ALLOWLIST", "acct-CLAIMANT-88,acct-MERCHANT-001").split(",")),
    expires_at=float(os.getenv("GUARDTEAM_EXPIRES_AT", "9999999999")),
    nonce=os.getenv("GUARDTEAM_MANDATE_NONCE", "mnd-01"),
    total_budget=float(os.getenv("GUARDTEAM_BUDGET", "20000")),
)
_guard = TransactionGuard(_sentinel, _mandate, _SECRET)

mcp = FastMCP("sentinel-skills")


@mcp.tool()
def injection_scan(text):
    """Detect prompt injection in untrusted text (EN + 中文, 20+ categories)."""
    fs = _sentinel.detector.scan(text, Source.TOOL_RESULT)
    sev = max((f.severity for f in fs), default=Severity.INFO)
    return {"flagged": bool(fs), "findings": [f.rule_id for f in fs], "severity": sev.name}


@mcp.tool()
def taint_untrusted(session_id, text):
    """Record untrusted content so a later high-stakes action sourcing a
    parameter from it can be traced (provenance)."""
    d = _sentinel.scrutinize_result(ToolResult(session_id=session_id, text=text))
    return {"action": d.action.value}


@mcp.tool()
def authorize_payment(session_id, to, amount):
    """Enforce the signed mandate + provenance BEFORE settlement; return a signed
    receipt. Blocks over-cap / off-allow-list / over-budget / injection-tainted."""
    call = ToolCall(session_id=session_id, tool="create_payment",
                    arguments={"to": to, "amount": str(amount)})
    return _guard.authorize(call).to_dict()


@mcp.tool()
def verify_receipt(receipt):
    """Verify a receipt's tamper-evident HMAC signature."""
    try:
        r = Receipt(
            decision=receipt["decision"], action=receipt["action"],
            recipient=receipt["recipient"], amount=float(receipt["amount"]),
            currency=receipt["currency"], reasons=tuple(receipt.get("reasons", [])),
            mandate_nonce=receipt["mandate_nonce"], ts=float(receipt["ts"]),
            signature=receipt.get("signature", ""))
        return {"valid": r.verify(_SECRET)}
    except (KeyError, TypeError, ValueError) as e:
        return {"valid": False, "error": str(e)}


@mcp.tool()
def mandate_info():
    """The active spending mandate (public fields; no secret)."""
    p = _mandate._payload()
    p["signature_present"] = bool(_mandate.signature)
    return p


if __name__ == "__main__":
    mcp.run()
