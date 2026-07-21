"""Prompt-injection detection for MCP traffic.

The threat model: an MCP server is *untrusted content*. Anything it returns —
tool descriptions, resource contents, tool-call results — may try to hijack the
agent that reads it ("you are now...", "ignore previous instructions", or a
hidden instruction to read a secret and POST it somewhere).

This module ships a fast, deterministic, signature-based detector. It is
intentionally dependency-free and pluggable: `Detector` is a Protocol, so a
heavier LLM-based classifier can be dropped in behind the same interface
without touching the gateway. Signatures catch the overwhelming majority of
known injection patterns at ~zero latency; the LLM tier (roadmap) is for the
long tail.
"""

from __future__ import annotations

import re
from typing import Protocol

from .types import Finding, Severity, Source


class Detector(Protocol):
    """Anything that can turn a blob of untrusted text into findings."""

    def scan(self, text: str, source: Source) -> list[Finding]:
        ...


# Unicode ranges abused to *smuggle* instructions past humans and naive
# filters while remaining readable to the model.
_ZERO_WIDTH = "​‌‍⁠﻿"
_TAG_BLOCK = re.compile(r"[\U000e0000-\U000e007f]")  # "ASCII smuggling" tags
_BIDI_OVERRIDE = re.compile(r"[‪-‮⁦-⁩]")


class _Rule:
    __slots__ = ("rule_id", "severity", "message", "pattern")

    def __init__(self, rule_id: str, severity: Severity, message: str, pattern: str):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.pattern = re.compile(pattern, re.IGNORECASE | re.DOTALL)


# Ordered roughly by how load-bearing each family is in real attacks.
_RULES: tuple[_Rule, ...] = (
    # --- Instruction override -------------------------------------------------
    _Rule(
        "INJ001", Severity.HIGH, "Instruction-override phrase",
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?"
        r"\b(previous|prior|earlier|above|all|the)\b[^.\n]{0,20}?"
        r"\b(instruction|instructions|prompt|context|rule|rules|directive)s?\b",
    ),
    _Rule(
        "INJ002", Severity.HIGH, "Role / persona reassignment",
        r"\byou\s+are\s+now\b|\bact\s+as\b[^.\n]{0,30}\b(dan|admin|root|"
        r"developer\s+mode|jailbroken)\b|\bpretend\s+to\s+be\b",
    ),
    _Rule(
        "INJ003", Severity.HIGH, "Injected system/assistant turn",
        r"(?:^|\n)\s*(?:#{0,3}\s*)?(system|assistant|developer)\s*[:：]",
    ),
    _Rule(
        "INJ004", Severity.MEDIUM, "New-instruction preamble",
        r"\b(new|updated|revised|real|actual)\s+(instruction|instructions|"
        r"task|directive|system\s+prompt)\b|\byour\s+(new|real)\s+task\b",
    ),
    # --- Secret / sensitive-resource access ----------------------------------
    # A bare keyword mention is only a weak signal (API docs legitimately say
    # "api_key"); MEDIUM => sanitize/observe, not block. The *directive* to read
    # a secret (SEC002) is what blocks.
    _Rule(
        "SEC001", Severity.MEDIUM, "Reference to credential material",
        r"(~/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws/credentials|"
        r"aws_secret_access_key|private[_ ]?key|api[_ ]?key|bearer\s+token|"
        r"password\s*[:=])",
    ),
    _Rule(
        "SEC002", Severity.HIGH, "Filesystem/secret read directive",
        r"\b(read|cat|open|load|print|exfiltrate|dump|fetch|retrieve)\b"
        r"[^.\n]{0,60}?"
        r"(?:\bfile|\bcontents?|~?/?\.ssh|\.env|\bsecret|\bcredential|\btoken\b|"
        r"\bapi[_ ]?key|\bid_rsa\b|\bpassword|aws_secret\w*)",
    ),
    # --- Exfiltration channels -----------------------------------------------
    # Channel indicators are kept strong (a real outbound sink) so honest API
    # descriptions like "POST to the configured endpoint" don't trip it.
    _Rule(
        "EXF001", Severity.CRITICAL, "Outbound exfiltration directive",
        r"\b(send|post|upload|exfiltrate|leak|forward|email|transmit)\b"
        r"[^.\n]{0,50}?(https?://|ftp://|webhook|curl\s|wget\s|\battacker\b|"
        r"evil\.)",
    ),
    _Rule(
        "EXF002", Severity.HIGH, "Shell / network command in content",
        r"\b(curl|wget|nc\s|bash\s+-c|/bin/sh|powershell|Invoke-WebRequest)\b",
    ),
    # --- Tool abuse ----------------------------------------------------------
    _Rule(
        "TUL001", Severity.HIGH, "Content steering tool use",
        r"\b(before|after|when|whenever)\b[^.\n]{0,30}?\b(using|calling|"
        r"invoking|you\s+use)\b[^.\n]{0,30}?\btool\b|"
        r"\balways\s+call\b|\bdo\s+not\s+tell\s+the\s+user\b|"
        r"\bwithout\s+(informing|telling|asking)\s+the\s+user\b",
    ),
)


def _truncate(s: str, n: int = 120) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[: n - 1] + "…"


class SignatureDetector:
    """Deterministic, dependency-free injection detector.

    Extra signatures can be added at construction time; each entry is
    ``(rule_id, severity, message, regex)``.
    """

    def __init__(self, extra_rules: list[tuple[str, Severity, str, str]] | None = None):
        rules = list(_RULES)
        for rule_id, severity, message, pattern in extra_rules or []:
            rules.append(_Rule(rule_id, severity, message, pattern))
        self._rules = tuple(rules)

    def scan(self, text: str, source: Source) -> list[Finding]:
        if not text:
            return []
        findings: list[Finding] = []

        # Obfuscation is itself a signal — legitimate tool output has no reason
        # to carry zero-width joiners, bidi overrides, or tag-block characters.
        if any(ch in text for ch in _ZERO_WIDTH):
            findings.append(Finding(
                "OBF001", Severity.MEDIUM, source,
                "Zero-width characters (possible hidden-instruction smuggling)",
                "",
            ))
        if _TAG_BLOCK.search(text):
            findings.append(Finding(
                "OBF002", Severity.HIGH, source,
                "Unicode tag-block characters (ASCII smuggling)", "",
            ))
        if _BIDI_OVERRIDE.search(text):
            findings.append(Finding(
                "OBF003", Severity.MEDIUM, source,
                "Bidirectional override characters", "",
            ))

        for rule in self._rules:
            m = rule.pattern.search(text)
            if m:
                findings.append(Finding(
                    rule.rule_id, rule.severity, source,
                    rule.message, _truncate(m.group(0)),
                ))
        return findings


def strip_obfuscation(text: str) -> str:
    """Remove invisible smuggling characters. Used by SANITIZE."""
    text = _TAG_BLOCK.sub("", text)
    text = _BIDI_OVERRIDE.sub("", text)
    for ch in _ZERO_WIDTH:
        text = text.replace(ch, "")
    return text
