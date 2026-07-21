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
        r"(?:^|\n|[.!?]\s+)\s*(?:#{0,3}\s*)?(system|assistant|developer)\s*[:：]",
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
    # Blocks on a directive to read a *secret* specifically. Deliberately does
    # NOT fire on generic "read a file" / "return its contents" — those are
    # everyday benign phrasing, and over-blocking them is how injection filters
    # earn a reputation for breaking real workflows.
    _Rule(
        "SEC002", Severity.HIGH, "Secret-read directive",
        r"\b(read|cat|open|load|print|exfiltrate|dump|fetch|retrieve)\b"
        r"[^.\n]{0,60}?"
        r"(~?/?\.ssh|\.env\b|\.aws|\bsecret|\bcredential|\btoken\b|"
        r"\bapi[_ ]?key|\bid_rsa\b|\bprivate[_ ]?key|\bpassword|aws_secret\w*)",
    ),
    # --- Exfiltration channels -----------------------------------------------
    # Channel indicators are kept strong (a real outbound sink) so honest API
    # descriptions like "POST to the configured endpoint" don't trip it.
    _Rule(
        "EXF001", Severity.CRITICAL, "Outbound exfiltration directive",
        r"\b(send|post|upload|exfiltrate|leak|forward|email|transmit)\b"
        r"[^\n]{0,45}?(https?://|ftp://|webhook|curl\s|wget\s|\battacker\b|"
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
    # --- Terminal / rendering hijack -----------------------------------------
    _Rule(
        "OBF004", Severity.MEDIUM, "ANSI/OSC terminal escape sequence",
        r"\x1b[\[\]][0-9;?]*[A-Za-z]|\x1b\]8;",
    ),
    _Rule(
        "EXF003", Severity.HIGH, "Markdown image/link exfiltration to a "
        "parameterized remote URL",
        r"!\[[^\]]{0,60}\]\(\s*https?://[^)\s]*\?[^)]*\)",
    ),
    # --- Chinese-language injection (this contest is China-hosted; most
    #     detectors are English-only, leaving a real gap) --------------------
    _Rule(
        "CJK001", Severity.HIGH, "Instruction override (Chinese)",
        r"(忽略|无视|忘记|不要理会)[^。\n]{0,12}?"
        r"(之前|上述|以上|前面|所有|全部)?[^。\n]{0,8}?"
        r"(指令|指示|提示|规则|命令|设定|要求)",
    ),
    _Rule(
        "CJK002", Severity.HIGH, "Role reassignment (Chinese)",
        r"你现在是|从现在(开始|起)你(是|将)|现在(开始)?你要扮演|进入开发者模式|"
        r"扮演[^。\n]{0,6}(管理员|不受限|越狱)",
    ),
    _Rule(
        "CJK003", Severity.HIGH, "Secret exfiltration directive (Chinese)",
        r"(读取|获取|打开|发送|上传|外泄|泄露|传送)[^。\n]{0,20}?"
        r"(密钥|私钥|凭证|凭据|口令|密码|机密|\.ssh|id_rsa|\.env|token)",
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


class CompositeDetector:
    """Runs several detectors and merges their findings. Lets a fast signature
    pass and a slower LLM pass live behind the one `Detector` interface."""

    def __init__(self, *detectors: Detector):
        self._detectors = detectors

    def scan(self, text: str, source: Source) -> list[Finding]:
        out: list[Finding] = []
        for d in self._detectors:
            out.extend(d.scan(text, source))
        return out


class CallableDetector:
    """Adapt any ``fn(text, source_name) -> iterable[Finding | dict]`` into a
    Detector. This is the escape hatch for an LLM classifier — Sentinel stays
    free of any model-SDK dependency; you bring the callable.

    Each returned item is a `Finding` or a dict with keys
    ``{rule_id?, severity?, message?, span?}``. Return empty for clean text.

    Example::

        def llm_detect(text, source):
            v = my_model.classify(text)          # your model call
            return [{"severity": "HIGH", "message": v.reason}] if v.bad else []

        detector = CompositeDetector(SignatureDetector(),
                                     CallableDetector(llm_detect))
    """

    def __init__(self, fn, rule_prefix: str = "LLM"):
        self._fn = fn
        self._prefix = rule_prefix

    def scan(self, text: str, source: Source) -> list[Finding]:
        findings: list[Finding] = []
        for i, item in enumerate(self._fn(text, source.value) or []):
            if isinstance(item, Finding):
                findings.append(item)
            else:
                findings.append(Finding(
                    rule_id=item.get("rule_id", f"{self._prefix}{i:03d}"),
                    severity=Severity.parse(item.get("severity", "HIGH")),
                    source=source,
                    message=item.get("message", "LLM-flagged injection"),
                    span=item.get("span", ""),
                ))
        return findings


_ANSI = re.compile(r"\x1b[\[\]][0-9;?]*[A-Za-z]|\x1b\]8;[^\x07\x1b]*(?:\x07|\x1b\\)?")


def strip_obfuscation(text: str) -> str:
    """Remove invisible/rendering smuggling characters. Used by SANITIZE."""
    text = _TAG_BLOCK.sub("", text)
    text = _BIDI_OVERRIDE.sub("", text)
    text = _ANSI.sub("", text)
    for ch in _ZERO_WIDTH:
        text = text.replace(ch, "")
    return text
