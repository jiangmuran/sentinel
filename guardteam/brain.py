"""Pluggable LLM 'brains' for the reasoning agents.

Design principle — **LLM proposes, Sentinel disposes**: the brain drives the
*analysis / proposal* agents (aggregator, locator, planner), but the compliance
auditor's enforcement stays deterministic. You never let an LLM decide whether a
payment is allowed; that is exactly what an attacker would target. So the brain
can make the team smarter without weakening the security guarantee.

The brain is a provider-agnostic **OpenAI-compatible** chat client (the runtimes
AgentTeams uses — QwenPaw / OpenClaw / DeepSeek / OpenAI / local). Zero
dependency: stdlib urllib. Configure via env:

    GUARDTEAM_LLM_BASE_URL   (default https://api.openai.com/v1)
    GUARDTEAM_LLM_API_KEY
    GUARDTEAM_LLM_MODEL      (default gpt-4o-mini)

With no key configured, agents fall back to deterministic logic and run anywhere.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Callable, Protocol


class Brain(Protocol):
    def decide(self, role: str, context: dict) -> dict | None:
        """Return a small decision dict for a role, or None to fall back."""
        ...


class NullBrain:
    """No LLM — every agent uses its deterministic logic."""

    def decide(self, role: str, context: dict) -> dict | None:
        return None


class CallableBrain:
    """Wrap any `fn(role, context) -> dict | None` — the test/LLM seam."""

    def __init__(self, fn: Callable[[str, dict], dict | None]):
        self._fn = fn

    def decide(self, role: str, context: dict) -> dict | None:
        try:
            return self._fn(role, context)
        except Exception:  # noqa: BLE001 - a brain must never crash the team
            return None


_SYS = {
    "locator": "你是金融风控的风险定位 Agent。只输出 JSON: "
               '{"level":"high"|"low","reason":"..."}。发现可疑收款方、异常金额或被标记信号时判 high。',
    "planner": "你是处置方案 Agent。只输出 JSON: "
               '{"disposition":"pay"|"review"|"reject","reason":"..."}。高风险时不要直接 pay。',
}


class LLMBrain:
    """OpenAI-compatible chat brain over stdlib urllib."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None, timeout: float = 30.0):
        self.base_url = (base_url or os.getenv("GUARDTEAM_LLM_BASE_URL",
                                               "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("GUARDTEAM_LLM_API_KEY", "")
        self.model = model or os.getenv("GUARDTEAM_LLM_MODEL", "gpt-4o-mini")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _chat(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self.model, "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(
            self.base_url + "/chat/completions", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())
        return data["choices"][0]["message"]["content"]

    def decide(self, role: str, context: dict) -> dict | None:
        system = _SYS.get(role)
        if not system or not self.configured:
            return None
        try:
            out = self._chat(system, json.dumps(context, ensure_ascii=False))
            return _extract_json(out)
        except Exception:  # noqa: BLE001 - degrade to deterministic on any error
            return None


def _extract_json(text: str) -> dict[str, Any] | None:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None
