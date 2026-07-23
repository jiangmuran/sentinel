"""A Claude (Anthropic) brain for the GuardTeam analysis agents.

This is the first-party companion to the provider-agnostic OpenAI-compatible
`LLMBrain` in `brain.py`: same `Brain` interface, but calls Claude through the
official `anthropic` SDK. Pick whichever matches your stack — AgentTeams runs
OpenAI-compatible runtimes (Qwen/OpenClaw), while teams standardized on Claude
use this one.

Kept out of `brain.py` on purpose so the OpenAI-compatible path stays free of any
Anthropic SDK dependency. `anthropic` is an *optional* dependency (`pip install
"guardteam[llm]"` → the `anthropic` extra); with it absent, `configured` is False
and `decide()` returns None, so the team falls back to deterministic logic and
still runs anywhere.

Security note is unchanged: the brain only drives the *analysis* agents. The
compliance auditor's enforcement stays deterministic — LLM proposes, Sentinel
disposes.
"""

from __future__ import annotations

import json

from .brain import _SYS, _extract_json  # pure, provider-neutral helpers


class ClaudeBrain:
    """Brain backed by Claude via the official Anthropic SDK.

    Credentials resolve the SDK's normal way (ANTHROPIC_API_KEY, or an
    `ant auth login` profile) — nothing is hardcoded. `client` can be injected
    for testing.
    """

    def __init__(self, model: str = "claude-opus-4-8", max_tokens: int = 256,
                 client=None):
        self.model = model
        self.max_tokens = max_tokens
        self._client = client

    @property
    def configured(self) -> bool:
        if self._client is not None:
            return True
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def _get_client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic()  # resolves creds from env/profile
        return self._client

    def decide(self, role: str, context: dict) -> dict | None:
        system = _SYS.get(role)
        if not system or not self.configured:
            return None
        try:
            resp = self._get_client().messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                messages=[{"role": "user",
                           "content": json.dumps(context, ensure_ascii=False)}],
            )
            text = "".join(
                getattr(b, "text", "") for b in resp.content
                if getattr(b, "type", None) == "text"
            )
            return _extract_json(text)
        except Exception:  # noqa: BLE001 - a brain must never crash the team
            return None
