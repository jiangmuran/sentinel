"""Structured, replayable audit log.

Every decision Sentinel makes is appended as one JSON object per line (JSONL).
This is the "black box recorder": it lets an operator answer, after the fact,
*which* tool result tried to inject the agent and *what* Sentinel did about it.
`clock`/`event_id` are injectable so tests produce byte-stable output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from .types import Decision, ToolCall


class AuditLog:
    def __init__(
        self,
        stream: TextIO | None = None,
        path: str | Path | None = None,
        clock: Callable[[], float] | None = None,
        event_id: Callable[[], str] | None = None,
    ):
        if path is not None:
            self._stream: TextIO = open(path, "a", encoding="utf-8")
            self._owns_stream = True
        else:
            self._stream = stream or sys.stderr
            self._owns_stream = False

        if clock is None:
            import time
            clock = time.time
        self._clock = clock

        self._seq = 0
        self._event_id = event_id or self._default_event_id

    def _default_event_id(self) -> str:
        self._seq += 1
        return f"evt-{self._seq:06d}"

    def record(
        self,
        event: str,
        decision: Decision,
        call: ToolCall | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "id": self._event_id(),
            "ts": round(self._clock(), 3),
            "event": event,
            "decision": decision.to_dict(),
        }
        if call is not None:
            record["session"] = call.session_id
            record["tool"] = call.tool
            record["call_id"] = call.call_id
        if extra:
            record.update(extra)
        self._stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._stream.flush()
        return record

    def close(self) -> None:
        if self._owns_stream:
            self._stream.close()
