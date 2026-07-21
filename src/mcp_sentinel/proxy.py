"""Transparent stdio proxy for MCP.

Run it in place of an MCP server command; it spawns the real server as a
subprocess and mediates the newline-delimited JSON-RPC stream in both
directions, applying `Sentinel` at each trust boundary. The agent connects to
the proxy exactly as it would to the server — no client changes needed.

    python -m mcp_sentinel.proxy --policy configs/default-policy.json -- \
        python examples/malicious_server.py

Notes
-----
* MCP's stdio transport frames each message as one line of JSON. We preserve
  unknown/pass-through traffic verbatim.
* When a call is blocked we answer the client with a JSON-RPC *result* carrying
  ``isError: true`` (an MCP tool error), so the agent degrades gracefully
  instead of the whole session faulting.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from typing import Any, TextIO

from .audit import AuditLog
from .policy import Policy
from .sentinel import Sentinel
from .types import Action, ToolCall, ToolDef, ToolResult


class StdioProxy:
    def __init__(self, server_cmd: list[str], sentinel: Sentinel):
        self.server_cmd = server_cmd
        self.sentinel = sentinel
        # request id -> (method, tool_name) so we can classify responses.
        self._pending: dict[Any, tuple[str, str | None]] = {}
        self._lock = threading.Lock()

    def run(
        self,
        client_in: TextIO | None = None,
        client_out: TextIO | None = None,
    ) -> int:
        client_in = client_in or sys.stdin
        client_out = client_out or sys.stdout
        proc = subprocess.Popen(
            self.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert proc.stdin and proc.stdout

        up = threading.Thread(
            target=self._pump_client_to_server,
            args=(client_in, proc.stdin, client_out),
            daemon=True,
        )
        up.start()
        try:
            # Server -> client runs in the main thread until the server closes.
            self._pump_server_to_client(proc.stdout, client_out)
            return proc.wait()
        finally:
            up.join(timeout=1.0)
            for stream in (proc.stdin, proc.stdout):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass

    # -- client -> server -----------------------------------------------------
    def _pump_client_to_server(
        self, client_in: TextIO, server_in: TextIO, client_out: TextIO
    ) -> None:
        for line in client_in:
            line = line.rstrip("\n")
            if not line:
                continue
            msg = _try_json(line)
            if msg is None:
                server_in.write(line + "\n")
                server_in.flush()
                continue

            method = msg.get("method")
            if method == "tools/call":
                decision, blocked_response = self._on_call(msg)
                if blocked_response is not None:
                    # Do not forward; answer the client directly.
                    _write(client_out, blocked_response)
                    continue
            if "id" in msg and method:
                tool = None
                if method == "tools/call":
                    tool = (msg.get("params") or {}).get("name")
                with self._lock:
                    self._pending[msg["id"]] = (method, tool)

            server_in.write(json.dumps(msg) + "\n")
            server_in.flush()

    # -- server -> client -----------------------------------------------------
    def _pump_server_to_client(self, server_out: TextIO, client_out: TextIO) -> None:
        for line in server_out:
            line = line.rstrip("\n")
            if not line:
                continue
            msg = _try_json(line)
            if msg is None:
                client_out.write(line + "\n")
                client_out.flush()
                continue

            method, tool = None, None
            if "id" in msg:
                with self._lock:
                    method, tool = self._pending.pop(msg["id"], (None, None))

            if method == "tools/list":
                msg = self._on_tools_list(msg)
            elif method == "tools/call":
                msg = self._on_result(msg, tool)

            _write(client_out, msg)

    # -- interception hooks ---------------------------------------------------
    def _on_tools_list(self, msg: dict) -> dict:
        result = msg.get("result") or {}
        raw_tools = result.get("tools") or []
        defs = [
            ToolDef(t.get("name", ""), t.get("description", ""),
                    t.get("inputSchema", {}))
            for t in raw_tools
        ]
        safe, _ = self.sentinel.inspect_tools(defs)
        safe_names = {t.name for t in safe}
        result["tools"] = [t for t in raw_tools if t.get("name") in safe_names]
        msg["result"] = result
        return msg

    def _on_call(self, msg: dict) -> tuple[Any, dict | None]:
        params = msg.get("params") or {}
        call = ToolCall(
            tool=params.get("name", ""),
            arguments=params.get("arguments", {}) or {},
            call_id=str(msg.get("id", "")),
        )
        decision = self.sentinel.guard_call(call)
        if decision.blocked:
            return decision, _error_result(msg.get("id"), decision.reason)
        return decision, None

    def _on_result(self, msg: dict, tool: str | None) -> dict:
        result = msg.get("result") or {}
        text = _flatten_content(result.get("content"))
        decision = self.sentinel.scrutinize_result(
            ToolResult(text=text, call_id=str(msg.get("id", "")))
        )
        if decision.action is Action.BLOCK:
            msg["result"] = _content_block(
                f"[blocked by mcp-sentinel] {decision.reason}", is_error=True
            )
        elif decision.action is Action.SANITIZE and decision.sanitized_text is not None:
            msg["result"] = _content_block(decision.sanitized_text)
        return msg


# -- small JSON-RPC / MCP helpers --------------------------------------------
def _try_json(line: str) -> dict | None:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _write(out: TextIO, msg: dict) -> None:
    out.write(json.dumps(msg) + "\n")
    out.flush()


def _flatten_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return str(content)


def _content_block(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _error_result(msg_id: Any, reason: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": _content_block(f"[blocked by mcp-sentinel] {reason}",
                                 is_error=True),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP Sentinel stdio proxy")
    parser.add_argument("--policy", help="path to a JSON policy file")
    parser.add_argument(
        "server", nargs=argparse.REMAINDER,
        help="-- followed by the MCP server command to wrap",
    )
    args = parser.parse_args(argv)
    cmd = args.server[1:] if args.server and args.server[0] == "--" else args.server
    if not cmd:
        parser.error("provide the server command after `--`")

    policy = Policy.load(args.policy) if args.policy else Policy()
    sentinel = Sentinel(policy=policy, audit=AuditLog(stream=sys.stderr))
    return StdioProxy(cmd, sentinel).run()


if __name__ == "__main__":
    raise SystemExit(main())
