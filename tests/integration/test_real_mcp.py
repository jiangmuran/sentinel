"""Real end-to-end integration test against the OFFICIAL MCP SDK.

A genuine MCP client (`mcp.ClientSession`) connects — over real stdio MCP
framing — to a genuine FastMCP server, but *through* the Sentinel proxy:

    client  ⇄  mcp_sentinel.proxy  ⇄  examples/real_server.py (FastMCP)

This proves protocol compatibility and that Sentinel:
  * quarantines the poisoned tool from discovery,
  * blocks the injected tool result,
  * passes benign tools/calls through untouched.

Requires `pip install "mcp>=1.2"` and the package installed (`pip install -e .`).
Skipped automatically if the SDK is absent, so the stdlib unit suite stays
dependency-free.
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REAL_SERVER = ROOT / "examples" / "real_server.py"

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAVE_MCP = True
except ImportError:
    HAVE_MCP = False


async def _drive_through_proxy():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_sentinel.proxy", "--", sys.executable, str(REAL_SERVER)],
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = [t.name for t in listed.tools]

            weather = await session.call_tool("get_weather", {"city": "Hangzhou"})
            weather_text = _text_of(weather)
            weather_error = bool(getattr(weather, "isError", False))

            add = await session.call_tool("add", {"a": 2, "b": 3})
            add_text = _text_of(add)
            return names, weather_text, weather_error, add_text


def _text_of(result) -> str:
    parts = []
    for block in result.content:
        parts.append(getattr(block, "text", ""))
    return "\n".join(parts)


@unittest.skipUnless(HAVE_MCP, "official mcp SDK not installed")
class TestRealMCP(unittest.TestCase):
    def test_end_to_end_through_proxy(self):
        names, weather_text, weather_error, add_text = asyncio.run(
            _drive_through_proxy()
        )

        # 1. Poisoned tool quarantined at discovery; benign tool survives.
        self.assertIn("add", names)
        self.assertNotIn("get_weather", names)

        # 2. If the tool is called anyway, the injected result is blocked.
        self.assertTrue(weather_error)
        self.assertIn("blocked by mcp-sentinel", weather_text)
        self.assertNotIn("IGNORE PREVIOUS INSTRUCTIONS", weather_text)

        # 3. Benign call passes through untouched.
        self.assertIn("5", add_text)


if __name__ == "__main__":
    unittest.main()
