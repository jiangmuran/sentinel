# Contributing to MCP Sentinel

Thanks for helping make agent tool-use safer. This project is intentionally
small, dependency-free, and test-first — contributions that keep it that way are
the easiest to merge.

## Ground rules

- **Stdlib only** for the runtime. Keep `python -m benchmark.runner` and
  `python examples/demo.py` runnable on a fresh clone with no `pip install`.
- **Every change ships with a test.** Run the suite before opening a PR:
  ```bash
  python -m unittest discover -s tests -v
  ```
- **Detector changes must not regress SentinelBench.** Run
  `python -m benchmark.runner` — it must still report 100% detection / 0% FPR,
  or you must justify the trade-off and add the cases that moved.

## High-value contributions

- **New attack cases** for `benchmark/corpus.py` — especially real-world
  injection techniques we don't yet cover. Always add a matching benign control
  so precision stays measurable.
- **New detector signatures** in `src/mcp_sentinel/detector.py`.
- **An LLM-based detector** implementing the `Detector` protocol.
- **New transports** (HTTP/SSE) alongside the stdio proxy.

## Reporting a real-world injection

If you've seen an injection technique in the wild, open an issue with a minimal
reproduction (the tool description or result text). Inert strings only — do not
include live secrets or working exploit infrastructure.

## Security & scope

This is **defensive** tooling. Payloads in the repo are inert test fixtures.
PRs that turn it into an attack tool will be declined.
