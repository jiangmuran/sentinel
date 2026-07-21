# GOAI Submission Checklist — Sentinel

Track: **新智基座 / Agent Infra**. Sources: goaihz.com + official press (2026-07).
Deadline for our track: **Aug 16, 2026** (具身未来 is Aug 20). Finals: Sept 22–23, Hangzhou.

## What GOAI asks you to submit

| Required item | Our asset | Status |
|---|---|---|
| **可运行 Demo** (runnable demo) | `examples/payment_demo.py`, `examples/demo.py`, `python -m benchmark.runner`, real-SDK integration tests | ✅ runnable, zero-dep |
| **代码仓库** (code repository) | this repo (Apache-2.0) | ⚠️ **needs a public GitHub repo** (blocker — needs you) |
| **技术方案** (technical proposal) | `WHITEPAPER.md` + pitch deck (`web/pitch.html`) | ✅ |

## Evaluation dimensions → how we hit them

Official dimensions: *技术创新性 · 开源贡献度 · 真实场景/科研价值 · 方案完整性 · Demo可运行性 · 工程成熟度 · 团队长期成长潜力*.

| Dimension | Evidence |
|---|---|
| 技术创新性 | Provenance/taint gating at the **action layer** — a runtime for the LLM Scope Violation class, not another text filter |
| 开源贡献度 | Apache-2.0, EN+中文, pluggable `Detector`, **SentinelBench** (open, OWASP-mapped, benign-controlled) |
| 真实场景价值 | Stops the exact loss class behind EchoLeak (CVE-2025-32711) for agents that spend money today |
| 方案完整性 | Whitepaper + deck + landing page + threat model + roadmap + honest limitations |
| Demo 可运行性 | Clone-and-run, deterministic, **proven on the official MCP SDK**; benchmark as a CI gate |
| 工程成熟度 | 40 tests, 0 runtime deps, structured audit log, policy-as-config |
| 团队长期潜力 | A citable benchmark + a category ("trust runtime for the agent economy") |

## Open-source compliance (required by the rules)

- [x] Explicit license — **Apache-2.0** (`LICENSE`)
- [x] Third-party dependencies stated — **zero runtime deps**; dev/test uses the official `mcp` SDK (declared in `pyproject.toml` extras)
- [x] IP boundary clear — all original; attack payloads are inert defensive fixtures
- [x] Commercial model/API usage disclosed — none required (deterministic core); the optional LLM detector tier is bring-your-own and disclosed as such

## Gaps before submission (priority order)

1. **Public GitHub repo** — required as the 代码仓库 deliverable. *Needs you* (repo or `gh` access). Unblocks CI + Pages + a citable star count.
2. **Register on goaihz.com** and note the team/track. *Needs you.*
3. **Demo video (≤ ~2 min)** — screen-capture of `payment_demo.py` + the live injection tester. I can write the shot-list/script; recording needs a screen.
4. **中文 版 pitch / one-pager** — for the China-hosted judges. *I can build this autonomously* (next loop iteration).

## Timeline

- Now → Aug 16: finalize repo, demo video, 中文 materials, grow SentinelBench + traction.
- Aug 16: submit (demo + repo + whitepaper/deck).
- Aug–Sept: 初赛 → 复赛.
- Sept 22–23: finals in Hangzhou (finalists attend in person).
