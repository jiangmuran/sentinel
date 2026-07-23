# GOAI Submission Checklist — Sentinel GuardTeam

Track: **新智基座 / Agent Infra**, reference direction **#4 金融风控与理赔自动化**.
Sources: goaihz.com `/tracks?track=infra`, `/faq` (2026-07). Team ≤ 3 people.
初赛 deadline: **Aug 16, 2026**. Finals: **Sept 22–23, Hangzhou** (finalists attend in person).

> **Reframe (2026-07-22):** the track detail page reveals hard requirements that a
> single-purpose library does NOT meet. We reframe into a **multi-agent financial
> risk-control closed-loop on AgentTeams**, with Sentinel as the security + audit
> Skills. See [`GOAI_INFRA_PROPOSAL.md`](GOAI_INFRA_PROPOSAL.md).

## Hard requirements of this track (must-haves)

- [x] **≥3 different-function agents in a complete closed loop** → 4 agents: 信号聚合 → 风险定位 → 处置方案 → 合规审计
- [ ] **Must use AgentTeams** (github.com/agentscope-ai/AgentTeams) as the multi-agent coordination base → Manager-Workers orchestration *(build for 复赛)*
- [x] **Skills are mandatory** (input/output, invocation, deps, failure handling, reuse) → 4 Sentinel Skills: `mandate.check`, `provenance.trace`, `receipt.sign`, `injection.scan`
- [x] Recommended: MCP integration, observability (Trace/Log) → MCP-native; JSONL audit log

## Deliverables by stage

| Stage | Required | Status |
|---|---|---|
| **初赛** (Aug 16) | 作品简介 (≤500字) + 方案 PPT/PDF + 可执行代码包(可选) | 简介 ✅ (372字, see proposal) · PPT ⏳ (reframe deck) · Skills code ✅ |
| **复赛** | 更新 PPT/PDF + 可执行 AgentTeams 代码包 + 可运行 Demo/视频 | ⏳ build the 4-agent AgentTeams loop |
| **决赛** | 路演 PPT + 现场 Demo + 代码仓库最终版 | ⏳ |

## Evaluation dimensions & weights → how we hit them

| Dimension (weight) | Evidence |
|---|---|
| 场景价值与行业可复制性 **25%** | 金融风控/理赔是刚需;可迁移到反欺诈、理赔核验、支付合规 |
| 多Agent协同与自主闭环 **25%** | 4 agents, clear responsibilities, exception handling via runtime block + human-in-loop |
| Skill工程体系与生态复用 **25%** | 4 Sentinel Skills, MCP-exposed, cross-Team reusable, full I/O + failure specs |
| 工程落地/运行验证/**安全可审计** **20%** | **our strength** — signed receipts, JSONL trace, mandate audit, real-SDK verified |
| 开放/开源贡献 **5%** | Apache-2.0, SentinelBench (OWASP-mapped) + CommerceBench, interface contracts + docs |

**Differentiator:** the only risk-control multi-agent system whose agents provably
can't be hijacked into fraudulent payments — directly wins the 20% 安全可审计 and is a
moat no other team has (Sentinel is already open, tested, benchmarked).

## Open-source compliance (required)

- [x] License **Apache-2.0** · [x] deps stated (zero runtime; `mcp` test extra) · [x] IP clear (inert fixtures) · [x] commercial API usage disclosed (none required)

## Gaps (priority order)

1. **Register on goaihz.com** — 新智基座 track, ≤3 people. *Needs you.*  ✅ repo is live: github.com/jiangmuran/sentinel
2. **Reframe deck → the GuardTeam multi-agent 风控 story** (初赛 PPT). *I can build.*
3. **Build the 4-agent AgentTeams loop** wrapping Sentinel Skills (复赛 code). *Bigger build.*
4. **Demo video** from `docs/DEMO_SCRIPT.md` (needs a screen).

## Assets already in hand (reused into the reframe)

Sentinel engine (mandate + provenance + signed receipt + injection detection),
46 tests, SentinelBench (71) + CommerceBench (10), real-MCP-SDK integration, live
site (jiangmuran.github.io/sentinel), whitepaper, EN/中文 materials — **the four
mandatory Skills already run and are tested.**
