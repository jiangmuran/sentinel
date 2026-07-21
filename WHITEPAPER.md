# Sentinel: A Trust Runtime for AI Agents

**A provenance-based defense against the LLM Scope Violation class of attacks.**

Version 0.1 · Apache-2.0 · Built for the GOAI open-source challenge

---

## Abstract

As AI agents move from answering questions to *taking actions* — spending money,
sending messages, executing code, and delegating to other agents — the dominant
security risk shifts. It is no longer that a model produces bad text; it is that
**untrusted content coerces the agent into a privileged, irreversible action**.
Aim Security named this pattern *LLM Scope Violation*; it is the root cause
behind the 2025 EchoLeak (CVE-2025-32711), GitHub-MCP, and tool-poisoning
disclosures.

Content filters — signature or LLM-based — mitigate this only indirectly: they
ask *"does this text look malicious?"* and are defeated by paraphrase,
translation, encoding, and roleplay. Sentinel adds the missing layer. It is a
**trust runtime**: a transport-agnostic guard in the data path that (1) detects
injection, (2) enforces least privilege, and — the core contribution —
(3) tracks **provenance** so that any high-stakes action whose parameters derive
from untrusted content is refused at the action layer. Sentinel is deterministic,
dependency-free, ships with an open benchmark (SentinelBench), and is proven
end-to-end against the official Model Context Protocol (MCP) SDK.

---

## 1. The problem

### 1.1 Agents now act

In 2024, an "agent" was mostly a chatbot with retrieval. By 2026 it is a system
that autonomously calls tools that move money, send email, run shell commands,
and hand work to other agents. Every one of those tools consumes **untrusted
input**: web pages, documents, tickets, other servers' responses. The moment an
agent both (a) reads attacker-influenceable data and (b) can take a consequential
action, the two can be connected by an adversary.

### 1.2 LLM Scope Violation

The unifying vulnerability is not "prompt injection" in the abstract; it is the
concrete event that **untrusted data crosses into a privileged action** — reading
a secret, wiring a payment, deleting a resource. Aim Security's analysis of
EchoLeak named this *LLM Scope Violation*. It reframes the defense target: we do
not need to perfectly classify text as malicious; we need to prevent untrusted
content from *reaching* a high-stakes action.

### 1.3 It is already public

| Disclosure | Date | Mechanism |
|---|---|---|
| EchoLeak (CVE-2025-32711) | 2025-06 | Zero-click indirect injection exfiltrates M365 Copilot data via one email |
| GitHub MCP exploit | 2025-05 | A malicious issue coerces the agent into leaking private repositories |
| MCP Tool Poisoning | 2025-04 | Hidden instructions in a tool description hijack the agent at discovery |

See [References](#references). MCP — now stewarded by the Linux Foundation's
Agentic AI Foundation (AAIF) — standardizes *how* agents connect to tools but
ships **no defense** for any of the above.

---

## 2. Why detection alone is insufficient

A pure content filter has two structural weaknesses:

1. **It is an arms race on the text.** Attackers paraphrase, translate (a German
   or Chinese injection evades an English-only filter), base64-encode, or wrap
   the instruction in a roleplay frame. We demonstrate this honestly: SentinelBench
   includes a *hard tier* of semantic/cross-lingual/encoded attacks that our
   signature layer is *expected to miss* (see §5).
2. **It cannot see consequences.** Even a perfect classifier of "malicious text"
   does not tell you whether that text actually flowed into a wire transfer. The
   security-relevant event is the data flow, not the string.

Sentinel therefore treats detection as necessary but not sufficient, and adds a
provenance layer that targets the consequence directly.

---

## 3. Threat model

**Trusted:** the agent runtime, the user's intent, Sentinel itself, and the
policy configuration.

**Untrusted:** every MCP server and the content it returns — tool *descriptions*
(read at discovery), tool *results* (read after a call), and by extension any
external data an otherwise-trusted tool fetches (the GitHub-MCP class).

**Adversary goal:** cause the agent to perform a high-stakes action (exfiltration,
payment, code execution, deletion, delegation) that the user did not intend, by
planting instructions or data in untrusted content.

**Out of scope (v0.1):** a compromised agent runtime or model weights; attacks
that never touch a Sentinel-observed boundary; covert channels inside model
reasoning that leave no textual trace in tool I/O.

---

## 4. Design: the trust runtime

Sentinel sits in the data path as a proxy. The agent connects to Sentinel exactly
as it would to the server; no client changes are required. It guards the three
trust boundaries of a tool-using session.

```
        ┌──────────────────── Sentinel ────────────────────┐
 agent ─┤ guard_call        (least privilege + PROVENANCE)  ├─ untrusted
  (LLM) ┤ scrutinize_result (injection scan + taint)        ┤   tools /
        │ inspect_tools     (tool-poisoning scan)           │   servers
        └──────────────── audit log (JSONL) ────────────────┘
```

Each inspected message yields a `Decision`: **ALLOW**, **SANITIZE** (forward with
invisible-character smuggling stripped), or **BLOCK**.

### 4.1 Signature detection

A fast, deterministic, dependency-free detector across 20+ categories, in
**English and Chinese**: instruction override, role reassignment, injected
system/assistant turns, secret-read directives, exfiltration channels,
tool-steering / confused-deputy, markdown-image exfiltration, and obfuscation
(zero-width joiners, Unicode tag-block "ASCII smuggling", ANSI/OSC escapes). The
detector is a `Detector` protocol; a `CompositeDetector` layers an LLM classifier
behind the same interface (via `CallableDetector`) with no dependency on any
model SDK.

Two design choices that matter for precision and robustness:

- **Precision over eagerness.** A directive to read a *secret* blocks; the phrase
  "read a file" does not. Over-blocking legitimate workflows is how filters earn
  distrust; SentinelBench's benign controls (§5) keep this measurable.
- **Re-scan after de-obfuscation.** A SANITIZE decision strips zero-width / tag /
  ANSI characters and then *re-scans*. An injection hidden behind zero-width
  joiners ("i‍g‍n‍o‍r‍e all instructions") is thereby caught after unmasking and
  escalated to BLOCK.

### 4.2 Least-privilege policy

A JSON policy (reviewable in CI) constrains each tool: allow-list posture,
per-argument deny patterns (path traversal, secret paths, SSRF ranges), rate
limits, and an explicit `stakes` level. Policy denial short-circuits before
content scanning.

### 4.3 Provenance / taint tracking — the core contribution

The central idea: instead of asking whether text *looks* malicious, ask whether
an **irreversible action originated from untrusted content**. Sentinel answers
this as a data-flow property.

**Tainting.** When a tool result is scrutinized and flagged (any severity), its
*distinctive tokens* are recorded as a session taint. A token is distinctive if
it is long (≥6 chars) and not a common lowercase word — account ids, emails,
URLs, hex, and ALLCAPS markers qualify; "instructions" and "following" do not.
This avoids false taints on ordinary language.

**Action classification.** Each call is classified by blast radius —
`payment | exec | delete | send | delegate | write` (high-stakes) versus a
low-stakes default — by tool-name convention, overridable per tool via policy.

**Gating.** For a high-stakes call, Sentinel checks whether any argument value
contains a tainted token. If so, the action's parameters derive from untrusted
content, and the call is **BLOCKED** with the provenance chain in the audit log.

```
on scrutinize_result(result):
    findings = detect(result.text)
    if findings:                       # untrusted & suspicious
        taint[session] += distinctive_tokens(result.text)

on guard_call(call):
    if policy.denies(call): BLOCK
    if actions.is_high_stakes(call):
        for token in taint[session]:
            if token in any(str(arg) for arg in call.args):
                BLOCK  # provenance: parameter derives from untrusted content
    ...
```

Crucially this is **precise, not blunt**: a payment whose recipient came from a
*clean* page is allowed; the identical payment whose recipient came from a
*flagged* page is blocked. It is not "block all payments."

This is a deterministic, dependency-free runtime approximation of taint tracking
for agents — the missing production runtime for the LLM Scope Violation class.

### 4.4 Accountability

Every decision is appended to a structured, replayable JSONL audit log — including
the taint id, matched token, and reason for each provenance block. Autonomous
agents lack the "are you sure?" confirmation and undo that humans get; the audit
log is the accountability ledger that makes an agent's actions reviewable after
the fact.

---

## 5. SentinelBench

Detection rate is meaningless without measuring over-blocking: a block-everything
filter scores 100% detection *and* 100% false positives. SentinelBench therefore
scores **precision and recall together**, with benign controls as first-class
cases.

**Corpus (v0):** 71 cases across 21 categories, each mapped where applicable to
the **OWASP MCP Top 10 (2025)**. Two difficulty tiers:

- **Core** — keyword/structural attacks a signature layer should catch.
- **Hard** — semantic, cross-lingual (German), roleplay, and base64-encoded
  attacks with no signature surface. Signatures are *expected* to miss these; the
  tier quantifies the gap the LLM detector tier is meant to close. Reporting a
  realistic sub-100% number here is the point.

**Results (signature layer, default config):**

| Metric | Result |
|---|---|
| Core detection | **100%** (41/41) |
| False-positive rate | **0%** (0/22 benign) |
| Hard-tier detection | 0% (0/8) — the LLM tier's job |

The runner exits non-zero only on a *regression* (a core miss or a false
positive), so it doubles as a CI gate.

**Relation to prior benchmarks.** AgentDojo and InjecAgent measure whether a
*model* complies with injections end-to-end. SentinelBench measures the
complementary, cheaper-to-run property: the precision **and** recall of a *guard*
at the payload/action layer.

---

## 6. Evaluation on the real MCP protocol

Beyond unit tests, Sentinel is validated end-to-end against the **official MCP
Python SDK**. A genuine `mcp.ClientSession` connects, over real stdio MCP framing,
to a genuine FastMCP server *through* the Sentinel proxy:

- A poisoned tool is quarantined from discovery; a benign tool survives; an
  injected result is blocked; a benign call returns untouched.
- In the agentic-commerce test, the client browses a poisoned product listing and
  then issues a payment; the payment to the attacker's account is **blocked by the
  provenance gate over the real wire**, while a legitimate payment is allowed.

The whole system is clone-and-run with **zero runtime dependencies**; 40 tests
pass.

---

## 7. Limitations (stated honestly)

- **Signatures miss the hard tier.** Semantic, cross-lingual, and encoded
  injections require the LLM detector tier (roadmap). We report this openly.
- **Taint matching is token-based.** If an agent *paraphrases* attacker content
  before using it (e.g. rewrites an account id), token-level provenance can miss
  it. Semantic provenance is future work.
- **Provenance needs a source.** Content the agent never routed through Sentinel
  is not tainted. Sentinel must be in the data path for all untrusted surfaces.
- **v0.1 covers MCP stdio.** HTTP/SSE and A2A transports are on the roadmap.

None of these are hidden by the benchmark — they are *why* the benchmark has a
hard tier and benign controls.

---

## 8. Roadmap

1. Reference LLM detector adapter behind the `Detector` protocol (lift the hard tier).
2. HTTP/SSE transport, then **A2A / agent-to-agent** provenance.
3. Semantic (embedding-based) provenance to survive paraphrase.
4. MCP server reputation / supply-chain allow-listing.
5. A public **SentinelBench leaderboard** others submit to.
6. Alignment / contribution path to AAIF `AgentGateway`.

---

## 9. Related work

- **Invariant Labs** — disclosed MCP tool poisoning and the GitHub-MCP exploit;
  ships `mcp-scan` for poisoned-description detection.
- **OWASP MCP Top 10 (2025)** — taxonomy Sentinel maps its categories to.
- **AgentDojo, InjecAgent** — end-to-end model-susceptibility benchmarks;
  complementary to SentinelBench's guard-precision focus.
- Academic defenses (multi-stage MCP guards, etc.) largely operate at the
  content/classification layer; Sentinel's distinguishing contribution is
  **provenance gating at the action layer**.

---

## 10. Vision: the trust layer for the agent economy

Encryption is not optional for web traffic; every request carries TLS. As agents
begin to transact, delegate, and act autonomously, **every consequential action
will need a provenance and trust check** — a way to answer *what is allowed, where
did this come from, and who is accountable*. Sentinel is a first, working piece of
that substrate. Its addressable surface is not "MCP users" but **every autonomous
agent deployment** — a category that is only beginning to exist.

---

## References

- Aim Security — *EchoLeak*, CVE-2025-32711 (2025-06). NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-32711>
- Invariant Labs — *MCP Tool Poisoning Attacks* (2025-04-06). <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
- Invariant Labs — *GitHub MCP Exploited* (2025-05-26). <https://invariantlabs.ai/blog/mcp-github-vulnerability>
- OWASP — *MCP Top 10 (2025)*. <https://owasp.org/www-project-mcp-top-10/>
- Debenedetti et al. — *AgentDojo* (NeurIPS 2024). <https://agentdojo.spylab.ai/>
- Zhan et al. — *InjecAgent* (2024). <https://arxiv.org/abs/2403.02691>

*Dates and CVE identifiers are the cited authors' own figures; please verify
against the primary sources before relying on them.*

---

## Appendix A — category → rule → OWASP mapping

| Attack category | Example rule(s) | OWASP MCP |
|---|---|---|
| Tool poisoning (description) | `SEC002`, `TUL001`, `INJ00x` | MCP03 |
| Indirect injection (result) | `INJ001–004` | MCP01 |
| Secret exfiltration | `SEC001/002`, `EXF001` | MCP01 |
| Confused deputy / cross-server | `TUL001`, provenance | MCP08 |
| ASCII / ANSI smuggling | `OBF001/002/004` | MCP01 |
| Chinese-language injection | `CJK001/002/003` | MCP01/03 |
| High-stakes action from untrusted content | provenance gate | MCP01 |
