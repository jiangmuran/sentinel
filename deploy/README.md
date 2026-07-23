# Deploying GuardTeam on AgentTeams (复赛)

GuardTeam is built to the same shape as Alibaba's
[AgentTeams](https://github.com/agentscope-ai/AgentTeams) — Manager + Workers,
a shared room, and **Skills consumed over MCP** — so moving from the local
closed loop to a real deployment is a mapping, not a rewrite.

## How the pieces map

| GuardTeam (this repo)                     | AgentTeams primitive                    | Status |
|-------------------------------------------|-----------------------------------------|--------|
| `Manager` (`guardteam/team.py`)           | Manager agent / orchestrator            | code   |
| 4 Workers (aggregator/locator/planner/auditor) | Worker agents (≥3 required)         | code   |
| `Room` transcript                         | Matrix room (message bus)               | code → Matrix |
| `Room` blackboard                         | MinIO shared file system                | code → MinIO |
| **Skills MCP server** (`guardteam/mcp_server.py`) | MCP Skills behind the Higress gateway | **runnable container** |
| `Mandate` signing secret (env)            | gateway-held credential (never in Worker) | env / vault |

The four Skills — `injection_scan`, `taint_untrusted`, `authorize_payment`,
`verify_receipt` — are what a Worker calls over MCP. They're verified end-to-end
with a **real MCP client** in `tests/integration/test_skills_mcp.py`.

## Run the Skills server

```bash
# Container (networked transport, for a gateway):
docker compose -f deploy/docker-compose.yml up --build     # serves on :8000

# Or directly:
GUARDTEAM_SECRET=... python -m guardteam serve-mcp --transport streamable-http
```

A Worker's MCP client then points at `http://<host>:8000`. Configure the mandate
via env (`GUARDTEAM_MAX_AMOUNT`, `GUARDTEAM_ALLOWLIST`, `GUARDTEAM_BUDGET`, …);
the signing secret stays server-side, mirroring the Higress credential-isolation
model — a hijacked Worker can request a payment but can never forge a mandate.

## What's verified vs. what's a template

- **Verified in CI:** the Skills server over MCP (stdio transport), all
  enforcement logic, both benchmarks, the full multi-agent loop.
- **Template (needs the real stack):** the Matrix room, MinIO shared FS, and
  Higress gateway wiring are AgentTeams-provided infrastructure — this repo
  provides the containerized Skills server and the role logic that plug into
  them. The `--transport streamable-http` path is the deployment transport;
  bring it up against your AgentTeams cluster.
