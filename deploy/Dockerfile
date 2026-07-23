# Sentinel Skills — MCP server container.
#
# Serves the four GuardTeam Skills (injection_scan / taint_untrusted /
# authorize_payment / verify_receipt / mandate_info) over MCP, ready for an
# AgentTeams Worker (or any MCP client) to consume through the gateway.
#
#   docker build -f deploy/Dockerfile -t sentinel-skills .
#   docker run -e GUARDTEAM_SECRET=... -p 8000:8000 sentinel-skills
#
# The signing secret stays in the container's env — Workers never see it.
FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e ".[test]"   # [test] pulls the official mcp SDK

# The mandate + signing secret are configured via env (see guardteam/mcp_server.py):
#   GUARDTEAM_SECRET, GUARDTEAM_MAX_AMOUNT, GUARDTEAM_ALLOWLIST, GUARDTEAM_BUDGET, ...
ENV GUARDTEAM_SECRET=change-me-in-prod

EXPOSE 8000
# Networked transport for a gateway; use `stdio` for a co-located subprocess.
CMD ["python", "-m", "guardteam", "serve-mcp", "--transport", "streamable-http"]
