# burp-mcp — Claude Code plugin for Burp Suite

A Claude Code **plugin** (MCP server + skills + hooks) that wraps PortSwigger's official Burp MCP extension
(SSE on `127.0.0.1:9876`). Adds scope enforcement, tiered HITL gates, response
quarantine, report-path confinement, auth-header scrubbing, and engagement
state (`reports/<slug>/engagement.yaml`) that survives Burp Community restarts.

Full install + usage guide: **see `docs/guide.md`** (pending).

---

## Quick install

```bash
# 1. Clone
git clone https://github.com/<you>/burp-mcp.git
cd burp-mcp

# 2. Install Python package (registers burp-stdio + burp-mcp on PATH)
pip install -e .

# 3. Install slash commands user-globally, so /pentest-* resolve from any dir
burp-mcp install-skills

# 4. Register MCP servers at user scope (one time, per Claude Code install)
cp .mcp.json.example .mcp.json   # or register via `claude mcp add --scope user`
```

## Run from any directory

```bash
cd ~/engagements/acme-corp     # anywhere you want reports written
export BURP_MCP_REPORTS_DIR="$(pwd)/reports"   # optional; defaults to ./reports

# in Claude Code:
/pentest-start acme-corp AcmeCorp app.acme.example,api.acme.example
/pentest-recon acme-corp
# ...through /pentest-report
```

## Prereqs

- Burp Suite Community (or Pro) with the "MCP Server" BApp extension loaded
  → SSE on `127.0.0.1:9876`
- Python ≥ 3.11
- Chrome configured to proxy through Burp (`--proxy-server=127.0.0.1:8080
  --proxy-bypass-list="<-loopback>"`)

## Config knobs

| Env var | Default | Purpose |
|---------|---------|---------|
| `BURP_MCP_HTTP` | `http://127.0.0.1:9876/mcp` | Upstream Burp MCP URL |
| `BURP_MCP_REPORTS_DIR` | `./reports` in CWD | Where findings + engagement state land |

Scope is loaded per engagement from `engagement.yaml` via `/pentest-start` —
not hardcoded in source.

## Files

- `server.py` — stdio MCP server; proxies to upstream SSE
- `safety.py` — 5-control spine (scope, HITL, quarantine, confinement, auth scrub)
- `persist.py` — JSONL request log + markdown finding writer + engagement state
- `cli.py` — `burp-mcp install-skills`
- `.claude/commands/` — the `/pentest-*` slash commands
- `templates/engagement.yaml` — engagement state template

## Smoke test

```
burp-stdio
# should print: burp-safety-proxy starting — upstream=http://127.0.0.1:9876/mcp
```

Then in Claude Code with `.mcp.json` present:
- `list_upstream_tools` → list of Burp tools
- `http_get url=http://localhost/` → `[OK]` with wrapped body
- `http_get url=http://evil.com/` → `BLOCKED: out-of-scope host 'evil.com'`
