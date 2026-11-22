# burp-conductor — MCP pentest harness

An **MCP plugin** (server + slash-command skills + hooks) that conducts a
full web-app engagement from any MCP-capable AI harness — Claude Code,
Codex, Cline, Cursor, or any other MCP client.

burp-conductor is **not just a Burp MCP wrapper**. The proxy, scanner, and
Repeater/Intruder work is delegated to PortSwigger's official Burp MCP
extension (streamable HTTP MCP at `http://127.0.0.1:9876/mcp`; SSE only as
fallback), but recon, SPA crawl, template-based active scanning, OOB
interaction, and novel-injection discovery are driven by a free stack of
ProjectDiscovery CLIs plus an in-repo differential fuzzer, invoked under
the same safety spine via `Bash` calls from the phase skills.

![burp-conductor engagement](assets/architecture.svg)

Why both: the Burp MCP alone exposes 26 tools but Burp **Community** ships
no Crawl, no Active Scanner, and no Collaborator. The free stack closes those
gaps — Katana crawls (headless Chrome for SPAs), Nuclei scans (fast-HTTP +
headless passes), interactsh gives us OOB canaries, `tools/diff_fuzz.py`
stands in for Backslash-Powered Scanner. Every free-stack call is scope-checked,
HITL-gated, and confines output to the session scratchpad — same rules as
MCP tool calls. Full rationale and install matrix in `CLAUDE.md`.

The slash-command skills under `.claude/commands/` are Claude Code-native
(that's where the `/pentest-*` convention is best supported today), but the
MCP server itself is transport-standard — any client that speaks MCP can
call it.

---

## Safety spine

Every tool call — MCP or free-stack Bash — passes through `safety.py`:

| Control | What it does |
|---------|--------------|
| Scope | Rejects any host not in `engagement.yaml` `scope.hosts` |
| HITL | Gates upstream firing tools (`send_http1_request`, `create_repeater_tab`, `send_to_intruder`, scanner trigger) behind explicit "go" |
| Quarantine | Wraps response bodies in `<spotlight>`; `quarantine="true"` stops action |
| Confinement | All writes forced under `reports/` with path-traversal block |
| Auth scrub | Strips `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token` from the JSONL log |
| Identity | Injects a unique `X-Pentest-ID: <company>/<slug>/<yyyy-mm-dd>` header on every outbound call so client blue teams can filter us out of SIEM/WAF |

---

## Quick install

```bash
# 1. Clone
git clone https://github.com/leehourr/burp-conductor.git
cd burp-conductor

# 2. Install Python package (registers burp-stdio + burp-conductor on PATH)
pip install -e .

# 3. Install slash commands user-globally, so /pentest-* resolve from any dir
#    (Claude Code only — other MCP harnesses skip this step)
burp-conductor install-skills

# 4. Register MCP servers at user scope (one time, per Claude Code install)
cp .mcp.json.example .mcp.json   # or register via `claude mcp add --scope user`

# 5. Install the free stack (one-time)
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
nuclei -update-templates
# diff_fuzz ships in-repo at tools/diff_fuzz.py — no install needed
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
  → streamable HTTP MCP at `http://127.0.0.1:9876/mcp` (SSE is a fallback transport only)
- Python ≥ 3.11
- A recent Go toolchain (for `go install` of Katana / Nuclei / interactsh — see each project's README for the current minimum)
- Google Chrome (required for `-headless -system-chrome` passes)
- Chrome configured to proxy through Burp (`--proxy-server=127.0.0.1:8080
  --proxy-bypass-list="<-loopback>"`)

## Config knobs

| Env var | Default | Purpose |
|---------|---------|---------|
| `BURP_MCP_HTTP` | `http://127.0.0.1:9876/mcp` | Upstream Burp MCP URL |
| `BURP_MCP_REPORTS_DIR` | `./reports` in CWD | Where findings + engagement state land |

Scope and identity are loaded per engagement from `engagement.yaml` via
`/pentest-start` — not hardcoded in source.

## Repo layout

- `server.py` — stdio MCP server; proxies to upstream Burp MCP over streamable HTTP (SSE fallback)
- `safety.py` — safety spine (scope, HITL, quarantine, confinement, auth scrub, identity injection)
- `persist.py` — JSONL request log + markdown finding writer + engagement state
- `cli.py` — `burp-conductor install-skills`
- `tools/diff_fuzz.py` — Community-edition Backslash-Powered Scanner stand-in
- `.claude/commands/` — the six `/pentest-*` slash commands (recon / auth / access / inject / roundout / report)
- `templates/engagement.yaml` — engagement state template
- `research/` — walkthrough docs and source citations (HTML; marked `linguist-documentation`)

**Not in the repo:** `reports/` is fully gitignored. Engagement output —
findings, JSONL logs, screenshots, practice-lab runs — stays local. The
harness recreates the tree per engagement from `templates/engagement.yaml`.

## Smoke test

```
burp-stdio
# should print: burp-safety-proxy starting — upstream=http://127.0.0.1:9876/mcp
```

Then in Claude Code with `.mcp.json` present:
- `list_upstream_tools` → list of Burp tools
- `http_get url=http://localhost/` → `[OK]` with wrapped body
- `http_get url=http://evil.com/` → `BLOCKED: out-of-scope host 'evil.com'`
