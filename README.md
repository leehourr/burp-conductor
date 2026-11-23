# burp-conductor — MCP pentest harness

An **MCP plugin** (server + slash-command skills + hooks) that conducts a
full web-app engagement from any MCP-capable AI harness — Claude Code,
Codex, Cline, Cursor, or any other MCP client.

> **Safe probes only.** Every phase skill is written to **verify, not exploit** —
> single-request checks, canary-based SSRF (interactsh), reflected-XSS markers
> that don't execute privileged actions, SQLi probes that read error state
> rather than drop or exfiltrate data, auth tests that stop at proof-of-access.
> No destructive payloads, no data exfiltration, no persistence, no lateral
> movement. Deliverable is "find the bug, prove it exists, document the fix" —
> not red-team post-exploitation. The HITL gate and `safety.py` enforce this
> at the tool-call layer; the skills enforce it at the methodology layer.

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

## Phase walkthrough

The engagement moves left-to-right through six phases. Each is a slash command
that reads and writes `reports/<slug>/engagement.yaml` as the single source of
truth — so a fresh session can resume mid-engagement with `/pentest-resume <slug>`.

| Command | Phase | What it does | Prereq |
|---------|-------|--------------|--------|
| `/pentest-start <slug> <client> <hosts>` | 0 · Bootstrap | Create `reports/<slug>/engagement.yaml`, load scope, print RoE and roadmap. No upstream tools fire. | — |
| `/pentest-recon <slug>` | 1 · Recon | Surface map (endpoints, auth boundary, hidden params, threat model). Katana crawl + Param Miner. Passive only — no active probes. Writes `verify_queue`. | start done |
| `/pentest-auth <slug>` | 2 · Auth | Login endpoint probes: rate-limit, user enumeration, session handling, JWT weaknesses, reset/MFA flow. HITL on every send. | recon done |
| `/pentest-access <slug>` | 3 · Access | Horizontal IDOR (object-level), vertical priv-esc (function-level), business-logic abuse. One object at a time, no mass sweeps. | auth done |
| `/pentest-inject <slug>` | 4 · Inject | SQLi (error + blind), reflected/stored XSS, SSRF via interactsh canary, HTTP method/content-type tamper. Drives the Nuclei scanner pass on `verify_queue`. | access done |
| `/pentest-roundout <slug>` | 5 · Roundout | OWASP Top 10:2025 sweep for gaps: headers, TLS, SCA (JS libs), deserialization, logging, exception info disclosure. | inject done |
| `/pentest-report <slug>` | 6 · Report | Assemble EN draft from per-finding markdown, hand off to Otoi-san for JP translation, prepare debrief. No upstream tools fire. | roundout done |

Plus one utility: **`/pentest-resume <slug>`** — reads engagement state, prints the status table, suggests the next step. Use it when picking up a stale engagement.

Every phase skill reprints the six-phase roadmap at five anchor moments (start, phase close, blocker, HITL ask, resume) so the harness stays oriented across long sessions.

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

