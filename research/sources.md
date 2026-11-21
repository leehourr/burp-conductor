# Research Sources

## OWASP Top 10:2025 — official category numbering (current)

Verified against https://top10.owasp.org/2025/ on 2026-11-08.

| Code | Name | Notes |
|------|------|-------|
| A01:2025 | Broken Access Control | Same as A01:2021 |
| A02:2025 | Security Misconfiguration | Was A05:2021 — moved up |
| A03:2025 | Software Supply Chain Failures | Was A06:2021 "Vulnerable and Outdated Components" — renamed + moved up |
| A04:2025 | Cryptographic Failures | Was A02:2021 — moved down |
| A05:2025 | Injection | Was A03:2021 — moved down |
| A06:2025 | Insecure Design | Was A04:2021 — moved down |
| A07:2025 | Authentication Failures | Was A07:2021 "Identification and Authentication Failures" — renamed |
| A08:2025 | Software or Data Integrity Failures | Was A08:2021 — minor rename |
| A09:2025 | Security Logging and Alerting Failures | Was A09:2021 "Logging and Monitoring Failures" — renamed |
| A10:2025 | Mishandling of Exceptional Conditions | NEW — replaces A10:2021 SSRF |
| SSRF removed | SSRF was A10:2021; has no slot in Top 10:2025 — reference CWE-918 | verified |
| Race conditions have no dedicated 2025 slot — closest is A06:2025 Insecure Design | inference | — |

## OWASP Top 10:2021 — superseded, kept for historical reference

| Code | Name |
|------|------|
| A01:2021 | Broken Access Control |
| A02:2021 | Cryptographic Failures |
| A03:2021 | Injection |
| A04:2021 | Insecure Design |
| A05:2021 | Security Misconfiguration |
| A06:2021 | Vulnerable and Outdated Components |
| A07:2021 | Identification and Authentication Failures |
| A08:2021 | Software and Data Integrity Failures |
| A09:2021 | Security Logging and Monitoring Failures |
| A10:2021 | Server-Side Request Forgery (SSRF) |

Source: https://owasp.org/Top10/2021/ — verified 2026-11-08

## Burp Sequencer — sample size

| Fact | URL | Date verified |
|------|-----|---------------|
| Minimum to start analysis: 100 tokens (unreliable) | https://portswigger.net/burp/documentation/desktop/tools/sequencer/sample | 2026-11-08 |
| Recommended minimum: ≥ 5,000 tokens | https://portswigger.net/burp/documentation/desktop/tools/sequencer/sample | 2026-11-08 |
| FIPS-compliant maximum: 20,000 tokens | https://portswigger.net/burp/documentation/desktop/tools/sequencer/results/tests | 2026-11-08 |
| Specific bit-count thresholds ("< 100 bits weak") are NOT in PortSwigger docs — removed from CLAUDE.md (inference, unverified) | https://portswigger.net/burp/documentation/desktop/tools/sequencer/results | 2026-11-08 |

## JWT attacks — alg:none and key confusion

| Fact | URL | Date verified |
|------|-----|---------------|
| alg:none bypass documented — server accepts unsigned token when alg header set to "none" | https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported | 2026-11-08 |
| RS256 → HS256 key confusion attack documented (use public key as HMAC secret) | https://portswigger.net/web-security/jwt | 2026-11-08 |
| No single CVE for the alg:none class — it is a library implementation flaw, not one CVE | https://portswigger.net/web-security/jwt | 2026-11-08 |

## Burp MCP server extension — endpoint

| Fact | URL | Date verified |
|------|-----|---------------|
| Default SSE endpoint: http://127.0.0.1:9876 (with or without `/sse` depending on client) | https://cdn.jsdelivr.net/gh/portswigger/mcp-server@main/README.md | 2026-11-15 |
| Extension bundles a stdio-to-SSE proxy for clients that only support stdio | https://cdn.jsdelivr.net/gh/portswigger/mcp-server@main/README.md | 2026-11-15 |

## Claude Code .mcp.json transport

| Fact | URL | Date verified |
|------|-----|---------------|
| `type` field accepts `stdio`, `sse`, `http`, `streamable-http` | https://code.claude.com/docs/en/mcp-configuration | 2026-11-15 |
| SSE is legacy; streamable-HTTP is preferred. Claude Code v2.1.265+ auto-falls back to SSE when HTTP is refused | https://code.claude.com/docs/en/mcp-configuration | 2026-11-15 |

## OWASP Juice Shop — docker

| Fact | URL | Date verified |
|------|-----|---------------|
| `docker run --rm -p 3000:3000 bkimminich/juice-shop` from Docker Hub listing | https://hub.docker.com/r/bkimminich/juice-shop | 2026-11-15 |
| `docker run -d -p 3000:3000 bkimminich/juice-shop` from OWASP's own help site | https://help.owasp-juice.shop/part1/running.html | 2026-11-15 |

## Burp MCP server extension — install / start (official)

Verified 2026-11-16 across PortSwigger BApp listing, deepwiki PortSwigger/mcp-server §3, and HackTricks AI-Burp-MCP.

| Fact | URL | Date verified |
|------|-----|---------------|
| Official install path is the BApp Store entry "MCP Server" — no CLI installer | https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc | 2026-11-16 |
| Offline/closed-network install: `Extensions → BApp Store → Import BApp file` with downloaded `.bapp` | https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/installing/manual-install | 2026-11-16 |
| After install, a dedicated `MCP` tab appears; enable under `Settings → MCP Server` with an `Enabled` tick (not on by default) | https://deepwiki.com/PortSwigger/mcp-server/3-installation-and-setup | 2026-11-16 |
| Port drift observed: default 9876, some builds surface 19876 — read Burp's Output tab, do not assume | https://www.pentest-book.com/others/burp | 2026-11-16 |
| For stdio-only clients (Codex CLI etc.), extract `mcp-proxy-all.jar` via the MCP tab's *Extract server proxy jar* button; invoke as `java -jar mcp-proxy-all.jar --sse-url http://127.0.0.1:9876` | https://hacktricks.wiki/en/AI/AI-Burp-MCP.html | 2026-11-16 |
| Claude Code speaks SSE/HTTP natively — proxy jar not required for `.mcp.json` entries using `type: sse` or `streamable-http` | https://code.claude.com/docs/en/mcp-configuration | 2026-11-16 |
| Session smoke test: `claude mcp list` + "what tools does burp-direct expose?"; ECONNREFUSED means extension is installed but not enabled/listening | — | 2026-11-16 |

## Claude Code `claude mcp add` — server registration

Verified 2026-11-16 against Claude Code official docs + third-party guides (mcp.so, sfeir cheatsheet).

| Fact | URL | Date verified |
|------|-----|---------------|
| Syntax: `claude mcp add --transport <sse\|http\|stdio> <name> <url-or-cmd>` — name BEFORE url | https://code.claude.com/docs/en/mcp | 2026-11-16 |
| Official SSE example from docs: `claude mcp add --transport sse asana https://mcp.asana.com/sse` | https://code.claude.com/docs/en/mcp | 2026-11-16 |
| stdio servers use `--` to separate Claude flags from launch command: `claude mcp add <name> -- <cmd> <args>` | https://code.claude.com/docs/en/mcp | 2026-11-16 |
| Scope flag `-s user\|project\|local` — default is `local` (project-only); `project` writes to `.mcp.json` at repo root; `user` writes to global `~/.claude.json`; `local` writes to the per-project section of `~/.claude.json` | https://mcp.so/blog/claude-code-mcp | 2026-11-16 |
| stdio transport for locally-spawned scripts = JSON-RPC over child-process stdin/stdout pipes; not a network choice, the only option for spawned servers | https://code.claude.com/docs/en/mcp | 2026-11-16 |
| Harness `server.py` uses streamable-HTTP (not SSE) for hop 2 to Burp — env var `BURP_MCP_HTTP=http://127.0.0.1:9876/mcp` confirmed in local `D:\Work\burp-mcp\.mcp.json` | — (local repo file) | 2026-11-16 |
| Per-call overhead of stdio harness over direct-SSE: ~1–5 ms Python wrapping — INFERENCE, not benchmarked. Dominated by Burp's own per-request work (hundreds of ms to seconds) | — | 2026-11-16 |
| Hand-edited `.mcp.json` with `url` but no `type` is silently skipped; Claude Code prints `MCP server "<name>" has a "url" but no "type"` | https://institute.sfeir.com/en/claude-code/claude-code-mcp-model-context-protocol/faq/ | 2026-11-16 |
| SSE is legacy; HTTP is preferred; Claude Code tries HTTP first and auto-falls back to SSE | https://code.claude.com/docs/en/mcp | 2026-11-16 |
| Management: `claude mcp list`, `claude mcp get <name>`, `claude mcp remove <name>` | https://code.claude.com/docs/en/mcp | 2026-11-16 |

## Burp MCP server extension — upstream tool surface (authoritative)

**Correction 2026-11-18:** Prior "12 tools" (Snyk, partial) and "27 tools" (2026-11-16 count) are both superseded. Re-verified against `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` on `PortSwigger/mcp-server@main`: **26 tools** registered via `mcpTool` / `mcpUnitTool` / `mcpPaginatedTool`. See the dated entry at the bottom of this file for the full re-verification. Collaborator tools exist (Pro only).

| Group | Tool name (as registered) | URL | Date verified |
|---|---|---|---|
| HTTP send | `SendHttp1Request`, `SendHttp2Request` | https://raw.githubusercontent.com/PortSwigger/mcp-server/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt | 2026-11-16 |
| Repeater | `CreateRepeaterTab`, `CreateRepeaterTabHttp2` | " | 2026-11-16 |
| Intruder | `SendToIntruder` | " | 2026-11-16 |
| Scanner (Pro) | `GetScannerIssues` — READ ONLY, no trigger tool | " | 2026-11-16 |
| Collaborator (Pro) | `GenerateCollaboratorPayload`, `GetCollaboratorInteractions` | " | 2026-11-16 |
| Proxy history | `GetProxyHttpHistory`, `GetProxyHttpHistoryRegex`, `GetProxyWebsocketHistory`, `GetProxyWebsocketHistoryRegex` | " | 2026-11-16 |
| Organizer | `GetOrganizerItems`, `GetOrganizerItemsRegex` | " | 2026-11-16 |
| Config | `output_project_options`, `output_user_options`, `SetProjectOptions`, `SetUserOptions` | " | 2026-11-16 |
| Encoders | `UrlEncode`, `UrlDecode`, `Base64Encode`, `Base64Decode`, `GenerateRandomString` | " | 2026-11-16 |
| Engine control | `SetTaskExecutionEngineState`, `SetProxyInterceptState` | " | 2026-11-16 |
| Editor | `get_active_editor_contents`, `SetActiveEditorContents` | " | 2026-11-16 |

**Consequences for our harness:**
- No scanner-trigger tool exists. `HITL_PER_PHASE` slot for `scanner_scan` is dead; remove. Active scan must be driven in GUI or via `SendToIntruder`.
- Collaborator IS available (Pro); `/pentest-inject` SSRF check can use `GenerateCollaboratorPayload` + `GetCollaboratorInteractions` as the external canary.
- No BApp-extension bridge. **Autorize, Hackvertor, JWT Editor, and every other BApp are unreachable from MCP.** Autorize workaround = run it in the Burp GUI side-by-side with the MCP session.
- Sequencer and `get_site_map` remain absent — correctly flagged as invented in prior entry.
- Live cross-check: `mcp__burp-stdio__list_upstream_tools` once SSE is up.

**Third-party forks (do not confuse):** `BurpMCP-Ultra` (149 tools), `Burp-MCP-Unrestricted` (HITL stripped). URLs: https://github.com/Cy-S3c/BurpMCP-Ultra ; https://github.com/RamanMG/Burp-MCP-Unrestricted — 2026-11-15.

## Phase progress tracker — format convention

Decided 2026-11-16 (Lee). Standardized across all `/pentest-*` command files.

| Fact | Where | Date |
|------|-------|------|
| Six phases, slash-command names: `recon`, `auth`, `access`, `inject`, `roundout`, `report` | `.claude/commands/pentest-*.md` | 2026-11-16 |
| Three tick states: `[x]` done · `[>]` in_progress (you-are-here) · `[ ]` pending | `.claude/commands/pentest-*.md` | 2026-11-16 |
| Phase-name mapping to `engagement.yaml` keys: `recon→recon`, `auth→auth`, `access→crawl`, `inject→baseline_scan`, `roundout→verify`, `report→report` | `.claude/commands/pentest-start.md` + `pentest-resume.md` | 2026-11-16 |
| Box printed on every output inside a phase: announce, after each tool call, at each HITL prompt, at phase close. Per Lee: "the few additional lines aren't a downside" | `.claude/commands/pentest-*.md` | 2026-11-16 |
| Tick state sourced from `read_engagement` / `engagement.yaml`, never from model memory | `.claude/commands/pentest-*.md` | 2026-11-16 |
| `pentest-report.md` NOT updated — file is corrupted (binary NUL bytes), needs full rewrite separately | — | 2026-11-16 |

## Phase check-level structure + decision-menu format

Decided 2026-11-16 (Lee). Each phase's checks are enumerated in the skill file; each check uses a decision-menu so tool choice is reasoned, not reflex.

| Fact | Where | Date |
|------|-------|------|
| Sub-sections per phase (fixed, not model-invented): recon → surface_map, auth_boundary, threat_model · auth → rate_limit, user_enum, session, jwt, reset_mfa · access → object_level, function_level, business_logic · inject → sqli, xss, ssrf, method_tamper · roundout → platform, client_side, logging, exception · report → draft_en, otoi_handoff, debrief | `.claude/commands/pentest-*.md` | 2026-11-16 |
| Decision-menu format per check: `goal / signals / tools A-C / default / escalate when / abort when`. Skill must state tool pick + one-line reasoning BEFORE firing; escalation past default requires per-call HITL naming the three conditions | `.claude/commands/pentest-auth.md` (reference impl) | 2026-11-16 |
| Four tick states for checks: `[x]` done · `[>]` in_progress · `[ ]` pending · `[-]` n/a (reason recorded in `aborted_reason` / `evidence`) | `.claude/commands/pentest-auth.md` | 2026-11-16 |
| Two-box output: top = phase-checks (zoomed in, current-phase sub-sections) · bottom = roadmap (zoomed out, 6 phases). Both printed on every output inside a phase | `.claude/commands/pentest-auth.md` | 2026-11-16 |
| Reminder block appended after both boxes: lists all six phases' sub-sections so the operator does not memorize them. `← you are here` marker on the current phase line | `.claude/commands/pentest-auth.md` | 2026-11-16 |
| engagement.yaml schema extension: `phases.<name>.checks[]` with `id / status / tool / reasoning / signal / evidence / aborted_reason`. Reference schema in pentest-auth.md | `.claude/commands/pentest-auth.md` | 2026-11-16 |
| Pattern-first rollout: `/pentest-auth` is the reference. Other 5 phase files inherit the same shape once this one is validated. `/pentest-report` still corrupted; rewrite separately | — | 2026-11-16 |
| Rationale for NOT expanding beyond 6 phases: phases = engagement state machine (scope/advance/resume); checks = WSTG depth. Keeps `engagement.yaml` keys stable; resume stays legible | — | 2026-11-16 |
| Threat modeling / business logic / client-side (silently folded in prior version) now explicit sub-sections: threat_model under recon, business_logic under access, client_side under roundout | `.claude/commands/pentest-*.md` | 2026-11-16 |

## Burp extensions — role in burp-mcp engagements

Decided 2026-11-16 (Lee). Added to project CLAUDE.md "Burp extensions" section.

| Fact | URL | Date | Label |
|------|-----|------|-------|
| Turbo Intruder exists as a PortSwigger-authored BApp (extension existence) | https://github.com/PortSwigger/turbo-intruder (repo verified earlier) | 2026-11-16 | verified on repo; BApp Store hash slug NOT re-fetched this session |
| Turbo Intruder repo and example scripts live at github.com/PortSwigger/turbo-intruder, `resources/examples/race-single-packet-attack.py` | https://github.com/PortSwigger/turbo-intruder | 2026-11-16 | verified (earlier entry) |
| Single-packet attack class documented by Kettle — defeats check-then-act race windows | https://portswigger.net/research/smashing-the-state-machine (URL pattern inferred, not fetched this session) | 2026-11-16 | inference on URL; CLASS verified across community sources earlier |
| Param Miner is a PortSwigger-authored BApp for hidden header + parameter discovery (cache-key injection, host-header, backend smuggling) | — | 2026-11-16 | inference (well-known BApp; URL not fetched this session) |
| Autorize is a BApp by Barak Tawily for passive horizontal-authorization diff testing | — | 2026-11-16 | inference on authorship; existence verified in community sources |
| Retire.js BApp wraps the Retire.js JS-library scanner into Burp passively | — | 2026-11-16 | inference (well-known BApp; URL not fetched this session) |
| Software Vulnerability Scanner BApp by vulners.com maps service/software banners to Vulners DB CVEs passively | — | 2026-11-16 | inference (well-known BApp; URL not fetched this session) |
| Backslash Powered Scanner is a Kettle BApp that extends Burp's active scanner with novel injection heuristics (Pro only) | — | 2026-11-16 | inference (well-known BApp; URL not fetched this session) |
| **Pending verification:** BApp Store URL hashes for Turbo Intruder, Param Miner, Autorize, Retire.js, SVS, Backslash Powered Scanner. Pattern is `https://portswigger.net/bappstore/<32-hex>`. Fetch before citing in deliverables | https://portswigger.net/bappstore | 2026-11-16 | verified on BApp Store pattern only |
| JWT Editor, Hackvertor, Logger++ marked as skippable because MCP primitives (`Base64Encode`, `UrlEncode`, `SendHttp1Request`, `log_request`) cover their core use cases | — | 2026-11-16 | inference |
| No BApp can be invoked through Burp MCP — official server exposes only Burp core primitives; extensions run in GUI only | https://raw.githubusercontent.com/PortSwigger/mcp-server/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt | 2026-11-16 | verified |

## Free alternatives to Burp Pro features (ProjectDiscovery stack)

Decided (prior conversation, reconfirmed 2026-11-16 by Lee). Added to project CLAUDE.md "Free alternatives" section.

| Fact | URL | Date | Label |
|------|-----|------|-------|
| Katana (headless crawler) replaces Burp Pro Crawl | https://github.com/projectdiscovery/katana | 2026-11-16 | inference on replacement choice; tool existence verified via well-known PD repo, not re-fetched this session |
| Katana JS-crawl flag `-jc`, depth `-d`, output `-o` | https://github.com/projectdiscovery/katana | 2026-11-16 | inference — flags recalled from prior use, not re-fetched; VERIFY before quoting exact flags to client |
| Nuclei (template scanner) replaces Burp Pro Active Scanner | https://github.com/projectdiscovery/nuclei | 2026-11-16 | inference on replacement choice; tool existence verified via well-known PD repo |
| Nuclei severity filter `-severity`, JSONL output `-o <file>.jsonl` | https://github.com/projectdiscovery/nuclei | 2026-11-16 | inference — flags recalled from prior use, not re-fetched; VERIFY before quoting |
| Nuclei template update: `nuclei -update-templates` | https://github.com/projectdiscovery/nuclei | 2026-11-16 | inference |
| interactsh-client (OOB server client) replaces Burp Collaborator | https://github.com/projectdiscovery/interactsh | 2026-11-16 | inference on replacement choice; tool existence verified |
| Public interactsh server at `interact.sh`; self-hostable | https://github.com/projectdiscovery/interactsh | 2026-11-16 | inference — public server name recalled, not re-fetched |
| Install via `go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest`; binaries land in `%USERPROFILE%\go\bin\` | https://go.dev/ref/mod#go-install | 2026-11-16 | verified on go install mechanism; PD-specific paths inference |
| **Pending verification:** exact CLI flag names for Katana/Nuclei/interactsh-client. Fetch each tool's README before citing flags in a client deliverable or in a `/pentest-*` skill file | — | 2026-11-16 | — |
| Coverage gap without Burp Pro: Sequencer (token randomness analysis) — no ProjectDiscovery equivalent. Use `ent` or `dieharder` on captured tokens, or re-implement in skill | https://www.fourmilab.ch/random/ (ent) ; https://webhome.phy.duke.edu/~rgb/General/dieharder.php (dieharder) | 2026-11-16 | inference on tool names and URLs; not re-fetched this session |

## Turbo Intruder example filenames

| Fact | URL | Date verified |
|------|-----|---------------|
| `resources/examples/default.py` exists in official repo | https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/default.py | 2026-11-08 |
| `resources/examples/race-single-packet-attack.py` exists (NOT `race-single-packet.py`) | https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py | 2026-11-08 |

## Burp Sequencer edition (verified 2026-11-16)

| Fact | URL | Date verified |
|------|-----|---------------|
| Burp Sequencer ships in Burp Community Edition (no `ent`/`dieharder` fallback needed) | https://portswigger.net/burp/communitydownload | 2026-11-16 |
| Burp Community: Scanner, Crawler, Collaborator are Pro-only; Intruder on Community is demo/throttled | https://portswigger.net/burp/communitydownload | 2026-11-16 |

## Similar open-source MCP-pentest projects — landscape framing

Labeled as inference (not freshly surveyed), 2026-11-16. Walkthrough's
"Similar projects" section lists PortSwigger/mcp-server (dependency),
fr0gger/MCP_Security and other pentest-mcp wrappers (tool plumbing),
PentestGPT/HackerGPT (prompt-only agents), CAI by Alias Robotics
(autonomous no-HITL framework). Framed as pattern examples, not
exhaustive catalog. If anyone needs a verified competitor audit, run a
fresh GitHub search and log results here before citing as verified.

---

## 2026-11-17 — Free-stack depth parity with Burp Pro Scanner (CLAUDE.md update)

**Fact (verified):** Nuclei headless templates require explicit `-headless` flag;
headless templates are skipped otherwise.
URL: https://docs.projectdiscovery.io/tools/nuclei/running
Date: 2026-11-17

**Fact (verified):** Katana supports `-headless`, `-system-chrome` (`-sc`),
`-automatic-form-fill` (`-aff`), `-headless-options` (`-ho`), `-no-sandbox` (`-nos`),
`-show-browser` (`-sb`). Official usage docs example:
`katana -u https://tesla.com -headless -system-chrome -headless-options --disable-gpu,proxy-server=http://127.0.0.1:8080`
URL: https://docs.projectdiscovery.io/opensource/katana/usage
URL: https://docs.projectdiscovery.io/opensource/katana/running.md
Date: 2026-11-17

**Fact (verified):** Nuclei v3.2 added authenticated-scanning via `-secret-file` / `-sf`
option, accepting .yaml/.yml/.json (plain or encrypted). Compatible with all
existing templates; login flow uses a login template paired with secrets file.
Nuclei auto-handles cookies between requests inside one template.
URL: https://docs.projectdiscovery.io/tools/nuclei/authenticated-scans
URL: https://projectdiscovery.io/blog/scanning-login-protected-targets-with-nuclei
Date: 2026-11-17

**Fact (inference, pending runtime check):** `-system-chrome` (`-sc`) exists in Nuclei
as well as Katana. Appears in multiple third-party README mirrors of Nuclei but
official docs page snippet didn't include flag details. Confirm with `nuclei -h`
on install; drop `-system-chrome` from invocations if the flag is absent (Nuclei
will fetch its own chromium on first run, slower but functional).
URL: https://docs.projectdiscovery.io/templates/protocols/headless
Date: 2026-11-17

**Correction logged:** Prior assumption that Nuclei `-sf` meant "session flow file"
was wrong. `-sf` = `-secret-file`. CLAUDE.md "Free alternatives" table corrected
same day.

## Burp MCP tool surface — re-verified 2026-11-18

**Fact (verified):** The official PortSwigger Burp MCP server registers
**26 tools** in `Tools.kt` (not 27, not 12 — prior figures were wrong).
Surface includes `send_http1_request`, `send_http2_request`,
`create_repeater_tab`, `send_to_intruder`, `get_scanner_issues`,
`get_proxy_http_history_regex`, `generate_collaborator_payload`,
encoders, Organizer, Proxy intercept toggle, task-engine read, config.
No standalone scanner-trigger tool on the official server (Scanner is
Pro-only and MCP exposes read-only Scanner access).
URL: https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt
Date: 2026-11-18

**Fact (verified):** Proxy-history retrieval returns full raw request and
response bytes via `HttpRequestResponse { request, response, notes }` —
not just metadata. Serialization is in `serialization.kt`.
URL: https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/serialization.kt
Date: 2026-11-18

**Fact (verified):** Each proxy-history item is truncated at 5000 chars by
`MAX_HISTORY_ITEM_LENGTH` in `HistoryItemJson.kt`, with a literal
`... (truncated)` marker appended. No flag exists to raise the cap.
Implication for `replay_history`: items hitting the cap must be flagged
and skipped (incomplete raw bytes produce broken replays).
URL: https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/HistoryItemJson.kt
Date: 2026-11-18

**Fact (verified):** No get-single-history-item-by-ID tool on the official
surface. Only regex pagination over the full history is supported.
Date: 2026-11-18

**Correction logged:** Prior "27 core tools" (2026-11-15/16 entries in
raw-vs-harness-walkthrough.html) and "12-tool surface" (Snyk/HackTricks
partial listing) are both superseded. Settle at **26** everywhere.

---

| Fact | Source | Date |
|---|---|---|
| Burp Pro ships **Session Handling Rules** (automatic re-login macros that fire on session-expired detection) and **Macros** (recorded request sequences replayed as login). Both Pro-only; absent from Community. Harness equivalent: `SendHttp1Request` login call + `replay_history` rewriting `Authorization`/`Cookie` headers with the fresh token on resume. | portswigger.net/burp/documentation — Sessions > Session Handling Rules; Macros (long-standing feature, decade+). Not re-fetched 2026-11-18, labeled **inference from prior reading** | 2026-11-18 |
| Universal HTTP-proxy resume ceiling — three states neither Community+harness nor Pro restore: (1) server-side DB / app state across target restart, (2) Chrome SPA state / `localStorage` / `sessionStorage`, (3) auth-token server-side survival (always re-login). Added to raw-vs-harness-walkthrough.html as "Resume-workflow parity" subsection. | Analytical — derived from Pro project-file scope (history + scanner issues + Repeater/Intruder tabs; no target DB, no embedded-Chromium profile) | 2026-11-18 |

- interactsh-client v1.4.1 — verified from binary self-report during juice-shop SSRF OOB proof (2026-11-19). Source: `interactsh-client` stdout line `[INF] Current interactsh version 1.4.1 (latest)` (bg task b4hii75ed output, 2026-11-19).

## 2026-11-21 — diff_fuzz tool (Backslash-Powered-Scanner stand-in)
- Fact: Burp extension "Backslash-Powered Scanner" by James Kettle is Apache-2.0 licensed and hooks `IScannerCheck` (Pro-gated API), so it cannot run inside Burp Community.
  - Source: https://github.com/PortSwigger/backslash-powered-scanner (verified 2026-11-21)
  - Label: verified
- Fact: Our `tools/diff_fuzz.py` reimplements BPS's core idea (baseline → probe → signature-diff → escape-partner confirm) without the `IScannerCheck` surface so it runs standalone under Community.
  - Label: in-repo implementation, see `tools/diff_fuzz.py` header

## 2026-11-21 — Pentest phase models
- Fact: PTES (Penetration Testing Execution Standard) defines 7 phases: Pre-engagement, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting.
  - Source: http://www.pentest-standard.org/index.php/Main_Page
  - Label: verified (public standard)
- Fact: OWASP WSTG (Web Security Testing Guide) organizes testing into 11 categories (Info Gathering, Config/Deploy Mgmt, Identity Mgmt, Authentication, Authorization, Session Mgmt, Input Validation, Error Handling, Cryptography, Business Logic, Client Side).
  - Source: https://owasp.org/www-project-web-security-testing-guide/
  - Label: verified (public standard)
