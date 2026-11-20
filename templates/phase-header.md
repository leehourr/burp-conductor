# Phase header template

Each `/pentest-<phase>` skill prints its header block before step 0 so Claude
re-anchors on role, forbidden tools, goal, rule, and exit condition without
re-reading CLAUDE.md. Five lines, fixed shape:

```
[<phase>] <one-line role>
          Forbidden: <tools or actions>
          Goal:      <what this phase produces — list of check ids>
          Rule:      each check is a decision menu — state tool pick
                     + one-line reasoning BEFORE firing. Escalate
                     only via explicit per-call HITL naming the
                     three escalation conditions.
          Exit:      <what makes this phase done>
```

Canonical headers (verified tool names per CLAUDE.md 2026-11-15):

```
[recon]   passive map only.
          Forbidden: send_http1_request, send_http2_request,
                     create_repeater_tab, send_to_intruder,
                     scanner trigger.
          Goal:      surface_map, auth_boundary, threat_model
                     → verify_queue.
          Exit:      queue has candidates, user says next.

[auth]    probe login / register / forgot-password / token / MFA.
          Forbidden: credential brute, lockout triggers.
          Goal:      rate_limit, user_enum, session, jwt, reset_mfa.
          Exit:      all five checks closed, user says next.

[access]  verify object-level + function-level + business logic,
          one object at a time.
          Forbidden: mass IDOR sweeps, blind ID enumeration on
                     state-changing endpoints.
          Goal:      object_level, function_level, business_logic.
          Exit:      all three checks closed, user says next.

[inject]  verify injection candidates + run active scan on queued URLs.
          Forbidden: live internal SSRF without explicit go,
                     stored-XSS payload that reaches real users,
                     SQLi payload that mutates state.
          Goal:      sqli, xss, ssrf, method_tamper.
          Exit:      all four checks closed, verify_queue drained,
                     user says next.

[roundout] OWASP Top 10 coverage sweep.
          Forbidden: nothing new; passive reads free, active probes
                     per-call gated.
          Goal:      platform, client_side, logging, exception.
          Exit:      all four checks closed, user says next.

[report]  assemble EN draft, Otoi-san handoff, debrief prep.
          Forbidden: upstream Burp tool fires. Any new evidence
                     needed → back to the appropriate phase.
          Goal:      draft_en, otoi_handoff, debrief.
          Exit:      draft ready, handoff note ready, debrief outlined.
```

Per-call HITL applies to `send_http1_request`, `send_http2_request`,
`create_repeater_tab`, `send_to_intruder` regardless of phase.
Per-phase HITL applies to the scanner trigger (name unverified —
confirm via `list_upstream_tools`) and to any free-stack Bash
invocation (Katana, Nuclei fast/headless/authenticated, interactsh).

---

# Two-box output contract (every phase)

Every phase skill prints two boxes at **anchor moments**, not after every
line of output. Anchor moments:

1. Phase announce (first output of the skill).
2. Each HITL gate — before the user is asked to approve a counted-tool fire.
3. Check transition — when `current check` changes (one check closes,
   next opens).
4. After a counted-tool fire returns (the fire that just moved the
   tools-used counter).
5. Phase close.

**Not** after every passive `http_get` / `get_proxy_history` call — those
get a one-line status update ("passive read: /api/users returned 200,
no new surface") and the boxes stay quiet. The decision-menu tool-pick
+ reasoning statement already carries the "which tool are we firing"
signal for passive calls; the boxes are for stateful anchor points.

**Phase-checks box (top, zoomed-in):** the current phase's check list, the
current check id, which tool pick (A / B / C) is in use, the one-line
signal, and the per-phase tools-used counter.

```
┌─ <phase> checks ───────────────────────────────────────┐
│  [tick] id   [tick] id   [tick] id   ...               │
│  current check: <id> · tool in use: <A|B|C> · signal:  │
│  <short observation or "none yet">                     │
│  tools used: <n>/<n total this phase>                  │
└────────────────────────────────────────────────────────┘
```

**Roadmap box (bottom, zoomed-out):** all six phases with tick, current
phase, findings count, next slash command, engagement-total tools-used.

```
┌─ engagement: <slug> ───────────────────────────────────┐
│  [tick] recon    [tick] auth     [tick] access         │
│  [tick] inject   [tick] roundout [tick] report         │
│  current: <phase> · findings: <N> · next: /pentest-<p> │
│  tools used: <n>/<n total engagement>                  │
└────────────────────────────────────────────────────────┘
```

**Sub-sections reminder (print below the boxes so the model doesn't have
to memorize which check-ids belong where):**

```
recon    → surface_map, auth_boundary, threat_model
auth     → rate_limit, user_enum, session, jwt, reset_mfa
access   → object_level, function_level, business_logic
inject   → sqli, xss, ssrf, method_tamper
roundout → platform, client_side, logging, exception
report   → draft_en, otoi_handoff, debrief
```

**Tick states:** `[x]` done · `[>]` in_progress · `[ ]` pending · `[-]`
n/a (reason recorded in the check's `aborted_reason` field).

**Tools-used counter:** increments on every upstream tool fire that
counts as HITL (`send_http1_request`, `send_http2_request`,
`create_repeater_tab`, `send_to_intruder`, scanner trigger). Passive
tools (`http_get`, `get_proxy_history`) do not count. Format:
`tools used: N / M` where N is phase-local in the top box, engagement-
total in the bottom box.

**State sources:** phase-level status from `read_engagement` →
`phases.<name>.status`. Check-level status from `phases.<name>.checks[]`.
Findings count from counting `.md` files matching
`YYYY-MM-DD-<sev>-<slug>.md` under `reports/<slug>/`. Never drift from
file state — re-read before printing.
