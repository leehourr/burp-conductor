"""Burp MCP harness — stdio MCP server that interposes on PortSwigger's
official Burp MCP extension (SSE at 127.0.0.1:9876) and applies the lean-v3
safety spine from safety.py.

Claude Code / Codex connects to THIS server over stdio. This server forwards
tool calls to the upstream SSE server after safety checks, and wraps responses
on the way back.

Run:  python D:\\Work\\burp-mcp\\server.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer

import persist
import safety

UPSTREAM_MCP = os.environ.get("BURP_MCP_HTTP", "http://127.0.0.1:9876/mcp")

mcp = MCPServer("burp-safety-proxy")

# ----- Upstream client -------------------------------------------------------
# PortSwigger's extension uses Streamable HTTP MCP transport (MCP 2025-03).


async def upstream_tools_list() -> list[dict[str, Any]]:
    async with streamable_http_client(UPSTREAM_MCP) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [{"name": t.name, "description": t.description} for t in result.tools]


async def upstream_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    async with streamable_http_client(UPSTREAM_MCP) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(name, arguments)
            return {"content": [c.model_dump() for c in result.content]}


# ----- Tools (stub wrappers) -------------------------------------------------
# For the smoke test we expose three illustrative wrappers. A fuller build
# enumerates upstream tools and generates a safe wrapper per tool.


@mcp.tool()
async def list_upstream_tools() -> str:
    """List tools advertised by the upstream PortSwigger Burp MCP server.

    Also runs a drift check: any tool name in safety.HITL_PER_CALL /
    HITL_PER_PHASE that is missing from the live surface is a silent-gate risk
    (the gate would stop firing without failing loud). Reported inline.
    """
    try:
        tools = await upstream_tools_list()
    except Exception as e:
        return f"ERROR contacting upstream {UPSTREAM_MCP}: {e}"

    live = {t.get("name") for t in tools}
    gated = safety.HITL_PER_CALL | safety.HITL_PER_PHASE
    # replay_history is our own tool, not upstream — exclude from drift check.
    gated_upstream = {n for n in gated if n != "replay_history"}
    missing = sorted(gated_upstream - live)
    extra_mutating = sorted(
        n for n in live
        if any(k in n for k in ("send_http", "repeater", "intruder", "scan"))
        and n not in gated_upstream
    )

    report: dict[str, Any] = {
        "upstream_tools": sorted(live),
        "count": len(live),
    }
    if missing:
        report["WARN_gated_names_missing_from_upstream"] = missing
    if extra_mutating:
        report["WARN_mutating_shaped_names_not_gated"] = extra_mutating
    return json.dumps(report, indent=2)


@mcp.tool()
async def http_get(url: str) -> str:
    """Issue a GET via Burp's proxy. In-scope only. Response is capped and spotlighted.

    (1) Scope check  (2) Upstream call  (3) Spotlight wrap
    """
    from urllib.parse import urlparse

    try:
        safety.check_in_scope(url)
    except safety.SafetyBlock as e:
        return f"BLOCKED: {e}"

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    use_https = parsed.scheme == "https"
    raw_request = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    raw_request = safety.inject_identity_into_raw(raw_request)

    try:
        result = await upstream_call(
            "send_http1_request",
            {
                "content": raw_request,
                "targetHostname": host,
                "targetPort": port,
                "usesHttps": use_https,
            },
        )
    except Exception as e:
        return f"UPSTREAM ERROR: {e}"

    body = json.dumps(result.get("content", result)).encode("utf-8", errors="replace")
    wrapped, quarantined = safety.spotlight_wrap(body)
    tag = "QUARANTINED" if quarantined else "OK"
    return f"[{tag}] " + wrapped.decode("utf-8", errors="replace")


@mcp.tool()
async def get_proxy_history(limit: int = 50, pattern: str = "") -> str:
    """Pull Burp proxy HTTP history. Optionally filter by URL pattern (regex).
    Use after passive browsing in Burp's embedded browser to inspect captured traffic.
    Response is capped and spotlighted.
    """
    tool_name = "get_proxy_http_history_regex" if pattern else "get_proxy_http_history"
    args: dict[str, Any] = {"offset": 0, "count": limit}
    if pattern:
        args["regex"] = pattern

    try:
        result = await upstream_call(tool_name, args)
    except Exception as e:
        return f"UPSTREAM ERROR: {e}"

    body = json.dumps(result.get("content", result)).encode("utf-8", errors="replace")
    wrapped, quarantined = safety.spotlight_wrap(body)
    tag = "QUARANTINED" if quarantined else "OK"
    return f"[{tag}] " + wrapped.decode("utf-8", errors="replace")


def _extract_history_items(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize upstream get_proxy_http_history* response into a list of dicts
    with request/response/notes fields. Defensive: handles the three shapes we
    could plausibly see (single text block containing a JSON array; one text
    block per item; or a JSON object wrapping a list).
    """
    blocks = result.get("content") or []
    items: list[dict[str, Any]] = []
    for b in blocks:
        text = b.get("text") if isinstance(b, dict) else None
        if not isinstance(text, str):
            continue
        chunks: list[str] = []
        try:
            json.loads(text)
            chunks = [text]
        except json.JSONDecodeError:
            # Upstream shape: concatenated JSON objects separated by blank lines
            # inside one text block. Split and parse individually.
            chunks = [c.strip() for c in text.split("\n\n") if c.strip()]
        for chunk in chunks:
            try:
                parsed = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, list):
                items.extend(x for x in parsed if isinstance(x, dict))
            elif isinstance(parsed, dict):
                if "request" in parsed or "response" in parsed:
                    items.append(parsed)
                else:
                    for v in parsed.values():
                        if isinstance(v, list):
                            items.extend(x for x in v if isinstance(x, dict))
    return items


@mcp.tool()
async def checkpoint_history(
    slug: str,
    regex: str = ".*",
    page_size: int = 100,
    max_pages: int = 100,
) -> str:
    """Snapshot Burp proxy history to reports/<slug>/replay-<date>.jsonl.

    Paginates get_proxy_http_history_regex, scope-filters each item, scrubs
    auth headers, and persists full raw bytes (up to Burp MCP's 5000-char
    per-item cap — items that hit the cap are flagged `upstream_truncated`).

    Use before Burp exits. Pair with replay_history on the new session.
    """
    total = 0
    written = 0
    oos = 0
    truncated = 0
    offset = 0

    for _ in range(max_pages):
        try:
            result = await upstream_call(
                "get_proxy_http_history_regex",
                {"regex": regex, "offset": offset, "count": page_size},
            )
        except Exception as e:
            return f"UPSTREAM ERROR at offset={offset}: {e}"

        items = _extract_history_items(result)
        if not items:
            break

        for it in items:
            total += 1
            res = persist.write_replay_entry(
                slug,
                it.get("request") or "",
                it.get("response") or "",
                it.get("notes"),
            )
            if res["status"] == "ok":
                written += 1
                if res.get("truncated_req") or res.get("truncated_resp"):
                    truncated += 1
            elif res["status"] == "out_of_scope":
                oos += 1

        if len(items) < page_size:
            break
        offset += page_size

    path = persist.replay_log_path(slug)
    return json.dumps(
        {
            "file": str(path),
            "items_seen": total,
            "written": written,
            "out_of_scope_skipped": oos,
            "upstream_truncated_flagged": truncated,
        },
        indent=2,
    )


@mcp.tool()
async def replay_history(
    slug: str,
    file: str = "",
    auth_headers_json: str = "",
    limit: int = 0,
) -> str:
    """Re-fire checkpointed history through send_http1_request to repopulate
    Burp's proxy history on a fresh session.

    Batch HITL: announce intent + target count + hosts + file *once* before
    firing; do not call this tool without that approval. Internally it bypasses
    per-call HITL theater because the batch was approved.

    `auth_headers_json`: JSON object like {"Authorization": "Bearer ..."}; each
    entry replaces (or appends) that header in every request, letting a fresh
    login splice into checkpointed requests whose auth was scrubbed.

    `limit`: 0 = all. Items marked `upstream_truncated` are SKIPPED — their
    bytes are incomplete and replaying them would produce a broken request.
    """
    path = persist.replay_log_path(slug) if not file else safety.confine_report_path(file)
    entries = persist.read_replay_entries(path)
    if not entries:
        return f"BLOCKED: no entries at {path}"

    try:
        auth_headers = json.loads(auth_headers_json) if auth_headers_json else {}
    except json.JSONDecodeError as e:
        return f"BLOCKED: bad auth_headers_json: {e}"
    if not isinstance(auth_headers, dict):
        return "BLOCKED: auth_headers_json must be a JSON object"

    fired = 0
    skipped_trunc = 0
    skipped_oos = 0
    errors = 0

    for entry in entries:
        if limit and fired >= limit:
            break
        if entry.get("upstream_truncated"):
            skipped_trunc += 1
            continue
        host = entry.get("host") or ""
        if host not in safety.SCOPE_HOSTS:
            skipped_oos += 1
            continue

        raw = persist.inject_auth(entry.get("request") or "", auth_headers)
        try:
            await upstream_call(
                "send_http1_request",
                {
                    "content": raw,
                    "targetHostname": host,
                    "targetPort": int(entry.get("port") or 443),
                    "usesHttps": bool(entry.get("https", True)),
                },
            )
            fired += 1
        except Exception:
            errors += 1

    return json.dumps(
        {
            "source": str(path),
            "fired": fired,
            "skipped_truncated": skipped_trunc,
            "skipped_out_of_scope": skipped_oos,
            "errors": errors,
            "total_in_file": len(entries),
        },
        indent=2,
    )


@mcp.tool()
async def write_report(filename: str, content: str) -> str:
    """Write a report file. Confined under REPORTS_ROOT."""
    try:
        path = safety.confine_report_path(
            str(safety.REPORTS_ROOT / filename)
        )
    except safety.SafetyBlock as e:
        return f"BLOCKED: {e}"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {path}"


@mcp.tool()
async def log_request(
    method: str,
    url: str,
    status: int,
    request_bytes: str = "",
    response_bytes: str = "",
) -> str:
    """Append one request/response pair to today's JSONL log. In-scope only."""
    return persist.log_request(method, url, status, request_bytes, response_bytes)


@mcp.tool()
async def save_finding(slug: str, severity: str, title: str, body: str) -> str:
    """Write a markdown finding under REPORTS_ROOT. Severity: info|low|medium|high|critical."""
    return persist.save_finding(slug, severity, title, body)


# ----- Engagement state ------------------------------------------------------


@mcp.tool()
async def start_engagement(
    slug: str,
    client: str,
    hosts: list[str],
    window_start: str = "",
    window_end: str = "",
) -> str:
    """Create a new engagement: reports/<slug>/engagement.yaml from template.
    Also loads `hosts` into safety.SCOPE_HOSTS for this session.
    """
    result = persist.start_engagement(
        slug,
        client,
        hosts,
        window_start or None,
        window_end or None,
    )
    if not result.startswith("BLOCKED"):
        safety.load_scope(hosts)
        # Identity header is NOT auto-set — it must be filled in
        # engagement.yaml and confirmed with the client before load.
        # read_engagement / /pentest-resume will pick it up.
    return result


@mcp.tool()
async def read_engagement(engagement: str) -> str:
    """Return the engagement.yaml for <engagement> as JSON."""
    try:
        data = persist.read_state(engagement)
    except FileNotFoundError as e:
        return f"BLOCKED: {e}"
    # Side-effect: rehydrate scope + identity from state so a fresh session
    # that opens an engagement is immediately ready to fire.
    hosts = (data.get("scope") or {}).get("hosts") or []
    if hosts:
        safety.load_scope(hosts)
    ident = data.get("identity") or {}
    try:
        safety.load_identity(ident.get("header_name"), ident.get("header_value"))
    except safety.SafetyBlock as e:
        return f"BLOCKED: {e}"
    return json.dumps(data, indent=2, default=str)


@mcp.tool()
async def list_engagements() -> str:
    """List every engagement under REPORTS_ROOT with a state file."""
    return json.dumps(persist.list_engagements(), indent=2, default=str)


@mcp.tool()
async def advance_phase(engagement: str, phase: str, patch_json: str) -> str:
    """Merge patch_json (JSON object) into state.phases[phase] and stamp checkpoint."""
    try:
        patch = json.loads(patch_json) if patch_json else {}
    except json.JSONDecodeError as e:
        return f"BLOCKED: bad patch_json: {e}"
    if not isinstance(patch, dict):
        return "BLOCKED: patch_json must be a JSON object"
    try:
        return persist.advance_phase(engagement, phase, patch)
    except FileNotFoundError as e:
        return f"BLOCKED: {e}"


@mcp.tool()
async def next_phase(engagement: str) -> str:
    """Return the next phase to run (pending/in_progress), or 'done' if all closed."""
    try:
        name = persist.next_phase(engagement)
    except FileNotFoundError as e:
        return f"BLOCKED: {e}"
    return name or "done"


@mcp.tool()
async def load_scope(engagement: str) -> str:
    """Load scope.hosts from an engagement.yaml into safety.SCOPE_HOSTS for this session."""
    try:
        data = persist.read_state(engagement)
    except FileNotFoundError as e:
        return f"BLOCKED: {e}"
    hosts = ((data.get("scope") or {}).get("hosts")) or []
    if not hosts:
        return "BLOCKED: no scope.hosts in engagement.yaml"
    safety.load_scope(hosts)
    return f"scope loaded: {sorted(safety.SCOPE_HOSTS)}"


def main() -> None:
    """Console-script entry point. Wired via pyproject [project.scripts]."""
    print(
        f"burp-safety-proxy starting — upstream={UPSTREAM_MCP}",
        file=sys.stderr,
    )
    mcp.run()


if __name__ == "__main__":
    main()
