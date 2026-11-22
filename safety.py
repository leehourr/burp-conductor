"""Safety wrapper for Burp MCP harness.

Lean v3 5-control spine:
  (1) Scope enforce IN  — reject tool call if target host not in SCOPE
  (2) Scope enforce OUT — reject response content referencing out-of-scope hosts
  (3) Response sanitize + cap ~8KB + spotlight/quarantine suspicious bodies
  (4) HITL tiers (handled in server.py; thresholds defined here)
  (5) Report-write prefix confinement (only paths under REPORTS_ROOT)
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

# ---- Configure per engagement ----------------------------------------------
SCOPE_HOSTS: set[str] = {
    "localhost",
    "127.0.0.1",
    # add client domains here, e.g. "example.com", "api.example.com"
}

# Identity header — unique, grep-able tag the client whitelists so their blue
# team can filter our traffic out of SIEM / WAF alerts. Agreed in writing
# before the engagement starts; recorded in engagement.yaml under `identity:`.
# Set via load_identity(); every outbound upstream call injects it.
IDENTITY_HEADER_NAME: str | None = None
IDENTITY_HEADER_VALUE: str | None = None

# Report root: env var wins (set per engagement or per machine), otherwise
# fall back to ./reports under the current working directory. Picking CWD
# means the harness runs from any engagement folder — clone-and-go, no
# machine-specific absolute paths.
REPORTS_ROOT = Path(
    os.environ.get("BURP_MCP_REPORTS_DIR") or (Path.cwd() / "reports")
).resolve()
RESPONSE_CAP_BYTES = 8 * 1024  # ~8 KB

# Tiered HITL — upstream tool names that require human approval before firing.
# Names re-verified 2026-11-18 against PortSwigger/mcp-server source
# (26-tool surface — Tools.kt). See research/sources.md.
#
# PER_CALL: targeted, mutating, or active traffic generators. Announce intent
# + target + payload shape and wait for explicit go on every single call.
HITL_PER_CALL: set[str] = {
    "send_http1_request",
    "send_http2_request",
    "create_repeater_tab",
    "send_to_intruder",
}

# PER_PHASE: bulk-ish operations where announcing every sub-request is theater.
# Announce once at phase start (scope, mode, rate) and wait for go; the phase
# then runs without re-prompting unless something unusual is observed.
#
# Scanner-trigger tool name on the official server is UNVERIFIED. Confirm via
# list_upstream_tools and update this set. Community forks observed:
# start_active_scan, start_passive_scan, scanner-start-audit.
HITL_PER_PHASE: set[str] = {
    # "<scanner_trigger_name>",  # fill in after list_upstream_tools
    "replay_history",  # local batch-replay tool (loops send_http1_request)
}

# Legacy alias — anything that needs *some* human gate before firing.
HITL_REQUIRED: set[str] = HITL_PER_CALL | HITL_PER_PHASE

# Patterns that trigger spotlight-quarantine on responses (prompt-injection
# markers in bodies that will be fed back into the LLM context).
SPOTLIGHT_PATTERNS = [
    re.compile(rb"ignore (all )?previous instructions", re.I),
    re.compile(rb"system prompt", re.I),
    re.compile(rb"</?(system|assistant|user)>", re.I),
    re.compile(rb"you are (now |an? )", re.I),
    re.compile(rb"disregard (your|the) (instructions|guardrails)", re.I),
]


class SafetyBlock(Exception):
    """Raised when a tool call or response fails a safety check."""


def load_scope(hosts: list[str]) -> None:
    """Replace SCOPE_HOSTS with the given list (plus loopback, always). Session-scoped."""
    global SCOPE_HOSTS
    SCOPE_HOSTS = {"localhost", "127.0.0.1", *(h.strip() for h in hosts if h.strip())}


def load_identity(name: str | None, value: str | None) -> None:
    """Set the identity header injected into every outbound upstream call.

    Pass (None, None) to clear. Header name/value are validated as single-line
    HTTP tokens — CR/LF forbidden to prevent header-split via engagement.yaml.
    """
    global IDENTITY_HEADER_NAME, IDENTITY_HEADER_VALUE
    if not name or not value:
        IDENTITY_HEADER_NAME = None
        IDENTITY_HEADER_VALUE = None
        return
    if any(c in name for c in "\r\n:") or any(c in value for c in "\r\n"):
        raise SafetyBlock("identity header name/value contains illegal CR/LF/colon")
    IDENTITY_HEADER_NAME = name.strip()
    IDENTITY_HEADER_VALUE = value.strip()


def inject_identity_into_raw(raw_request: str) -> str:
    """Insert the identity header into a raw HTTP/1.1 request string just after
    the Host header. No-op if identity is unset or the header already present.
    """
    if not IDENTITY_HEADER_NAME or not IDENTITY_HEADER_VALUE:
        return raw_request
    marker = f"{IDENTITY_HEADER_NAME}:".lower()
    if marker in raw_request.lower():
        return raw_request
    header_line = f"{IDENTITY_HEADER_NAME}: {IDENTITY_HEADER_VALUE}\r\n"
    # Insert after the first \r\n (end of request line) so it sits above Host.
    idx = raw_request.find("\r\n")
    if idx < 0:
        return raw_request
    return raw_request[: idx + 2] + header_line + raw_request[idx + 2 :]


def host_of(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def check_in_scope(url: str) -> None:
    """(1) Reject if host not in SCOPE_HOSTS."""
    host = host_of(url)
    if host is None:
        raise SafetyBlock(f"could not parse host from url: {url!r}")
    if host not in SCOPE_HOSTS:
        raise SafetyBlock(
            f"out-of-scope host {host!r} — add to SCOPE_HOSTS to allow"
        )


def requires_hitl(tool_name: str) -> bool:
    """(4) Tool needs *some* human gate before firing. See PER_CALL / PER_PHASE."""
    return tool_name in HITL_REQUIRED


def requires_hitl_per_call(tool_name: str) -> bool:
    """Per-call HITL: announce intent + target + payload on every single call."""
    return tool_name in HITL_PER_CALL


def requires_hitl_per_phase(tool_name: str) -> bool:
    """Per-phase HITL: announce once at phase start, then run without re-prompting."""
    return tool_name in HITL_PER_PHASE


def confine_report_path(path: str) -> Path:
    """(5) Resolve a report path and ensure it stays under REPORTS_ROOT."""
    p = Path(path).resolve()
    try:
        p.relative_to(REPORTS_ROOT)
    except ValueError:
        raise SafetyBlock(f"report path escapes REPORTS_ROOT: {p}")
    return p


def spotlight_wrap(body: bytes) -> tuple[bytes, bool]:
    """(2+3) Cap, sanitize, and wrap a response body.

    Returns (wrapped_bytes, was_quarantined).
    """
    truncated = False
    if len(body) > RESPONSE_CAP_BYTES:
        body = body[:RESPONSE_CAP_BYTES]
        truncated = True

    quarantined = any(p.search(body) for p in SPOTLIGHT_PATTERNS)

    if quarantined:
        wrapped = (
            b"<untrusted-tool-output source=\"burp\" quarantine=\"true\">\n"
            + body
            + b"\n</untrusted-tool-output>"
        )
        return wrapped, True

    if truncated:
        wrapped = (
            b"<untrusted-tool-output source=\"burp\" truncated=\"true\">\n"
            + body
            + b"\n</untrusted-tool-output>"
        )
        return wrapped, False

    return (
        b"<untrusted-tool-output source=\"burp\">\n"
        + body
        + b"\n</untrusted-tool-output>",
        False,
    )
