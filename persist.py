"""Persistence layer — append-only JSONL request log + markdown finding writer
+ engagement state (engagement.yaml) read/advance helpers.

Disk is ground truth: Burp Community loses project state on close, so every
request worth remembering gets logged here. Reports live under REPORTS_ROOT
so Otoi-san can review without opening Burp.

All writes go through safety.confine_report_path and strip auth headers.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

import safety

STATE_FILENAME = "engagement.yaml"
TEMPLATE_PATH = Path(__file__).parent / "templates" / "engagement.yaml"
PHASE_STATUSES = {"pending", "in_progress", "done", "skipped", "blocked"}
DEFAULT_PHASES = ["recon", "auth", "crawl", "baseline_scan", "verify", "report"]

AUTH_HEADER_RE = re.compile(
    r"^(authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization)\s*:",
    re.I | re.M,
)

SLUG_RE = re.compile(r"[^a-z0-9-]+")

# Request-line + Host-header parser for raw HTTP/1.1 captured from Burp.
# Group 1: method, 2: path, 3: host, 4: port (optional).
REQUEST_LINE_RE = re.compile(r"^([A-Z]+)\s+(\S+)\s+HTTP/", re.M)
HOST_HEADER_RE = re.compile(r"^Host:\s*([^\r\n:]+)(?::(\d+))?", re.I | re.M)

# Burp MCP truncates serialized items at 5000 chars and appends this marker.
UPSTREAM_TRUNC_MARKER = "... (truncated)"

# Ports we treat as HTTPS when scheme must be inferred (raw HTTP/1.1 drops it).
HTTPS_PORTS = {443, 8443, 9443}


def _today_log() -> Path:
    name = f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}-requests.jsonl"
    return safety.confine_report_path(str(safety.REPORTS_ROOT / name))


def _strip_auth(text: str) -> str:
    return AUTH_HEADER_RE.sub(r"\1: [REDACTED]", text)


def _cap(text: str, limit: int = safety.RESPONSE_CAP_BYTES) -> str:
    b = text.encode("utf-8", errors="replace")
    if len(b) <= limit:
        return text
    return b[:limit].decode("utf-8", errors="replace") + "\n...[truncated]"


def log_request(
    method: str,
    url: str,
    status: int,
    request_bytes: str = "",
    response_bytes: str = "",
) -> str:
    """Append one request/response pair to today's JSONL log. Scope-checked."""
    try:
        safety.check_in_scope(url)
    except safety.SafetyBlock as e:
        return f"BLOCKED: {e}"

    path = _today_log()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": method.upper(),
        "url": url,
        "status": status,
        "request": _cap(_strip_auth(request_bytes)),
        "response": _cap(_strip_auth(response_bytes)),
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return f"logged -> {path}"


def _slugify(s: str) -> str:
    return SLUG_RE.sub("-", s.lower()).strip("-")[:60] or "finding"


def save_finding(slug: str, severity: str, title: str, body: str) -> str:
    """Write a markdown finding under REPORTS_ROOT."""
    sev = severity.lower().strip()
    if sev not in {"info", "low", "medium", "high", "critical"}:
        return f"BLOCKED: bad severity {severity!r}"
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    name = f"{date}-{sev}-{_slugify(slug)}.md"
    try:
        path = safety.confine_report_path(str(safety.REPORTS_ROOT / name))
    except safety.SafetyBlock as e:
        return f"BLOCKED: {e}"

    path.parent.mkdir(parents=True, exist_ok=True)
    md = (
        f"# {title}\n\n"
        f"- **Severity:** {sev}\n"
        f"- **Date (UTC):** {date}\n\n"
        f"## Details\n\n{body}\n"
    )
    path.write_text(md, encoding="utf-8")
    return f"wrote -> {path}"


# ---------------------------------------------------------------------------
# Engagement state — engagement.yaml is the single source of truth for where
# an engagement is. Phase skills read it on start, write back on checkpoint.
# ---------------------------------------------------------------------------


def _state_path(engagement: str) -> Path:
    slug = _slugify(engagement)
    return safety.confine_report_path(
        str(safety.REPORTS_ROOT / slug / STATE_FILENAME)
    )


def read_state(engagement: str) -> dict[str, Any]:
    """Load engagement.yaml for <engagement>. Raises FileNotFoundError if absent."""
    path = _state_path(engagement)
    if not path.exists():
        raise FileNotFoundError(f"no engagement state at {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def advance_phase(engagement: str, phase: str, patch: dict[str, Any]) -> str:
    """Merge patch into state['phases'][phase], stamp checkpoint, write back.

    `patch` may set status, cursor, artifacts, notes, etc. Status (if present)
    is validated against PHASE_STATUSES. The checkpoint timestamp is always
    overwritten with 'now'.
    """
    if "status" in patch and patch["status"] not in PHASE_STATUSES:
        return f"BLOCKED: bad status {patch['status']!r}"

    state = read_state(engagement)
    phases = state.setdefault("phases", {})
    entry = phases.setdefault(phase, {})
    entry.update(patch)
    entry["checkpoint"] = datetime.now(timezone.utc).isoformat()

    path = _state_path(engagement)
    path.write_text(
        yaml.safe_dump(state, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return f"advanced {phase} -> {entry.get('status', '?')} @ {entry['checkpoint']}"


def list_engagements() -> list[dict[str, Any]]:
    """List every engagement under REPORTS_ROOT with a state file. Cheap read."""
    out: list[dict[str, Any]] = []
    if not safety.REPORTS_ROOT.exists():
        return out
    for child in sorted(safety.REPORTS_ROOT.iterdir()):
        if not child.is_dir():
            continue
        state_file = child / STATE_FILENAME
        if not state_file.exists():
            continue
        try:
            data = yaml.safe_load(state_file.read_text(encoding="utf-8")) or {}
        except Exception as e:
            out.append({"engagement": child.name, "error": str(e)})
            continue
        phases = data.get("phases") or {}
        out.append(
            {
                "engagement": data.get("engagement") or child.name,
                "client": data.get("client"),
                "window": data.get("window"),
                "phase_status": {k: (v or {}).get("status") for k, v in phases.items()},
            }
        )
    return out


def start_engagement(
    slug: str,
    client: str,
    hosts: list[str],
    window_start: str | None = None,
    window_end: str | None = None,
) -> str:
    """Create reports/<slug>/engagement.yaml from the template with identity
    + scope + window prefilled. Refuses to overwrite an existing state file.
    """
    slug = _slugify(slug)
    if not slug:
        return "BLOCKED: empty slug"
    if not hosts:
        return "BLOCKED: at least one scope host required"

    path = _state_path(slug)
    if path.exists():
        return f"BLOCKED: engagement.yaml already exists at {path}"

    if not TEMPLATE_PATH.exists():
        return f"BLOCKED: template missing at {TEMPLATE_PATH}"

    data = yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8")) or {}
    data["engagement"] = slug
    data["client"] = client
    data["scope"] = {"hosts": list(hosts), "notes": (data.get("scope") or {}).get("notes")}
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data["window"] = {
        "start": window_start or today,
        "end": window_end,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return f"started -> {path}"


# ---------------------------------------------------------------------------
# Replay layer — snapshot Burp proxy history to disk before the Burp process
# dies, then re-fire selected requests through send_http1_request on resume.
#
# Why: Burp Community has no project-save. When Burp exits, proxy history is
# gone. Our JSONL only has traffic Claude explicitly logged, so browser-driven
# exploration is lost too. This layer pulls history straight from Burp's MCP
# (GetProxyHttpHistoryRegex, verified 2026-11-18 against PortSwigger/mcp-server
# source) and persists full raw bytes per item — up to the upstream's 5000-char
# per-item cap, flagged where hit.
# ---------------------------------------------------------------------------


def replay_log_path(slug: str, date: str | None = None) -> Path:
    """reports/<slug>/replay-YYYY-MM-DD.jsonl"""
    slug = _slugify(slug)
    date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return safety.confine_report_path(
        str(safety.REPORTS_ROOT / slug / f"replay-{date}.jsonl")
    )


def parse_raw_request(raw: str) -> dict[str, Any]:
    """Pull method, path, host, port out of a raw HTTP/1.1 request string.

    Returns {} if the request line or Host header can't be parsed. Scheme is
    not recoverable from the raw request alone (Burp's MCP serialization drops
    HttpService) — caller infers from port (443→https, else http) and may be
    wrong for non-standard https ports. Document this to the user.
    """
    rl = REQUEST_LINE_RE.search(raw)
    if not rl:
        return {}
    method, path = rl.group(1), rl.group(2)
    host_m = HOST_HEADER_RE.search(raw)
    if not host_m:
        return {}
    host = host_m.group(1).strip()
    port = int(host_m.group(2)) if host_m.group(2) else 443
    return {"method": method, "path": path, "host": host, "port": port}


def _was_upstream_truncated(text: str) -> bool:
    return isinstance(text, str) and text.endswith(UPSTREAM_TRUNC_MARKER)


def find_in_request_log(
    method: str, host: str, path: str, days: int = 7
) -> dict[str, Any] | None:
    """Scan recent log_request JSONL files for a matching entry.

    Preferred rehydration source when upstream proxy history truncates an item
    at 5000 chars: our own log holds the full bytes (up to RESPONSE_CAP_BYTES,
    8 KB default) and the full URL with scheme. Match is method + host + path
    (ignoring query). Returns the most recent hit, or None.
    """
    from datetime import timedelta

    today = datetime.now(timezone.utc).date()
    want_path = path.split("?", 1)[0]
    want_method = method.upper()
    for i in range(days):
        day = today - timedelta(days=i)
        fname = f"{day.isoformat()}-requests.jsonl"
        p = safety.REPORTS_ROOT / fname
        if not p.exists():
            continue
        hit: dict[str, Any] | None = None
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("method") != want_method:
                continue
            url = e.get("url", "")
            if host not in url:
                continue
            # crude path check — url contains host+path prefix
            if want_path not in url.split("?", 1)[0]:
                continue
            hit = e  # keep scanning; last match in file wins (most recent)
        if hit:
            return hit
    return None


def write_replay_entry(
    slug: str,
    raw_request: str,
    raw_response: str,
    notes: str | None = None,
    date: str | None = None,
) -> dict[str, Any]:
    """Scrub + scope-check + append one history item to replay JSONL.

    Returns a result dict: {status: "ok"|"out_of_scope"|"unparseable",
    host?, truncated_req?, truncated_resp?}. Does not raise on skip — the
    caller is iterating a batch and needs per-item status.
    """
    parsed = parse_raw_request(raw_request or "")
    if not parsed:
        return {"status": "unparseable"}

    # Scope check — host must be in SCOPE_HOSTS or we drop silently.
    if parsed["host"] not in safety.SCOPE_HOSTS:
        return {"status": "out_of_scope", "host": parsed["host"]}

    truncated_req = _was_upstream_truncated(raw_request)
    truncated_resp = _was_upstream_truncated(raw_response)

    # If upstream truncated either side, try to rehydrate from our own
    # log_request JSONL (full bytes + full URL with scheme).
    rehydrated_fields: list[str] = []
    scheme_source = "port_heuristic"
    scheme_https = parsed["port"] in HTTPS_PORTS
    scrubbed_req = _strip_auth(raw_request or "")
    scrubbed_resp = _strip_auth(raw_response or "")
    if truncated_req or truncated_resp:
        hit = find_in_request_log(parsed["method"], parsed["host"], parsed["path"])
        if hit:
            if truncated_req and hit.get("request"):
                scrubbed_req = _strip_auth(hit["request"])  # already scrubbed at log time, cheap re-pass
                rehydrated_fields.append("request")
                truncated_req = False
            if truncated_resp and hit.get("response"):
                scrubbed_resp = _strip_auth(hit["response"])
                rehydrated_fields.append("response")
                truncated_resp = False
            url = hit.get("url", "")
            if url.startswith("https://"):
                scheme_https = True
                scheme_source = "log_url"
            elif url.startswith("http://"):
                scheme_https = False
                scheme_source = "log_url"

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": parsed["method"],
        "host": parsed["host"],
        "port": parsed["port"],
        "https": scheme_https,
        "scheme_source": scheme_source,  # log_url | port_heuristic
        "path": parsed["path"],
        "request": scrubbed_req,
        "response": scrubbed_resp,
        "notes": notes or "",
        "upstream_truncated": truncated_req or truncated_resp,
        "rehydrated_from_log": rehydrated_fields,
    }

    path = replay_log_path(slug, date)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return {
        "status": "ok",
        "host": parsed["host"],
        "truncated_req": truncated_req,
        "truncated_resp": truncated_resp,
        "rehydrated_from_log": rehydrated_fields,
        "scheme_source": scheme_source,
    }


def read_replay_entries(path: Path) -> list[dict[str, Any]]:
    """Load a replay JSONL. Returns [] if missing. Malformed lines skipped."""
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def inject_auth(raw_request: str, auth_headers: dict[str, str]) -> str:
    """Rewrite named headers in a raw HTTP/1.1 request. Case-insensitive match,
    append if absent. Used at replay time to splice fresh session material into
    a request whose original auth was scrubbed at checkpoint time.
    """
    if not auth_headers:
        return raw_request

    # Split headers from body on the first blank line.
    head, sep, body = raw_request.partition("\r\n\r\n")
    if not sep:
        head, sep, body = raw_request.partition("\n\n")
        if not sep:
            return raw_request  # malformed; let upstream deal with it

    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
    lower_names = {k.lower(): (k, v) for k, v in auth_headers.items()}
    kept: list[str] = []
    seen: set[str] = set()
    for i, line in enumerate(lines):
        if i == 0:  # request line stays
            kept.append(line)
            continue
        name = line.split(":", 1)[0].strip().lower() if ":" in line else ""
        if name in lower_names:
            orig_name, val = lower_names[name]
            kept.append(f"{orig_name}: {val}")
            seen.add(name)
        else:
            kept.append(line)
    for name, (orig_name, val) in lower_names.items():
        if name not in seen:
            kept.append(f"{orig_name}: {val}")

    return "\r\n".join(kept) + "\r\n\r\n" + body


def next_phase(engagement: str) -> str | None:
    """Return the first phase whose status is 'pending' or 'in_progress', in
    DEFAULT_PHASES order. None if all done/skipped/blocked.
    """
    state = read_state(engagement)
    phases = state.get("phases") or {}
    for name in DEFAULT_PHASES:
        entry = phases.get(name) or {}
        if entry.get("status") in {"pending", "in_progress", None}:
            return name
    return None
