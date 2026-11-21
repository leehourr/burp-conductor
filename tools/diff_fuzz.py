"""diff_fuzz — adaptive injection surface discovery.

Our Community-Edition stand-in for Burp Pro's Backslash-Powered Scanner. The
BPS source is Apache-2.0 but hooks `IScannerCheck`, which is Pro-gated — so
the open-source extension cannot run inside Community. This script re-implements
the core idea without the Burp plugin surface: send a baseline, send each
probe, diff response signatures, confirm the interesting ones with an escape
partner. What survives is a candidate novel-injection surface for
`/pentest-inject` to verify by hand.

Invocation (from /pentest-inject via Bash, same pattern as Katana/Nuclei):

    python tools/diff_fuzz.py \\
        --url 'https://target/api/search?q=FUZZ' \\
        --method GET \\
        --baseline 3 \\
        --rl 10 \\
        --out "$SCRATCH/diff-fuzz-<slug>.jsonl"

FUZZ marks the injection point (query string, body, header value — anywhere the
probe should be substituted). Scope is enforced via the project's safety.py.

Output is JSONL: one object per probe, with `signature`, `delta_from_baseline`,
`confirmed_by_partner`, and the full request/response for anything that
diverges. The skill filters by `confirmed_by_partner` and seeds verify_queue.

NOT a verifier. Flags candidates; the human (or MCP's send_http1_request under
HITL) confirms.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import safety  # noqa: E402

FUZZ_MARKER = "FUZZ"

# Poll probes: each probe aims to break a different parser. The "partner"
# is a double-escape form that should NEUTRALIZE the probe — a response that
# diverges on the probe but matches baseline on the partner is high-signal.
PROBES: list[tuple[str, str, str]] = [
    # (name, probe, partner — escape that cancels the probe)
    ("backslash",       "\\",        "\\\\"),
    ("single_quote",    "'",         "''"),
    ("double_quote",    "\"",        "\"\""),
    ("dollar_brace",    "${7*7}",    "$${7*7}"),
    ("hash_brace",      "#{7*7}",    "##{7*7}"),
    ("mustache",        "{{7*7}}",   "{{{{7*7}}}}"),
    ("asp_tag",         "<%7*7%>",   "<<%7*7%>>"),
    ("semicolon",       ";",         ";;"),
    ("null_byte",       "%00",       "%2500"),
    ("ssti_confirm",    "${{7*7}}",  "$${{7*7}}"),  # arithmetic confirm hook
]


@dataclass
class Response:
    status: int
    length: int
    latency_ms: int
    body_head: str = ""   # first 512 chars — reflection detection only
    word_hash: str = ""

    @classmethod
    def from_httpx(cls, r: httpx.Response, latency_ms: int) -> "Response":
        body = r.text
        head = body[:512]
        words = sorted(set(re.findall(r"[A-Za-z0-9_]+", body.lower())))
        wh = hashlib.sha1(("\n".join(words)).encode()).hexdigest()[:12]
        return cls(
            status=r.status_code,
            length=len(body),
            latency_ms=latency_ms,
            body_head=head,
            word_hash=wh,
        )


@dataclass
class Finding:
    probe: str
    payload: str
    baseline_range: dict[str, Any]
    probe_response: dict[str, Any]
    partner_response: dict[str, Any] | None = None
    delta: list[str] = field(default_factory=list)
    confirmed_by_partner: bool = False
    arithmetic_reflected: bool = False


def len_bucket(n: int) -> int:
    """Length bucket: ±10% tolerance. Returns the bucket index."""
    if n < 10:
        return n
    return int(n // max(1, n * 0.1))


def latency_bucket(ms: int) -> str:
    if ms < 250:
        return "fast"
    if ms < 1000:
        return "normal"
    if ms < 3000:
        return "slow"
    return "very_slow"


def signature(r: Response) -> tuple[int, int, str, str]:
    return (r.status, len_bucket(r.length), latency_bucket(r.latency_ms), r.word_hash)


def fire(client: httpx.Client, url: str, method: str, body: str | None,
         headers: dict[str, str]) -> Response:
    t0 = time.monotonic()
    if method == "GET":
        r = client.get(url, headers=headers)
    elif method == "POST":
        r = client.post(url, content=body, headers=headers)
    elif method == "PUT":
        r = client.put(url, content=body, headers=headers)
    else:
        raise ValueError(f"unsupported method: {method}")
    dt = int((time.monotonic() - t0) * 1000)
    return Response.from_httpx(r, dt)


def substitute(template: str, probe: str) -> str:
    return template.replace(FUZZ_MARKER, probe)


def diff(baseline_sigs: list[tuple], probe_sig: tuple, br: Response, pr: Response) -> list[str]:
    deltas: list[str] = []
    bstatus = {s[0] for s in baseline_sigs}
    bbucket = {s[1] for s in baseline_sigs}
    blat = {s[2] for s in baseline_sigs}
    bhash = {s[3] for s in baseline_sigs}

    if probe_sig[0] not in bstatus:
        deltas.append(f"status {pr.status} not in baseline {sorted(bstatus)}")
    if probe_sig[1] not in bbucket:
        deltas.append(f"length {pr.length} out of baseline band")
    if probe_sig[2] not in blat:
        deltas.append(f"latency {pr.latency_ms}ms ({probe_sig[2]}) off baseline")
    if probe_sig[3] not in bhash:
        deltas.append("body content shape changed")
    return deltas


ERROR_TOKENS = [
    re.compile(r"\b(SQL syntax|ORA-\d+|PG::|psycopg|mysql_|unclosed quot)", re.I),
    re.compile(r"\b(Traceback|at [a-zA-Z_.]+\(.*:\d+\)|Exception in thread)", re.I),
    re.compile(r"\b(Whitelabel Error|SpringApplication|DispatcherServlet)", re.I),
    re.compile(r"\b(Jinja|Twig|Freemarker|Velocity|ERB|Mustache)\b", re.I),
]


def error_tokens(body: str) -> list[str]:
    hits = []
    for pat in ERROR_TOKENS:
        m = pat.search(body)
        if m:
            hits.append(m.group(0))
    return hits


def run(args: argparse.Namespace) -> int:
    # Scope enforcement — refuse to fuzz hosts the engagement didn't load.
    if args.scope:
        safety.load_scope(args.scope.split(","))
    try:
        safety.check_in_scope(args.url.replace(FUZZ_MARKER, "SAFE"))
    except safety.SafetyBlock as e:
        print(f"BLOCKED: {e}", file=sys.stderr)
        return 2

    if FUZZ_MARKER not in args.url and FUZZ_MARKER not in (args.body or ""):
        print(f"ERROR: no {FUZZ_MARKER} marker in --url or --body", file=sys.stderr)
        return 2

    headers = {}
    if args.header:
        for h in args.header:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    rate_sleep = 1.0 / args.rl if args.rl > 0 else 0

    with httpx.Client(timeout=args.timeout, verify=not args.insecure,
                      follow_redirects=False) as client:
        # Baseline: N identical safe requests to bound natural variance.
        safe_url = substitute(args.url, "")
        safe_body = substitute(args.body or "", "") if args.body else None
        baseline: list[Response] = []
        for _ in range(args.baseline):
            baseline.append(fire(client, safe_url, args.method, safe_body, headers))
            time.sleep(rate_sleep)
        baseline_sigs = [signature(r) for r in baseline]

        findings: list[Finding] = []
        for name, probe, partner in PROBES:
            p_url = substitute(args.url, probe)
            p_body = substitute(args.body, probe) if args.body else None
            try:
                pr = fire(client, p_url, args.method, p_body, headers)
            except Exception as e:
                print(f"skip {name}: {e}", file=sys.stderr)
                continue
            time.sleep(rate_sleep)

            psig = signature(pr)
            delta = diff(baseline_sigs, psig, baseline[0], pr)

            # Reflection-aware: if the probe text is echoed into the body, the
            # word_hash delta is noise. Suppress hash-only deltas if the probe
            # is reflected.
            reflected = probe in pr.body_head or probe in pr.body_head.lower()
            if reflected and delta == ["body content shape changed"]:
                delta = []

            # Arithmetic confirm: if probe was an SSTI expression and "49"
            # (or the result of the embedded computation) appears in the body
            # but not in baseline, strongly suspicious.
            arith_hit = False
            if "7*7" in probe and "49" in pr.body_head and all(
                "49" not in b.body_head for b in baseline
            ):
                arith_hit = True
                delta.append("arithmetic reflection: '49' present only after SSTI probe")

            # Error-token leakage
            etok = error_tokens(pr.body_head)
            if etok:
                delta.append(f"error tokens: {etok}")

            if not delta:
                continue

            # Partner confirm: fire the double-escape; if it reverts to
            # baseline shape, the parser treated the probe as meaningful.
            partner_url = substitute(args.url, partner)
            partner_body = substitute(args.body, partner) if args.body else None
            try:
                partr = fire(client, partner_url, args.method, partner_body, headers)
            except Exception:
                partr = None
            time.sleep(rate_sleep)

            confirmed = False
            if partr is not None:
                partner_sig = signature(partr)
                partner_delta = diff(baseline_sigs, partner_sig, baseline[0], partr)
                # Partner reverted to baseline => probe was a real escape trigger.
                confirmed = len(partner_delta) == 0

            findings.append(Finding(
                probe=name,
                payload=probe,
                baseline_range={
                    "status": sorted({s[0] for s in baseline_sigs}),
                    "length": [b.length for b in baseline],
                    "latency_ms": [b.latency_ms for b in baseline],
                },
                probe_response=asdict(pr),
                partner_response=asdict(partr) if partr else None,
                delta=delta,
                confirmed_by_partner=confirmed,
                arithmetic_reflected=arith_hit,
            ))

    findings.sort(key=lambda f: (f.arithmetic_reflected, f.confirmed_by_partner, len(f.delta)),
                  reverse=True)

    out = Path(args.out).resolve() if args.out else None
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(asdict(f)) + "\n")

    summary = {
        "url": args.url,
        "method": args.method,
        "baseline_n": args.baseline,
        "probes_fired": len(PROBES),
        "findings": len(findings),
        "confirmed": sum(1 for f in findings if f.confirmed_by_partner),
        "arithmetic": sum(1 for f in findings if f.arithmetic_reflected),
        "out": str(out) if out else None,
    }
    print(json.dumps(summary, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="diff_fuzz",
        description="Adaptive injection-surface discovery via differential response analysis.")
    ap.add_argument("--url", required=True, help=f"URL with {FUZZ_MARKER} marker")
    ap.add_argument("--method", default="GET", choices=["GET", "POST", "PUT"])
    ap.add_argument("--body", default=None, help=f"request body with {FUZZ_MARKER} marker")
    ap.add_argument("--header", action="append", default=[],
                    help="additional header, 'Name: value'; repeatable")
    ap.add_argument("--baseline", type=int, default=3, help="baseline samples (default 3)")
    ap.add_argument("--rl", type=float, default=5, help="rate limit req/s (default 5)")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verify")
    ap.add_argument("--scope", default=None, help="comma-separated hosts to load into scope")
    ap.add_argument("--out", default=None, help="JSONL output path")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
