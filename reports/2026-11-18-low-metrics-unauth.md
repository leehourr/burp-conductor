# Prometheus /metrics endpoint accessible unauthenticated

- **Severity:** low
- **Date (UTC):** 2026-11-18

## Details

## Summary
`GET /metrics` returns full Prometheus metrics (process stats, Node.js heap, event-loop lag, HTTP request counters, LLM token counters) to unauthenticated requests.

## Steps to reproduce
1. `curl http://localhost:3000/metrics`

## Evidence
Response (200 OK, 25 KB plaintext):
```
juiceshop_startup_duration_seconds{task="datacreator",app="juiceshop"} 41.2682119
process_resident_memory_bytes{app="juiceshop"} 122658816
http_requests_count{status_code="2XX",app="juiceshop"} 100
...
```

## Impact
Discloses runtime fingerprint (Node.js internals, startup tasks, process uptime, request volume, resource usage). On its own low severity; useful to an attacker for timing attacks, scraping request patterns, and confirming version/deployment details.

## Remediation
- Bind `/metrics` to an internal network interface only (not the public listener).
- Require basic-auth or mTLS from the scraping system.
- At minimum, place behind an allowlist of monitoring-system IPs.

## References
- OWASP ASVS V14.3.3 (no unnecessary system info exposed)
- CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

