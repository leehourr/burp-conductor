# Unauthenticated Prometheus metrics endpoint discloses internal state

- **Severity:** medium
- **Date (UTC):** 2026-11-19

## Details

## Summary
`GET /metrics` returns a full Prometheus exposition without authentication, leaking per-endpoint request counts, process CPU/memory stats, Node.js heap internals, and application-specific gauges (LLM token usage, startup task names).

## Steps to reproduce
1. `curl http://localhost:3000/metrics`
2. Observe text/plain Prometheus output containing `juiceshop_llm_input_tokens_total`, `http_requests_count{status_code=...}`, `process_cpu_*`, `nodejs_heap_*`, `juiceshop_startup_duration_seconds` with internal task names (`validateConfig`, `cleanupFtpFolder`, `datacreator`).

## Evidence
```http
GET /metrics HTTP/1.1
Host: localhost:3000
```
Response:
```
# HELP juiceshop_llm_input_tokens_total ...
# HELP http_requests_count ...
# HELP process_cpu_user_seconds_total ...
# HELP juiceshop_startup_duration_seconds Duration of startup tasks
juiceshop_startup_duration_seconds{task="validateConfig"} ...
juiceshop_startup_duration_seconds{task="cleanupFtpFolder"} ...
```

## Impact
- Reveals internal architecture (startup tasks confirm `/ftp` handling exists).
- Request-count buckets by status_code help attackers time brute-force without triggering alarms.
- Process metrics aid in DoS planning (heap limits, CPU headroom).

## Remediation
- Bind `/metrics` to a management-interface only, not the public listener.
- Require authentication (basic auth or mTLS) if metrics must stay on the main port.
- Scrub label values that disclose internal task names before exposing.

## References
- CWE-200 — Exposure of Sensitive Information
- Prometheus security docs — "Metrics endpoints should not be exposed publicly"

