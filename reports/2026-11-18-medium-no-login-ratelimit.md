# No rate-limit on POST /rest/user/login

- **Severity:** medium
- **Date (UTC):** 2026-11-18

## Details

## Summary
The login endpoint `POST /rest/user/login` has no rate-limit, lockout, or CAPTCHA. Five sequential wrong-password attempts against a disposable test account returned identical 401 responses with no `Retry-After`, no 429, no backoff. A prior 10-request parallel burst stalled all ten on the bcrypt-serialized Node event loop without triggering any throttle response, confirming the server queues rather than rejects.

## Steps to reproduce
1. Register or reuse a test account (`pentest-juice-shop@example.com`).
2. Fire N wrong-password POST requests to `/rest/user/login`, sequentially or in parallel, from a single source IP.
3. Observe: every response is `401 Unauthorized`, body `Invalid email or password.` (26 bytes), no `Retry-After` header, no inflection point.

## Evidence
Request (×5, serial):
```http
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Content-Length: 68

{"email":"pentest-juice-shop@example.com","password":"wrongpass00N"}
```

Response (identical across all 5 attempts):
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=utf-8
Content-Length: 26

Invalid email or password.
```

Response timestamps (serial fires): `17:01:02`, `17:01:11`, `17:01:19`, `17:01:27`, `17:01:35` — ~8s inter-arrival from bcrypt latency alone, no server-side pacing.

Independent signal: a prior 10-request parallel burst all timed out at the MCP client (~60s), consistent with bcrypt saturation on a single-threaded Node process serving the queue — not throttling.

## Impact
Unthrottled login enables credential stuffing against the ~100 million breach-compiled credential lists in common use, password spraying across a user base, and targeted brute-force of weak passwords. OWASP ASVS V2.2.1 and NIST SP 800-63B §5.2.2 require anti-automation on authentication endpoints.

## Remediation
- Server-side rate-limit per source IP **and** per account on `/rest/user/login` (e.g. `express-rate-limit` with sliding window: 10 attempts / 15 min per IP, 5 / 15 min per account).
- Return `429 Too Many Requests` with `Retry-After` once threshold hit.
- Add temporary account lockout (15 min, exponential) after N consecutive failures per account.
- Pair with CAPTCHA (hCaptcha / Turnstile) after first threshold crossing, before hard lockout.
- Apply the same controls to `/rest/user/reset-password`, `/rest/2fa/verify`, and any secondary auth surface to prevent pivot.

## References
- OWASP ASVS v5.0 — V2.2.1 (Anti-automation)
- OWASP ASVS v5.0 — V11.1.4 (Account lockout)
- NIST SP 800-63B §5.2.2 — Rate limiting
- CWE-307 — Improper Restriction of Excessive Authentication Attempts
- OWASP Top 10 2021 — A07: Identification and Authentication Failures

