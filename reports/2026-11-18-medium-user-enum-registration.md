# User enumeration via registration endpoint

- **Severity:** medium
- **Date (UTC):** 2026-11-18

## Details

## Summary
`POST /api/Users` discloses whether an email is already registered via a status and body differential, allowing an unauthenticated attacker to enumerate valid accounts.

## Steps to reproduce
1. Register a test user: `POST /api/Users` with `{"email":"pentest-juice-shop@example.com","password":"wrongpass001"}` → 201 Created.
2. Re-submit the same email: `POST /api/Users` with `{"email":"pentest-juice-shop@example.com","password":"wrongpass001"}` → **400 Bad Request**, body `{"message":"Validation error","errors":[{"field":"email","message":"email must be unique"}]}` (92 bytes, ETag `W/"5c-oKvgu4JOyf1WwfxvTQbfx3UYcK0"`).
3. Submit a random-unknown email: `POST /api/Users` with `{"email":"nonexistent-xyzzy-9f3a@example.com","password":"wrongpass001"}` → **201 Created**, body 325 bytes with `Location: /api/Users/27`, full user object (`id`, `email`, `role`, `createdAt`).

Note: login endpoint `/rest/user/login` does NOT enumerate — known vs unknown emails return byte-identical 401 responses (26 bytes, ETag `W/"1a-ARJvVK+smzAF3QQve2mDSG+3Eus"`). Leak is isolated to registration.

## Evidence
Known email (conflict):
```http
POST /api/Users HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Content-Length: 68

{"email":"pentest-juice-shop@example.com","password":"wrongpass001"}
```
```http
HTTP/1.1 400 Bad Request
Content-Length: 92

{"message":"Validation error","errors":[{"field":"email","message":"email must be unique"}]}
```

Unknown email (success):
```http
POST /api/Users HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Content-Length: 72

{"email":"nonexistent-xyzzy-9f3a@example.com","password":"wrongpass001"}
```
```http
HTTP/1.1 201 Created
Location: /api/Users/27
Content-Length: 325

{"status":"success","data":{"id":27,"email":"nonexistent-xyzzy-9f3a@example.com","role":"customer",...}}
```

Discriminator: status (400 vs 201) + body length (92 vs 325) + explicit error field name (`"email must be unique"`). No rate-limit on `/api/Users` observed, so enumeration scales to the full address space the attacker is willing to grind.

## Impact
An unauthenticated attacker can:
1. Enumerate valid user emails at scale (one request per candidate), producing a validated list for credential-stuffing, phishing, or targeted social engineering.
2. Confirm executive / admin accounts for spear-phishing without ever touching the login endpoint (which is correctly hardened against enum).
3. Chain with the no-login-rate-limit finding (`2026-11-18-medium-no-login-ratelimit.md`): enumerate here, then brute-force the login endpoint against confirmed accounts only.

Side-effect of probing: successful probes create real user records on the server (id=27 was created during this test). On a real engagement these would need cleanup.

## Remediation
- Return an identical 2xx-shaped response (or an identical 400 with a generic `"registration received"` body) for both the taken-email and new-email cases. Deliver a verification email asynchronously; only the email owner receives the outcome.
- Alternative (weaker): return 400 with a generic `"invalid request"` body and no `field`/`message` schema differential.
- Add rate-limiting to `/api/Users` matching the login endpoint policy once that is remediated (per-IP + per-email, 429 with Retry-After).
- Same enumeration check should be applied to `/rest/user/reset-password` and `/rest/user/security-question` endpoints during the reset_mfa check.

## References
- OWASP ASVS v4 §2.1.12 (authentication responses must not permit username enumeration)
- CWE-204 (Observable Response Discrepancy)
- CWE-203 (Observable Discrepancy)

