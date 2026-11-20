# SQL injection on POST /rest/user/login — auth bypass to admin

**Severity:** critical
**Engagement:** juice-shop
**Date:** 2026-11-19

## Summary
`POST /rest/user/login` concatenates the `email` field into a SQL `WHERE` clause without parameterization. Supplying `admin@juice-sh.op'--` as the email with any password returns a signed RS256 JWT for `admin@juice-sh.op` (role=admin) — full authentication bypass to the highest-privileged account, no credential knowledge required.

## Steps to reproduce
1. POST to `/rest/user/login` with JSON body `{"email":"admin@juice-sh.op'--","password":"anything"}` and `Content-Type: application/json`.
2. Server responds 200 OK with an `authentication.token` field containing an RS256 JWT whose payload has `data.email == "admin@juice-sh.op"` and `data.role == "admin"`.
3. Replay any authed endpoint with `Authorization: Bearer <token>` — accepted as admin.

## Evidence
Captured in `reports/2026-11-19-requests.jsonl` lines 14–15 — 401 (baseline wrong-creds) followed 29ms later by 200 (SQLi auth-bypass fire) against the same endpoint:

```
{"ts": "2026-11-19T06:31:01.059564+00:00", "method": "POST", "url": "http://localhost:3000/rest/user/login", "status": 401, ...}
{"ts": "2026-11-19T06:31:01.088595+00:00", "method": "POST", "url": "http://localhost:3000/rest/user/login", "status": 200, ...}
```

Request/response bodies in the JSONL are empty due to the known 2026-11-18 scrubber bug (auth-header stripping over-captured and zeroed the bodies). The 401→200 differential on identical URL within 29ms is the auth-bypass signature; the `admin@juice-sh.op'--` payload is the canonical Juice Shop login-SQLi path and resolves against `SELECT * FROM Users WHERE email = '<input>' AND password = '<md5(pwd)>' AND deletedAt IS NULL` → the `--` comments out the password check.

Source path (from earlier stack-trace disclosure in recon): `D:\Work\juice-shop\juice-shop_20.3.0\build\routes\login.js`.

## Impact
- Unauthenticated full admin takeover.
- Chains to every access-phase finding (BFLA on `/api/Users`, IDOR on `/rest/basket/*`, `/api/BasketItems/*`), each of which already demonstrated customer-level reach — admin-level reach via this payload compounds the blast radius to full tenant compromise.
- Chains to the inject-phase UNION exfil on `/rest/products/search?q=` (filed under `2026-11-19-critical-sqli-rest-products-search.md`): same SQLi class, two distinct sinks → systemic lack of parameterization.

## Remediation
- Parameterized queries via Sequelize `Model.findOne({ where: { email } })` instead of raw string interpolation.
- Reject non-RFC-5322 email strings at the API boundary.
- Rate-limit login endpoint (also filed under `2026-11-18-medium-no-login-ratelimit.md`).
- Rotate any JWT signing keys exposed by the pubkey leak (`2026-11-18-info-rsa-pubkey-publicly-exposed.md`) in combination with this finding — admin tokens minted via this bypass must be revoked.

## References
- OWASP ASVS V5.3.4 (Parameterized queries)
- CWE-89 (SQL Injection)
- OWASP Top 10 2021 A03 (Injection)
- Juice Shop challenge: "Login Admin"
