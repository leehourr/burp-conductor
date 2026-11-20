# Verbose error disclosure — OpenSSL error codes + framework version leaked on 401

- **Severity:** low
- **Date (UTC):** 2026-11-19

## Details

# Verbose error disclosure on 401 responses

**Severity:** low
**Engagement:** juice-shop
**Date:** 2026-11-19

## Summary
Error-handling HTML returned from write endpoints under `/api/Users/:id` leaks (a) the framework and version (`OWASP Juice Shop (Express ^4.22.1)`) and (b) raw OpenSSL error identifiers (`error:1E08010C:DECODER routines::unsupported`) in both the `<title>` and `<h2>`. The OpenSSL code pinpoints the JWT verification failure mode (unsupported key encoding), giving an attacker a free oracle about the signing primitive without needing to probe further.

## Steps to reproduce
1. Authenticate as a low-privileged test user.
2. Issue a `PUT /api/Users/26` with the Bearer token and any JSON body.
3. Response is `401 Unauthorized`, `Content-Type: text/html`, page body contains the raw error identifier.

## Evidence
```
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=utf-8
...
<title>UnauthorizedError: error:1E08010C:DECODER routines::unsupported</title>
<h1>OWASP Juice Shop (Express ^4.22.1)</h1>
<h2><em>401</em> UnauthorizedError: error:1E08010C:DECODER routines::unsupported</h2>
```

## Impact
- Framework fingerprinting (`Express ^4.22.1`) narrows CVE search for A06 Vulnerable Components.
- OpenSSL error code (`1E08010C`) reveals the JWT-verify middleware path and failure class — useful during JWT algorithm-confusion probing (already filed `2026-11-18-critical-jwt-alg-none-accepted.md`; this makes follow-on probing cheaper).
- Default Express error handler enabled in production path — indicates `NODE_ENV` not set to `production`, which also disables view caching and other hardening.

## Additional evidence — build-path disclosure on /ftp/*.bak 403

Requests for backup files inside the exposed `/ftp` directory listing return a 403 with a stack trace that leaks the absolute build path on the server host:

```
HTTP/1.1 403 Forbidden
...
Error: Only .md and .pdf files are allowed!
    at D:\Work\juice-shop\juice-shop_20.3.0\build\routes\fileServer.js:68:18
```

- Reveals OS (Windows), install root (`D:\Work\juice-shop`), and version (`juice-shop_20.3.0`).
- Confirms the restriction is extension-based, encouraging an attacker to keep hunting for `.md`/`.pdf` misclassifications (e.g. `coupons_2013.md.bak` which the listing already exposes).

## Remediation
- Install a sanitising error handler that returns JSON with a generic message and a correlation id; log full detail server-side only.
- Set `NODE_ENV=production`.
- Remove framework version from error pages.

## References
- OWASP ASVS V7.4 (Error Handling)
- CWE-209 (Generation of Error Message Containing Sensitive Information)
- OWASP Top 10 2021 A05 (Security Misconfiguration)
