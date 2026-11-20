# /redirect returns unhandled stack trace revealing server path

- **Severity:** medium
- **Date (UTC):** 2026-11-18

## Details

## Summary
`GET /redirect` without the required `to` parameter triggers an unhandled `TypeError` and returns the full Node.js stack trace, disclosing absolute server paths and source structure.

## Steps to reproduce
1. `curl http://localhost:3000/redirect`

## Evidence
Response (500):
```
TypeError: Cannot read properties of undefined (reading 'includes')
at Object.isRedirectAllowed (D:\Work\juice-shop\juice-shop_20.3.0\build\lib\insecurity.js:157:34)
```
Full trace discloses `build/lib/insecurity.js` and Express middleware chain.

## Impact
Reveals the absolute filesystem path, framework internals (Express middleware order), and a security-relevant source file (`insecurity.js`) attackers will target for code review. Also confirms `/redirect` is an open-redirect surface — its parameter-less failure path hints that a valid `to=` call accepts arbitrary URLs for the open-redirect check.

## Remediation
- Install a global Express error handler that returns opaque 400/500 responses and logs the trace server-side only.
- Validate `to` param before dereferencing and respond 400 on missing/invalid input.
- Harden `isRedirectAllowed` to enforce an explicit allowlist of redirect targets.

## References
- OWASP ASVS V7.4.1 (error handling does not reveal sensitive information)
- CWE-209 (Information Exposure Through an Error Message)
- CWE-601 (URL Redirection to Untrusted Site — follow-up probe needed)

