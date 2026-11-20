# Missing Referrer-Policy and Permissions-Policy headers

- **Severity:** low
- **Date (UTC):** 2026-11-19

## Details

## Summary
Responses omit `Referrer-Policy` and `Permissions-Policy`. The legacy `Feature-Policy: payment 'self'` header is sent instead of its successor. Browsers fall back to default behaviour (full referrer sent cross-origin), which leaks path + query strings including any reset tokens or object IDs.

## Steps to reproduce
1. `curl -I http://localhost:3000/`
2. Response contains `Feature-Policy: payment 'self'` only; no `Referrer-Policy`, no `Permissions-Policy`.

## Impact
- Reset tokens or sensitive IDs in URL query strings leak via `Referer` to third-party resources (analytics, CDN, embedded iframes).
- Feature-Policy is deprecated; modern browsers may ignore it.

## Remediation
- Add `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` for the auth/reset paths).
- Replace `Feature-Policy` with the equivalent `Permissions-Policy` directives.

## References
- MDN — Referrer-Policy, Permissions-Policy
- OWASP ASVS V14.4.6

