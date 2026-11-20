# Missing Content-Security-Policy on main application responses

- **Severity:** medium
- **Date (UTC):** 2026-11-19

## Details

## Summary
Main application responses (e.g. `/`, `/rest/*`, `/api/*`) do not set a `Content-Security-Policy` header. Only `/api-docs/*` carries `Content-Security-Policy: default-src 'none'`. Without CSP, XSS defence relies entirely on output encoding — a single sink bypass becomes a full session takeover.

## Steps to reproduce
1. `curl -I http://localhost:3000/`
2. Observe response headers: `Access-Control-Allow-Origin: *`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Feature-Policy: payment 'self'`, `X-Recruiting: /#/jobs`, **no CSP**.
3. Compare against `curl -I http://localhost:3000/api-docs/` — CSP present there.

## Impact
- Paired with the already-filed DOM-XSS on the search parameter (2026-11-19-medium-dom-xss-search.md), the missing CSP removes the last mitigating layer.
- `unsafe-inline` would still be a gap, but no header at all means any injected `<script>` runs.

## Remediation
- Set a strict CSP on all HTML responses, at minimum: `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`.
- Replace legacy `Feature-Policy` with `Permissions-Policy` directives.
- Add `Referrer-Policy: no-referrer` or `strict-origin-when-cross-origin`.

## References
- OWASP ASVS V14.4.1 — CSP enforced
- MDN — Content-Security-Policy

