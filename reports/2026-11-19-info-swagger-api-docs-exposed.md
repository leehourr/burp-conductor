# Swagger UI exposed at /api-docs/ discloses API surface

- **Severity:** info
- **Date (UTC):** 2026-11-19

## Details

## Summary
`/api-docs/` serves a fully-rendered Swagger UI. The endpoint is reachable without authentication and loads `swagger-ui-init.js`, which carries the full API schema. This hands attackers the complete endpoint inventory, including admin routes already shown to be vulnerable (see critical `bfla-api-users-list`).

## Steps to reproduce
1. `curl -L http://localhost:3000/api-docs`
2. Browser `http://localhost:3000/api-docs/` — Swagger UI renders in full.
3. Fetch `/api-docs/swagger-ui-init.js` to pull the raw schema.

## Evidence
Response headers include `Content-Security-Policy: default-src 'none'` (only on this path) and HTML body loads `swagger-ui-bundle.js` + `swagger-ui-init.js`.

## Impact
- Attackers skip surface mapping — they get the full endpoint list, parameters, and expected shapes.
- Chains with the IDOR/BFLA findings already filed.

## Remediation
- Gate `/api-docs/*` behind authentication, or disable in production builds.
- If kept public, remove sensitive admin endpoints from the schema.

## References
- OWASP API Security Top 10 — API9:2023 Improper Inventory Management

