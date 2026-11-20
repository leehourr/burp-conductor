# Admin application-configuration endpoint accessible unauthenticated

- **Severity:** medium
- **Date (UTC):** 2026-11-18

## Details

## Summary
`GET /rest/admin/application-configuration` returns the full server configuration JSON to unauthenticated requests, including OAuth clientId, chatbot model, challenge-URL overrides, and XSS bonus payload.

## Steps to reproduce
1. `curl http://localhost:3000/rest/admin/application-configuration`

## Evidence
Response (200 OK, 36 KB JSON):
```json
{"config":{"server":{"baseUrl":"http://localhost:3000"},
 "application":{"googleOauth":{"clientId":"1005568560502-...apps.googleusercontent.com","authorizedRedirects":[...]},
 "chatBot":{"model":"gemma4:e4b","llmMaxRetries":2},
 "challenges":{"overwriteUrlForCsrfChallenge":"http://htmledit.squarefree.com","xssBonusPayload":"<iframe...>"}
 ...
```

## Impact
The `/rest/admin/*` namespace implies privileged access; exposing config unauthenticated discloses internal URLs, third-party integration identifiers (OAuth clientId, chatbot model), and configuration overrides that an attacker can map to attack surface. Also enables fingerprinting of version, feature flags, and challenge state.

## Remediation
- Enforce authentication + admin role on all `/rest/admin/*` routes.
- Return a public, minimal `/rest/application-configuration` for frontend-needed values only (theme, logo, welcome banner).
- Scrub integration secrets and challenge overrides from any public response.

## References
- OWASP ASVS V1.4.1 (access control enforced at trusted layer)
- CWE-284 (Improper Access Control)

