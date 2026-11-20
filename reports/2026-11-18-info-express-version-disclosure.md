# Express framework version disclosed in 401 error page

- **Severity:** info
- **Date (UTC):** 2026-11-18

## Details

## Summary
Unauthenticated requests to `/api/*` return a styled HTML 401 page that discloses the Express framework version string.

## Steps to reproduce
1. `curl http://localhost:3000/api/Users/`

## Evidence
Response (401 Unauthorized, HTML):
```html
<h1>OWASP Juice Shop (Express ^4.22.1)</h1>
<h2><em>401</em> UnauthorizedError: No Authorization header was found</h2>
```

## Impact
Discloses framework and major-version range, letting attackers prioritize CVE lookups. Low value in isolation but compounds with other info-disclosure findings (admin-config, redirect stack trace) to fingerprint the stack precisely.

## Remediation
- Replace the default Express error view with a generic opaque 401 body.
- Set `app.set('env','production')` and install a custom error handler.

## References
- OWASP ASVS V14.3.3 (do not disclose framework / version info)
- CWE-200 (Information Exposure)

