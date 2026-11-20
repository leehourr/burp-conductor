# Unauthenticated directory listing at /ftp exposes application files

- **Severity:** critical
- **Date (UTC):** 2026-11-19

## Details

## Summary
The `/ftp` endpoint serves an unauthenticated directory index with downloadable application files (backups, package manifests, logs). Any attacker can enumerate and retrieve sensitive files without authentication.

## Steps to reproduce
1. `curl http://localhost:3000/ftp`
2. Observe HTML listing with `<title>listing directory /ftp</title>` and download links.
3. Attempt disallowed filename variants (e.g. `.bak`) — server responds 403 but leaks internal Express path in the error body.

## Evidence
Request:
```http
GET /ftp HTTP/1.1
Host: localhost:3000
```
Response:
```
HTTP/1.1 200 OK
Content-Type: text/html
<title>listing directory /ftp</title>
...
```

Related: `/robots.txt` explicitly discloses this path (`Disallow: /ftp`), which signposts it to attackers rather than hiding it.

## Impact
- Source leak, backup download, acquisition of files intended to be internal.
- Chain: attacker reads `/ftp` → downloads `.md.bak`/`.pdf` files → extracts credentials, version info, intellectual property.

## Remediation
- Remove the directory-listing middleware from production builds.
- Enforce an allowlist on `/ftp/*` — only serve explicitly whitelisted files, if any.
- Strip the `Disallow: /ftp` hint from `robots.txt` (security-by-robots is a disclosure channel).

## References
- OWASP ASVS V14.3.3 — no directory listing
- CWE-548 — Exposure of Information Through Directory Listing

