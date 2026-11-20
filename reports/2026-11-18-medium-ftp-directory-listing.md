# /ftp directory listing exposed unauthenticated

- **Severity:** medium
- **Date (UTC):** 2026-11-18

## Details

## Summary
`GET /ftp` returns an HTML directory listing of server-side files unauthenticated, exposing internal filenames including backups, logs, and PDF archives.

## Steps to reproduce
1. `curl http://localhost:3000/ftp`

## Evidence
Response (200 OK):
```html
<title>listing directory /ftp</title>
```
Listing includes `acquisitions.md`, `announcement_encrypted.md`, `coupons_2013.md.bak`, `eastere.gg`, `encrypt.pyc`, `incident-support.kdbx`, `legal.md`, `package.json.bak`, `suspicious_errors.yml`, plus multiple PDFs and image assets.

## Impact
Unauthenticated file enumeration leaks internal filenames, backup files, and suspicious artifacts (`.kdbx` password vault, `.bak` package manifest, encrypted announcement). Attackers map file-read primitives and candidate paths for LFI / path-traversal attempts against downstream endpoints.

## Remediation
- Disable directory listing for `/ftp` (serve 403 or 404).
- Remove backup / sensitive files from the web root.
- If `/ftp` must expose content, enforce an allowlist of public filenames and reject the rest.

## References
- OWASP ASVS V14.3.2 (web server configuration)
- CWE-548 (Exposure of Information Through Directory Listing)

