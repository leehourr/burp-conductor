# robots.txt discloses sensitive /ftp path

- **Severity:** info
- **Date (UTC):** 2026-11-19

## Details

## Summary
`robots.txt` contains `Disallow: /ftp`, explicitly signposting the sensitive FTP directory (see critical finding `ftp-directory-listing`). Crawlers that respect robots.txt won't index it, but any attacker reads robots.txt to find exactly the paths defenders tried to hide.

## Steps to reproduce
1. `curl http://localhost:3000/robots.txt`
2. Body:
```
User-agent: *
Disallow: /ftp
```

## Impact
- Confirms `/ftp` exists and is intended to stay hidden — attacker now has a high-value target.
- Standalone impact is informational; it chains with the critical `/ftp` directory-listing finding.

## Remediation
- Remove the `Disallow: /ftp` line.
- Properly restrict `/ftp` at the server level (see critical finding).
- Use `robots.txt` only for crawler scope, not for security.

## References
- OWASP Testing Guide — WSTG-INFO-03

