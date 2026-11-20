# Unauthenticated security-question disclosure enables password-reset chain

- **Severity:** high
- **Date (UTC):** 2026-11-18

## Details

## Summary
`GET /rest/user/security-question?email=<addr>` returns the full security-question text for any user that has one set, with no authentication. Combined with Juice Shop's reset flow (`POST /rest/user/reset-password` takes `{email, answer, new, repeat}` with no email token), this reduces unauthenticated account takeover to a single guessable answer per target account.

## Steps to reproduce
1. Send unauthenticated `GET /rest/user/security-question?email=admin@juice-sh.op` via Burp.
2. Observe HTTP 200 with the question field in the JSON body.
3. Repeat with an email that has no security question set, or an unknown email — receive `{}` instead. Differential also leaks whether an account has a question configured.

## Evidence
Request (unauthenticated):
```http
GET /rest/user/security-question?email=admin@juice-sh.op HTTP/1.1
Host: localhost:3000
```
Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 134
ETag: W/"86-7lKHyn00vUiu7tauUbR5wME8FQo"

{"question":{"id":2,"question":"Mother's maiden name?","createdAt":"2026-11-18T10:16:29.148Z","updatedAt":"2026-11-18T10:16:29.148Z"}}
```

Control pair (empty results — user without a question / unknown email):
```http
GET /rest/user/security-question?email=pentest-juice-shop@example.com HTTP/1.1
→ 200 OK · Content-Length: 2 · body: {}

GET /rest/user/security-question?email=nonexistent-xyzzy-9f3a@example.com HTTP/1.1
→ 200 OK · Content-Length: 2 · body: {}
```

## Impact
An unauthenticated attacker can:
1. Enumerate which accounts have a security question set (134-byte body vs 2-byte `{}`), bypassing the login endpoint's byte-identical hardening.
2. Read the exact question text for each target account.
3. Attempt the reset flow (`POST /rest/user/reset-password`) with guessed answers — no email loop, no out-of-band verification, no rate-limit observed in the login check.

The three pieces chain to full account takeover on any user with a weak or publicly-researchable answer (place of birth, mother's maiden name, pet's name). On `admin@juice-sh.op` this escalates to administrative account compromise.

## Remediation
1. Require authentication to read a user's own security question; never expose other users' questions.
2. Replace the security-question reset path with an email-token + expiry flow.
3. Apply strict per-account rate-limiting and account-level lockout on reset attempts.
4. Return a generic response (`202 Accepted` with no body) regardless of whether the email exists or has a question set — removes the enumeration oracle.

## References
- OWASP ASVS §2.5 (Credential Recovery)
- CWE-640 (Weak Password Recovery Mechanism for Forgotten Password)
- CWE-204 (Observable Response Discrepancy)
- NIST SP 800-63B §5.1.1.2 (knowledge-based authentication deprecated)

