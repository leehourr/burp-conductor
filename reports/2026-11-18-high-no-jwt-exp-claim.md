# JWT has no `exp` claim — tokens valid indefinitely

- **Severity:** high
- **Date (UTC):** 2026-11-18

## Details

## Summary
JWTs issued by `POST /rest/user/login` contain no `exp` (expiration) claim. express-jwt's default is to accept tokens without `exp` as non-expiring. Tokens remain valid until the signing key rotates — effectively forever in this build.

## Steps to reproduce
1. Login as `pentest-juice-shop@example.com`.
2. Base64-decode the JWT payload.
3. Grep for `exp` — absent.

## Evidence
Decoded JWT payload (top-level claims):
```json
{
  "data": { ... user object ... },
  "bid": 7,
  "iat": 1795019782
}
```
Only `iat` (issued-at) is present. No `exp`, no `nbf`. The signing config in `lib/insecurity.js` passes no `expiresIn` to `jwt.sign()`.

## Impact
- A stolen token (XSS, device theft, log leak, backup exfiltration) remains valid indefinitely — there is no automatic expiry.
- Combined with the absence of a server-side revocation endpoint (see `no-server-side-logout` finding), a compromised token can only be invalidated by rotating the JWT signing key, which invalidates every active session globally.

## Remediation
- Set `expiresIn: '15m'` (short-lived access token) in `jwt.sign()` and pair with a refresh-token flow.
- At minimum, set `expiresIn: '1h'` as a hard ceiling.
- Validate `exp` server-side via express-jwt's default behavior (already active once the claim is present).

## References
- OWASP ASVS 3.3.1 — session timeout
- RFC 7519 §4.1.4 — `exp` claim
- CWE-613: Insufficient Session Expiration

