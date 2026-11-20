# Password hash (MD5) embedded in JWT payload returned to client

- **Severity:** high
- **Date (UTC):** 2026-11-18

## Details

## Summary
`POST /rest/user/login` returns a JWT whose payload embeds the user's stored password hash in the `data.password` field. Any token holder can Base64-decode the payload and offline-crack the hash.

## Steps to reproduce
1. Register a test user: `POST /api/Users` with `{"email":"pentest-juice-shop@example.com","password":"TestP@ss123!"}`.
2. Login: `POST /rest/user/login` with the same credentials.
3. Base64-decode the second segment of the returned `authentication.token`.

## Evidence
Request:
```http
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"email":"pentest-juice-shop@example.com","password":"TestP@ss123!"}
```
Response (200 OK, JWT payload decoded):
```json
{
  "data": {
    "id": 26,
    "username": "pentest",
    "email": "pentest-juice-shop@example.com",
    "password": "2c103f2c4ed1e59c0b4e2e01821770fa",
    "role": "customer",
    ...
  },
  "bid": 7,
  "iat": 1795019782
}
```
The 32-char hex string in `data.password` is the stored MD5 password hash (Juice Shop uses raw unsalted MD5 — `security.hash()` in `lib/insecurity.js`).

## Impact
- Anyone in possession of the token (XSS exfiltration, log exposure, proxy capture, device compromise) obtains the user's password hash.
- Unsalted MD5 is crackable at >100 billion hashes/second on commodity GPUs. Weak/reused passwords fall in seconds.
- Compounded by lack of `exp` claim (see `no-jwt-exp-claim` finding): the leaked hash remains valid as long as the password is unchanged, which is unbounded.

## Remediation
- Server-side: never embed the password hash (or any sensitive stored credential material) in a JWT or any client-returned object. Serialize the user object with an explicit allowlist — `id`, `email`, `role`, `username` only.
- Upgrade the password hashing algorithm from MD5 to bcrypt/argon2id regardless of this finding.

## References
- OWASP ASVS 6.2.3 — sensitive data in tokens
- CWE-522: Insufficiently Protected Credentials
- CWE-200: Information Exposure

