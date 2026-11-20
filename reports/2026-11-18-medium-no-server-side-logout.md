# No server-side logout / token-revocation endpoint

- **Severity:** medium
- **Date (UTC):** 2026-11-18

## Details

## Summary
Juice Shop exposes no server-side route for logout or JWT revocation. The client's "Logout" button clears browser localStorage only. A captured token continues to authenticate against `/api/*` indefinitely after the user "logs out."

## Steps to reproduce
1. Login as `pentest-juice-shop@example.com`; capture JWT.
2. `GET /api/Users/26` with the captured bearer → 200 OK with user data.
3. `GET /rest/user/logout` with the same bearer → 500 "Unexpected path: /rest/user/logout" (endpoint does not exist; falls through Angular catch-all).
4. Re-run step 2 immediately → 200 OK, same data. Token still valid.

## Evidence
Logout attempt:
```http
GET /rest/user/logout HTTP/1.1
Host: localhost:3000
Authorization: Bearer <token>
```
Response (500 Internal Server Error):
```json
{"error":{"message":"Unexpected path: /rest/user/logout","stack":"Error: Unexpected path: /rest/user/logout\n    at D:\\Work\\juice-shop\\juice-shop_20.3.0\\build\\routes\\angular.js:18:18\n ..."}}
```
Re-fire `GET /api/Users/26` with the same token 15 seconds later: 200 OK, full user object returned.

## Impact
- No mechanism exists to invalidate a leaked / stolen token before its signing key rotates.
- Combined with the absence of an `exp` claim (see `no-jwt-exp-claim`), a captured token is a permanent bearer credential.
- Also a secondary stack-trace disclosure on 500 — filesystem path `D:\Work\juice-shop\juice-shop_20.3.0\` leaked, confirming the surface noted in the redirect-stack-trace finding.

## Remediation
- Implement a server-side revocation list (Redis set keyed by `jti`) or short `exp` + refresh-token flow.
- Add an explicit `POST /rest/user/logout` route that deletes the server-side session record (or adds the current `jti` to the revocation set).
- Gate 500-error responses to return a sanitized message; stack traces must not reach the client.

## References
- OWASP ASVS 3.3.2 — logout invalidates session
- CWE-613: Insufficient Session Expiration
- CWE-209: Information Exposure Through Error Message

