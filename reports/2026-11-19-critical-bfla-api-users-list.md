# Function-level access control missing on /api/Users — full user directory + admin emails readable by any customer

- **Severity:** critical
- **Date (UTC):** 2026-11-19

## Details

## Summary
`GET /api/Users` (list, no id) is reachable with any authenticated customer JWT and returns the complete user directory — **27 records including 9 admin accounts** with emails, roles, `deluxeToken` values, and `lastLoginIp`. The endpoint has no role check at the controller; `express-jwt` authentication is treated as authorization.

## Steps to reproduce
1. Register the throwaway test user (or any customer).
2. Send:
   ```http
   GET /api/Users HTTP/1.1
   Host: localhost:3000
   Authorization: Bearer <customer-jwt>
   ```
3. Response: 200 OK with the full users table.

## Evidence
Request fired with customer token (`data.id=26, role=customer, bid=7`):
```http
GET /api/Users HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer-jwt>
```

Response (200 OK, 7500 bytes, 27 records — admins extracted):
```json
[
  {"id":1,  "email":"admin@juice-sh.op",              "role":"admin"},
  {"id":4,  "email":"bjoern.kimminich@gmail.com",     "role":"admin", "username":"bkimminich"},
  {"id":6,  "email":"support@juice-sh.op",            "role":"admin"},
  {"id":9,  "email":"J12934@juice-sh.op",             "role":"admin"},
  {"id":10, "email":"wurstbrot@juice-sh.op",          "role":"admin", "username":"wurstbrot"},
  {"id":12, "email":"bjoern@juice-sh.op",             "role":"admin"},
  {"id":22, "email":"testing@juice-sh.op",            "role":"admin"},
  {"id":23, "email":"cloud-admin@juice-sh.op",        "role":"admin"},
  {"id":15, "email":"accountant@juice-sh.op",         "role":"accounting"}
]
```

Also exposed per record: `deluxeToken` (premium-tier auth bearer for `deluxe`-role users), `lastLoginIp`, `isActive`, `createdAt`, `updatedAt`, `profileImage`.

## Impact
Chains to full compromise:

1. **Target enumeration** — adversary now knows every admin account's exact email. No guessing.
2. **Chains with the security-question disclosure finding** (`2026-11-18-high-security-question-disclosure.md`) — admin emails + public `/rest/user/security-question?email=` endpoint = enumerate recovery questions for all 9 admin accounts, brute-force the answers, use the reset flow for account takeover.
3. **Chains with the JWT `alg:none` finding** (`2026-11-18-critical-jwt-alg-none-accepted.md`) — once an adversary knows `id=1` is `admin`, they can forge `{"alg":"none"}` tokens with `data.id=1, role=admin` and skip the reset step entirely.
4. **Chains with the /api/Users/{id} IDOR** (`2026-11-19-high-idor-api-users.md`) — admin record directly fetchable by numeric id for schema-level enumeration.
5. **`deluxeToken` leak** — opaque token for premium-tier features; its re-use value on `/rest/deluxe-membership` or similar endpoints is not probed here but should be assumed usable until proven otherwise.
6. **PCI / privacy** — admin email addresses, user account lifecycle timestamps, and last-login IPs leak to any customer who can register.

This is Broken Function Level Authorization (BFLA) — a separate class of bug from the three object-level IDORs already filed.

## Remediation
- Add a role check to the `/api/Users` list controller (and every other admin-list endpoint under `/api/*`): deny-by-default unless `req.user.data.role === 'admin'`.
- Prefer an allow-list of models exposed by `finale` / `express-restify-mongoose`-style auto-CRUD generators; do not expose the full user model via automatic REST serialization.
- Audit every `/api/<Model>` route and add BFLA tests to the CI test suite.

## References
- OWASP API Top 10 2023 — API5:2023 Broken Function Level Authorization
- CWE-285: Improper Authorization
- CWE-863: Incorrect Authorization
- Related chain: `2026-11-18-critical-jwt-alg-none-accepted.md` · `2026-11-18-high-security-question-disclosure.md` · `2026-11-19-high-idor-api-users.md`
