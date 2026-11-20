# Business logic — negative quantity accepted on /api/BasketItems (price inversion)

- **Severity:** high
- **Date (UTC):** 2026-11-19

## Details

## Summary
POST /api/BasketItems accepts `quantity: -5` and persists the row (id=10, 200 OK). A negative quantity in a cart line inverts the line total at checkout — the basket subtracts product price × 5 from the order instead of adding it, enabling arbitrary discount or free-order fraud.

## Steps to reproduce
1. Register / authenticate as a customer (bid=7, id=26).
2. Fire POST /api/BasketItems with JSON body `{"BasketId":7,"ProductId":1,"quantity":-5}` and the customer JWT.
3. Server responds 200 OK and persists the row with `quantity: -5`.

## Evidence
Request:
```http
POST /api/BasketItems HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer-jwt bid=7>
Content-Type: application/json
Content-Length: 42

{"BasketId":7,"ProductId":1,"quantity":-5}
```

Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"status":"success","data":{"id":10,"ProductId":1,"BasketId":7,"quantity":-5,"updatedAt":"2026-11-19T04:49:09.692Z","createdAt":"2026-11-19T04:49:09.692Z"}}
```

## Impact
Financial loss via order-total inversion. An attacker drops a negative-quantity item into their own basket so the basket total is reduced below the true cost of the other items (or even becomes negative), paying far less than the goods are worth. Chains with the `/api/BasketItems/{id}` IDOR already filed — a negative-quantity row can be added to a different user's basket too, breaking their checkout or triggering refund flows.

## Remediation
Enforce `quantity >= 1` as a server-side validation at the BasketItem controller / model layer (Sequelize `validate: { min: 1 }`). Reject non-integer and non-positive values with 400 before the row is persisted. Re-validate on PUT/PATCH, not only on POST. Do not rely on frontend quantity-selector constraints — the raw API bypasses them.

## References
- OWASP API Top 10 2023 — API6:2023 Unrestricted Access to Sensitive Business Flows
- CWE-840: Business Logic Errors
- CWE-20: Improper Input Validation
