# Checkout accepts empty body — no address, payment, or delivery method required

- **Severity:** high
- **Date (UTC):** 2026-11-19

## Details

## Summary
POST /rest/basket/{id}/checkout accepts an empty JSON body `{}` and issues an order with `addressId=null`, `paymentId=null`, no delivery method, and no server-side validation that the basket is sane. Chained with the negative-quantity finding (2026-11-19-high-business-logic-negative-quantity-basketitem), this lets an authenticated user place a persisted order with an inverted (negative) total — a direct path to financial loss / credit abuse depending on downstream payout logic.

## Steps to reproduce
1. Authenticate as a customer (test user id=26, bid=7).
2. Insert a basket line with `quantity=-99` via POST /api/BasketItems (see linked finding).
3. POST /rest/basket/7/checkout with body `{}` — no address id, no payment id, no delivery method.
4. Observe 200 OK with `orderConfirmation`.
5. GET /rest/track-order/{orderConfirmation} — confirms order is persisted with `totalPrice=-197.01`, `addressId=null`, `paymentId=null`.

## Evidence

Checkout request:
```http
POST /rest/basket/7/checkout HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer JWT>
Content-Type: application/json
Content-Length: 2

{}
```
Response:
```json
{"orderConfirmation":"cdd3-be220aa79a83aa53"}
```

Order read-back:
```http
GET /rest/track-order/cdd3-be220aa79a83aa53 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <customer JWT>
```
Response (200 OK):
```json
{"status":"success","data":[{"promotionalAmount":"0","paymentId":null,"addressId":null,
"orderId":"cdd3-be220aa79a83aa53","delivered":false,"totalPrice":-197.01,
"products":[{"quantity":-99,"id":1,"name":"Apple Juice (1000ml)","price":1.99,"total":-197.01}],
"bonus":0,"deliveryPrice":0,"eta":"5"}]}
```

## Impact
- **Business-logic bypass.** Required fields (shipping address, payment method, delivery option) are not enforced at the server. An order is persisted without any of them.
- **Chain impact.** Combined with CWE-20 on BasketItems quantity, the persisted order has `totalPrice=-197.01`. If a downstream settlement / refund / loyalty-points process trusts `totalPrice`, this becomes direct financial loss or illicit credit.
- **State-machine violation.** The checkout → fulfillment pipeline expects address + payment selection as prerequisite steps. Skipping them means the normal order lifecycle (payment capture → ship → deliver) is broken from inception. OWASP API6:2023 Unrestricted Access to Sensitive Business Flows.

## Remediation
- Validate at the checkout controller that `addressId`, `paymentId`, and `deliveryMethodId` are present and reference records owned by the authenticated user.
- Reject checkout if basket contains any line with `quantity < 1` or `total < 0`.
- Enforce order totalPrice ≥ 0 as a database CHECK constraint on the Orders model.
- Treat the full order workflow as a state machine: address selected → payment selected → delivery selected → checkout. Reject checkout attempts that skip any state.

## References
- OWASP API Security Top 10 2023 — API6: Unrestricted Access to Sensitive Business Flows
- CWE-840: Business Logic Errors
- CWE-20: Improper Input Validation
- Related finding: reports/2026-11-19-high-business-logic-negative-quantity-basketitem.md

