# Function-level access control missing on /api/Feedbacks — all users' feedback + UserId mapping readable

- **Severity:** medium
- **Date (UTC):** 2026-11-19

## Details

## Summary
`GET /api/Feedbacks` returns the global feedback table to any authenticated user, including the `UserId` field that links each comment back to the author's numeric id.

## Steps to reproduce
1. Log in as the test customer (id=26).
2. `GET /api/Feedbacks` with the customer token.
3. Response: 200 OK with all feedback rows, each row including `UserId`.

## Evidence
Response (abridged, 200 OK, 1734 bytes, 8 records):
```json
[
  {"UserId":1,  "id":1, "comment":"I love this shop! ... (***in@juice-sh.op)",  "rating":5},
  {"UserId":2,  "id":2, "comment":"Great shop! ... (***@juice-sh.op)",           "rating":4},
  {"UserId":3,  "id":3, "comment":"Nothing useful ... (***der@juice-sh.op)",     "rating":1},
  {"UserId":21, "id":4, "comment":"Please send me the juicy chatbot NFT ... \"purpose betray marriage blame crunch monitor spin slide donate sport lift clutch\" (***ereum@juice-sh.op)", "rating":1}
]
```

The anonymized author suffix (`***in@juice-sh.op`) is stripped UI-side, but the raw `UserId` field is present and resolves through `/api/Users` (the BFLA finding above) to full user records.

Of particular note: record id=4 posts what looks like a **wallet mnemonic phrase** — 12-word BIP-39-style seed — in the public-feedback body for `UserId=21` (`ethereum@juice-sh.op`). This is a Juice Shop demo artifact, but on a real engagement, surfacing seed/mnemonic strings in feedback content would be a severe compounding finding.

## Impact
- De-anonymization: feedback's displayed `***in@juice-sh.op` → `admin@juice-sh.op` once joined with `/api/Users` results.
- Behavioral profiling: rating + comment + user id trio is enough to reconstruct complaint patterns across the customer base.
- Review integrity: any authenticated user can enumerate every review and identify who posted each one — chilling effect on honest negative feedback.

Lower severity than the `/api/Users` BFLA because feedback bodies are user-authored and semi-public already; the real leak here is the `UserId` cross-reference field, which should never be returned to a non-admin.

## Remediation
- Add a role check to `/api/Feedbacks` list: admins see all; a regular customer sees only their own feedback or a sanitized public projection (comment + rating only, no `UserId`).
- Strip `UserId` from the JSON serializer for non-admin responses, or move the admin-list endpoint to `/api/admin/Feedbacks` and gate it properly.

## References
- OWASP API Top 10 2023 — API5:2023 Broken Function Level Authorization
- CWE-285: Improper Authorization
- Related: `2026-11-19-critical-bfla-api-users-list.md`
