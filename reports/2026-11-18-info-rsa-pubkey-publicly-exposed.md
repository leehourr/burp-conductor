# JWT signing public key served unauthenticated at /encryptionkeys/jwt.pub

- **Severity:** info
- **Date (UTC):** 2026-11-18

## Details

## Summary
The RS256 public key used to verify JWTs is served unauthenticated at `/encryptionkeys/jwt.pub`. On its own this is not a secret — public keys are by design distributable — but combined with the `alg:none` acceptance already filed (critical), it also enables the RS256→HS256 algorithm-confusion variant: an attacker signs a forged payload with HS256 using the PEM text as the HMAC secret, and a verifier that does not pin algorithms accepts it.

## Steps to reproduce
```
GET /encryptionkeys/jwt.pub HTTP/1.1
Host: localhost:3000
```
Returns 200 OK with `-----BEGIN RSA PUBLIC KEY----- … -----END RSA PUBLIC KEY-----` (1024-bit RSA modulus beginning `MIGJAoGBAM3CosR73CBNcJsLv5E90NsFt6qN1uziQ484gbOouL...`). Response is served from a static directory with no auth.

## Impact
Enables RS256→HS256 confusion when paired with an unpinned verifier. Independently, the key being 1024-bit RSA is below current NIST guidance (2048-bit minimum).

## Remediation
- Fix the root cause in `lib/insecurity.js`: pin algorithms (`jwt.verify(token, key, { algorithms: ['RS256'] })`). This closes both the `alg:none` and HS256-confusion variants.
- Rotate to a 2048-bit RSA (or Ed25519) key pair.
- Public key exposure itself is acceptable once the verifier is hardened.

## References
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- NIST SP 800-57 Part 1 Rev. 5 (RSA key-length guidance)

