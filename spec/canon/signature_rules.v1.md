# Signature Rules v1

- Signature algorithm: Ed25519
- Signed payloads (canonical bytes):
  - manifest.json → signatures/manifest.sig
  - evidence.json → signatures/evidence.sig

Signatures must be verifiable with a declared public key.
Verifier must not assume network-based key discovery.
