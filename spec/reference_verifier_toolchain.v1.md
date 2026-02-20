# Reference Verifier Toolchain Spec v1

## Principle
Cryptographic verification establishes truth.
AI is downstream-only and may not override verifier truth.

## Input
A filesystem path to an Integrity Evidence Bundle (IEB).

## Deterministic Pipeline Order
1) Structure validation
2) Manifest canonical hash verification
3) File hash verification using hashes.sha256
4) Signature verification (Ed25519)
5) evidence.json schema validation
6) Bundle identity confirmation (`bundle_id`)

## Authoritative Results
One of:
- VERIFIED
- STRUCTURE_INVALID
- MANIFEST_HASH_MISMATCH
- FILE_HASH_MISMATCH
- INVALID_SIGNATURE
- SCHEMA_INVALID
- BUNDLE_ID_INVALID

## Output
Machine-readable JSON must conform to `verification_result.v1.schema.json`.

## Forbidden Behaviors
Verifier must never:
- Modify bundle contents
- Attempt repair or self-heal
- Fetch network resources
- Depend on AI
