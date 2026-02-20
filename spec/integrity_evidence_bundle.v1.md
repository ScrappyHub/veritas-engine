# Integrity Evidence Bundle (IEB) v1

## Purpose
A deterministic directory-bundle containing integrity evidence that can be independently verified (without AI) and analyzed (with AI downstream).

## Bundle Layout (Required)
- `manifest.json`
- `evidence.json`
- `hashes.sha256`
- `signatures/manifest.sig`
- `signatures/evidence.sig`

## Optional
- `provenance/`
- `artifacts/`

## Bundle Identity Rule
`bundle_id = sha256(canonical_bytes(manifest.json))`

`manifest.json` MUST include:
- `format = "integrity_evidence_bundle.v1"`
- `bundle_id = "sha256:<hex>"`
- `created_utc` (RFC3339 / ISO 8601 UTC)
- `hash_algorithm = "sha256"`
- `files[]` list containing `{ path, sha256 }` for all hashed files

## hashes.sha256
Line format:
`<hex_sha256> <relative_path>`

Ordering MUST be deterministic:
- Lexicographically by path ascending (bytewise / Unicode codepoint order).
- Paths use `/` separators.

## Signatures
Ed25519 signatures over the canonical bytes of:
- `manifest.json` → `signatures/manifest.sig`
- `evidence.json` → `signatures/evidence.sig`

Signature format is implementation-defined but must be verifiable using the corresponding Ed25519 public key and declared signing rules.

## Canonical JSON Rules
All JSON in the bundle MUST be:
- UTF-8 no BOM
- LF line endings
- Deterministic canonical serialization (see `spec/canon/canonical_json_rules.v1.md`)
