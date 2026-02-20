# Hash & Identity Rules v1

- Hash algorithm: SHA-256
- `bundle_id = sha256(canonical_bytes(manifest.json))`
- Every hashed file must appear in both:
  - `manifest.json` files[]
  - `hashes.sha256`

Any mismatch is a verification failure.
