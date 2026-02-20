# Deterministic Test Vectors

This directory provides deterministic convergence vectors for:
- Reference verifier (authoritative truth plane)
- Normalizer (deterministic bridge)
- Analyzer (downstream-only regression)

## Rules
- Verifier output must match `expected/verification_result.json` exactly.
- Analyzer uses regression assertions (range-based where needed) and must never override verifier truth.
- Vectors must remain offline-capable and self-contained.

## Vectors
- `00_minimal_verified/` — minimal valid VERIFIED bundle
- Additional vectors to be added: hash mismatch, invalid signature, structure invalid, schema invalid, suspicious-but-verified, etc.
