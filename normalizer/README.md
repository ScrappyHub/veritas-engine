# Veritas Normalizer

Deterministic bridge:
(IEB + verification_result) → analysis_input.v1.json

Requirements:
- Deterministic ordering
- Offline
- No mutation
- Stable output bytes for identical input

CLI (canonical):
- `veritas-normalize normalize <bundle_path> <verification_result.json> --json`

Output schema:
- `spec/schemas/analysis_input.v1.schema.json`
