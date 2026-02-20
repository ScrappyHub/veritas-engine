# Veritas Reference Verifier

Truth plane component.

Requirements:
- Deterministic
- Non-AI
- Offline
- No bundle mutation
- Must match `spec/reference_verifier_toolchain.v1.md`
- Must pass `test_vectors/` exactly

CLI (canonical):
- `veritas-verify verify <bundle_path> --json`

Output schema:
- `spec/schemas/verification_result.v1.schema.json`
