# Veritas AI Analyzer

Downstream analysis-only plane.

Requirements:
- Must not override verifier truth
- Findings must reference evidence fields/files/hashes
- Must disclose model_id and analysis boundaries

CLI (canonical):
- `veritas-analyze analyze <analysis_input.json> --json`

Output schema:
- `spec/schemas/integrity_assessment.v1.schema.json`
