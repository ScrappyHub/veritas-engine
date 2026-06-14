# Veritas Engine

AI-centered verifiable integrity infrastructure.

## Veritas - Deterministic Verification Engine

### Quick Start (Tier-0)

Run the full deterministic verification suite:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File "C:\dev\veritas-engine\scripts\_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1" `
  -RepoRoot "C:\dev\veritas-engine"
```

### Expected Output

```text
VERITAS_TIER0_FULL_GREEN_OK
```

### What This Proves

- All positive verification paths
- All negative failure cases
- Deterministic stdout behavior with no noise
- Receipt emission integrity
- Parse-gated execution of all runners

### Core Runners

```text
scripts/_RUN_veritas_all_selftests_v1.ps1
scripts/_RUN_veritas_all_selftests_with_receipts_v1.ps1
scripts/_RUN_veritas_negative_suite_v1.ps1
scripts/_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1
```

### Negative Coverage

```text
test_vectors/negative/01_tampered_file
test_vectors/negative/02_missing_file
test_vectors/negative/03_missing_manifest
```

### Receipts

```text
proofs/receipts/veritas.ndjson
```

Schema:

```text
schemas/veritas.receipt.v1.json
```

### Determinism Contract

- UTF-8 no BOM, LF line endings
- No interactive input
- Parse-gated scripts only
- Stable success tokens
- Append-only receipt ledger
