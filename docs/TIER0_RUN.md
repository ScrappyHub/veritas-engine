# Veritas Tier-0 Run

## Canonical final entrypoint

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File "C:\dev\veritas-engine\scripts\_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1" `
  -RepoRoot "C:\dev\veritas-engine"
```

## Expected final output

```text
VERITAS_TIER0_FULL_GREEN_OK
```

## Canonical runners

```text
scripts/_RUN_veritas_all_selftests_v1.ps1
scripts/_RUN_veritas_all_selftests_with_receipts_v1.ps1
scripts/_RUN_veritas_negative_suite_v1.ps1
scripts/_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1
```

## Canonical negative vectors

```text
test_vectors/negative/01_tampered_file
test_vectors/negative/02_missing_file
test_vectors/negative/03_missing_manifest
```

## Receipt ledger

```text
proofs/receipts/veritas.ndjson
```
