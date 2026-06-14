# Veritas Receipts

Veritas emits append-only NDJSON receipts to:

```text
proofs/receipts/veritas.ndjson
```

Each line is one canonical JSON object matching:

```text
schemas/veritas.receipt.v1.json
```

## Purpose

The receipt ledger provides deterministic, tamper-evident proof that Veritas runners executed and produced expected outputs.

Each receipt records runner path, verifier path, vector path, exit code, result, stdout SHA-256, verifier SHA-256, expected output SHA-256, actual output SHA-256, previous receipt hash, and current receipt hash.

## Append-only rule

Receipts are append-only UTF-8 no BOM LF NDJSON.

Existing receipt lines must not be edited in place.

## Hash chain rule

Each receipt contains prev_receipt_hash and receipt_hash.

The first prev_receipt_hash is all zeroes. Every later prev_receipt_hash equals the previous line receipt_hash.

## Canonical receipt producers

```text
scripts/_RUN_veritas_all_selftests_with_receipts_v1.ps1
scripts/_RUN_veritas_negative_suite_v1.ps1
scripts/_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1
```
