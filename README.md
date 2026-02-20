# Veritas Engine
AI-Centered Verifiable Integrity Infrastructure

Veritas Engine is an integrity verification and analysis infrastructure designed to enable independent validation of software, digital artifacts, and integrity claims.

## Core Law (Non-Negotiable)
**Cryptographic verification establishes truth.**
**AI performs analysis strictly downstream of verified truth.**
AI must never mutate evidence bundles or override verifier results.

## What Veritas Engine Produces
1) **Deterministic Verification Results** (non-AI, independently reproducible)
2) **AI Integrity Assessments** (analysis-only, evidence-linked, independently checkable)

## Repository Planes
### Plane A — Deterministic Verification Plane (Truth)
- Integrity Evidence Bundle (IEB)
- Reference Verifier (non-AI)
- Deterministic `verification_result.v1.json`

### Plane B — AI Integrity Analysis Plane (Interpretation)
- Deterministic Normalizer produces `analysis_input.v1.json`
- AI Analyzer produces `integrity_assessment.v1.json`
- Findings must cite evidence fields/files/hashes
- AI cannot claim VERIFIED if verifier is not VERIFIED

## Directory Layout
- `spec/` — Canonical specifications + schemas (authoritative)
- `verifier/` — Reference verifier (deterministic, non-AI, offline)
- `normalizer/` — Deterministic bridge: bundle+verifier → analysis_input
- `analyzer/` — AI analysis engine (downstream-only)
- `test_vectors/` — Deterministic convergence vectors + expected outputs
- `tools/` — Optional helper scripts (canonical JSON, signing, vector runner)

## Quick Start (Conceptual)
1) Verify a bundle:
   - `veritas-verify verify <bundle_path> --json > verification_result.json`
2) Normalize for AI:
   - `veritas-normalize normalize <bundle_path> <verification_result.json> --json > analysis_input.json`
3) Analyze:
   - `veritas-analyze analyze <analysis_input.json> --json > integrity_assessment.json`

## Status
This repository is a canonical v1 scaffold. Implementations must conform to:
- Integrity Evidence Bundle v1
- Reference Verifier Toolchain Spec v1
- Architecture Spec v1

See `spec/` and `test_vectors/`.
