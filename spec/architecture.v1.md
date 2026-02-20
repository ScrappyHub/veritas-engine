# Architecture Spec v1

## Two-Plane Model

### Plane A — Deterministic Verification Plane (Truth)
Inputs: Integrity Evidence Bundle (IEB)
Component: Reference Verifier (non-AI)
Output: deterministic verification_result.v1.json

### Plane B — AI Integrity Analysis Plane (Interpretation)
Inputs: analysis_input.v1.json (deterministic) + optional policy pack
Component: AI Analyzer
Output: integrity_assessment.v1.json (analysis-only, evidence-linked)

## Hard Gate
If verifier status != VERIFIED, AI must not claim VERIFIED and must surface that gate in output.

## Deterministic Normalizer
A deterministic component that transforms:
(IEB + verification_result) → analysis_input.v1.json
to remove ambiguity and provide stable ordering for AI.

## Independent Validation
All verifier outputs must be independently reproducible.
All AI outputs must cite evidence references (file+field+hash context).
Optional: sign AI assessment as a separate verifiable artifact.

## Test Vectors
A deterministic `test_vectors/` suite is mandatory for convergence.
Verifier: exact expected outputs
Analyzer: regression expectations that never override verifier truth
