# ============================================================
# File: tools/scripts/finalize_vector_00.py
# Veritas Engine — Finalize test vector 00_minimal_verified (v1)
#
# What it does:
# - Writes canonical JSON for evidence.json and manifest.json
# - Creates optional provenance + artifacts for realism (small deterministic content)
# - Computes deterministic file hashes and updates manifest.files
# - Computes bundle_id from canonical manifest bytes
# - Produces signatures (Ed25519) over canonical bytes of manifest.json and evidence.json
# - Writes expected/verification_result.json for VERIFIED status
#
# Determinism:
# - Provide --seed (32 bytes hex) to make signatures reproducible.
# - Without --seed, a random key will be generated and the vector will NOT be stable across machines.
#
# Signature format:
# - "veritas-ed25519-v1" + base64(signature)
# Public key file written as OpenSSH ssh-ed25519 line:
# - test_vectors/keys/test_signer_ed25519.pub
# ============================================================

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.scripts.canon_json import canon_bytes, write_canon_json_file, load_json_file, dumps_canon

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


EXCLUDE_DIRS = {"signatures", "expected"}
EXCLUDE_FILES = {"manifest.json", "hashes.sha256"}


def utc_fixed() -> str:
    # Stable fixed timestamp for vector
    return "2026-02-19T00:00:00Z"


def sha256_hex_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_hashed_files(root: Path) -> List[Path]:
    out: List[Path] = []
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(root)
        if any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        if rel.name in EXCLUDE_FILES:
            continue
        out.append(p)
    out.sort(key=lambda x: x.relative_to(root).as_posix())
    return out


def write_hashes_sha256(root: Path) -> List[Tuple[str, str]]:
    files = iter_hashed_files(root)
    lines: List[Tuple[str, str]] = []
    for fp in files:
        h = sha256_hex_file(fp).lower()
        rel = fp.relative_to(root).as_posix()
        lines.append((h, rel))
    text = "".join([f"{h} {p}\n" for (h, p) in lines])
    (root / "hashes.sha256").write_bytes(text.encode("utf-8"))
    return lines


def write_sig(path: Path, sig: bytes) -> None:
    payload = "veritas-ed25519-v1\n" + base64.b64encode(sig).decode("ascii") + "\n"
    path.write_bytes(payload.encode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--vector",
        default=str(Path("test_vectors/00_minimal_verified")),
        help="Path to the vector directory (bundle root)",
    )
    ap.add_argument(
        "--seed",
        default="",
        help="32-byte hex seed for deterministic Ed25519 key (recommended). Example: 64 hex chars.",
    )
    args = ap.parse_args()

    root = Path(args.vector).resolve()
    root.mkdir(parents=True, exist_ok=True)

    # Ensure required dirs
    (root / "signatures").mkdir(parents=True, exist_ok=True)
    (root / "expected").mkdir(parents=True, exist_ok=True)
    (root / "provenance").mkdir(parents=True, exist_ok=True)
    (root / "artifacts").mkdir(parents=True, exist_ok=True)

    # Deterministic small artifact
    artifact_path = root / "artifacts" / "artifact.bin"
    artifact_path.write_bytes(b"VERITAS_VECTOR_00_MINIMAL\n")  # stable bytes

    artifact_meta_path = root / "artifacts" / "artifact.metadata.json"
    artifact_meta = {
        "schema": "artifact_metadata.v1",
        "name": "artifact.bin",
        "note": "deterministic minimal artifact for vector 00",
    }
    write_canon_json_file(str(artifact_meta_path), artifact_meta)

    # Provenance (minimal)
    origin = {"producer": "veritas-engine", "version": "0.1.0-testvector", "created_utc": utc_fixed()}
    env = {"os": "test", "architecture": "test", "note": "vector_00"}
    toolchain = {"bundle_finalizer": "tools/scripts/finalize_vector_00.py", "created_utc": utc_fixed()}

    write_canon_json_file(str(root / "provenance" / "origin.json"), origin)
    write_canon_json_file(str(root / "provenance" / "environment.json"), env)
    write_canon_json_file(str(root / "provenance" / "toolchain.json"), toolchain)

    # evidence.json (canonical)
    evidence_path = root / "evidence.json"
    evidence = {
        "schema": "integrity_evidence.v1",
        "subject": {"type": "software_binary", "name": "artifact.bin", "sha256": sha256_hex_file(artifact_path).lower()},
        "verification": {"method": "cryptographic_hash", "result": "match", "confidence": "cryptographic"},
        "timestamps": {"observed_utc": utc_fixed()},
    }
    write_canon_json_file(str(evidence_path), evidence)

    # hashes.sha256 (does NOT include manifest.json or hashes.sha256 itself)
    hash_lines = write_hashes_sha256(root)

    # manifest.json (canonical, files list mirrors hashes.sha256)
    manifest_path = root / "manifest.json"
    manifest: Dict[str, Any] = {
        "format": "integrity_evidence_bundle.v1",
        "bundle_id": "sha256:" + ("0" * 64),  # placeholder; replaced after hashing
        "created_utc": utc_fixed(),
        "hash_algorithm": "sha256",
        "files": [{"path": p, "sha256": h} for (h, p) in hash_lines],
    }

    # Compute bundle_id from canonical bytes of manifest with placeholder replaced? No:
    # We compute using manifest where bundle_id is temporarily placeholder? That would self-reference.
    # Rule: bundle_id = sha256(canonical_bytes(manifest_without_bundle_id_value_effect))
    #
    # To avoid ambiguity, v1 finalizer rule:
    # - Compute bundle_id from canonical bytes of manifest where bundle_id is set to 64 zeros
    # - Then write manifest with real bundle_id.
    #
    # This is deterministic and stable for v1 vectors.
    write_canon_json_file(str(manifest_path), manifest)
    canon_m0 = canon_bytes(load_json_file(str(manifest_path)))
    bundle_id = "sha256:" + hashlib.sha256(canon_m0).hexdigest()

    manifest["bundle_id"] = bundle_id
    write_canon_json_file(str(manifest_path), manifest)
    canon_m = canon_bytes(load_json_file(str(manifest_path)))

    # Create deterministic key (recommended) or random
    if args.seed:
        seed_hex = args.seed.strip().lower()
        if len(seed_hex) != 64:
            raise SystemExit("SEED_INVALID: must be 64 hex chars (32 bytes)")
        seed = bytes.fromhex(seed_hex)
        priv = Ed25519PrivateKey.from_private_bytes(seed)
    else:
        # Not stable across machines; warn loudly.
        priv = Ed25519PrivateKey.generate()
        print("WARN: no --seed provided; signatures/pubkey will vary across machines; vector will not be stable.")

    pub = priv.public_key()
    pub_ssh = pub.public_bytes(encoding=Encoding.OpenSSH, format=PublicFormat.OpenSSH).decode("utf-8")
    keys_pub = Path("test_vectors/keys/test_signer_ed25519.pub")
    keys_pub.parent.mkdir(parents=True, exist_ok=True)
    keys_pub.write_text(pub_ssh + " veritas-test-signer\n", encoding="utf-8")

    # Sign canonical bytes of manifest.json and evidence.json
    canon_e = canon_bytes(load_json_file(str(evidence_path)))
    sig_m = priv.sign(canon_m)
    sig_e = priv.sign(canon_e)
    write_sig(root / "signatures" / "manifest.sig", sig_m)
    write_sig(root / "signatures" / "evidence.sig", sig_e)

    # Expected verification result (VERIFIED)
    expected = {
        "schema": "verification_result.v1",
        "bundle_id": bundle_id,
        "status": "VERIFIED",
        "checks": {"structure": True, "manifest": True, "hashes": True, "signatures": True, "schema": True},
        "errors": [],
        "verified_at_utc": utc_fixed(),
    }
    write_canon_json_file(str(root / "expected" / "verification_result.json"), expected)

    print(f"FINALIZED_OK: {root}")
    print(f"BUNDLE_ID: {bundle_id}")
    print(f"PUBKEY_WROTE: {keys_pub.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
