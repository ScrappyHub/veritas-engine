# ============================================================
# File: verifier/cli/veritas_verify.py
# Veritas Engine — Minimal Reference Verifier (v1)
#
# Deterministic, offline, non-AI, no bundle mutation.
# Signature format (implementation-defined, v1):
#   signatures/manifest.sig and signatures/evidence.sig:
#     line1: "veritas-ed25519-v1"
#     line2: base64(signature over canonical bytes of the JSON file)
#
# Public key input:
#   --pubkey <path> to an OpenSSH "ssh-ed25519 AAAA..." public key line.
# ============================================================

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.scripts.canon_json import load_json_file, dumps_canon, canon_bytes

try:
    from cryptography.hazmat.primitives.serialization import load_ssh_public_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:  # pragma: no cover
    load_ssh_public_key = None
    Ed25519PublicKey = None


STATUSES = [
    "VERIFIED",
    "STRUCTURE_INVALID",
    "MANIFEST_HASH_MISMATCH",
    "FILE_HASH_MISMATCH",
    "INVALID_SIGNATURE",
    "SCHEMA_INVALID",
    "BUNDLE_ID_INVALID",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_hex_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text_utf8(path: Path) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def parse_hashes_file(path: Path) -> List[Tuple[str, str]]:
    # returns [(sha256hex, relpath)]
    lines = read_text_utf8(path).splitlines()
    out: List[Tuple[str, str]] = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split(" ", 1)
        if len(parts) != 2:
            raise ValueError(f"bad hashes.sha256 line: {ln!r}")
        h, p = parts[0].strip(), parts[1].strip()
        out.append((h.lower(), p.replace("\\", "/")))
    out.sort(key=lambda x: x[1])
    return out


def load_pubkey_ssh(path: Path):
    if load_ssh_public_key is None:
        raise RuntimeError("cryptography is required for signature verification")
    line = path.read_text(encoding="utf-8").strip()
    key = load_ssh_public_key(line.encode("utf-8"))
    return key


def read_sig_file(path: Path) -> bytes:
    txt = read_text_utf8(path).splitlines()
    if len(txt) < 2:
        raise ValueError(f"bad signature file (need 2 lines): {path}")
    if txt[0].strip() != "veritas-ed25519-v1":
        raise ValueError(f"bad signature header: {txt[0]!r}")
    sig_b64 = txt[1].strip()
    return base64.b64decode(sig_b64)


def verify_sig_ed25519(pubkey, message: bytes, sig: bytes) -> None:
    # cryptography returns Ed25519PublicKey-like
    pubkey.verify(sig, message)


def schema_check_evidence(obj: Any) -> bool:
    # Minimal schema check aligned to spec: must contain required fields.
    if not isinstance(obj, dict):
        return False
    for k in ("schema", "subject", "verification", "timestamps"):
        if k not in obj:
            return False
    if obj.get("schema") != "integrity_evidence.v1":
        return False
    subj = obj.get("subject")
    if not isinstance(subj, dict):
        return False
    for k in ("type", "name", "sha256"):
        if k not in subj:
            return False
    return True


def build_result(bundle_id: str, status: str, checks: Dict[str, bool], errors: List[str]) -> Dict[str, Any]:
    return {
        "schema": "verification_result.v1",
        "bundle_id": bundle_id,
        "status": status,
        "checks": checks,
        "errors": errors,
        "verified_at_utc": utc_now_iso(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    vp = sub.add_parser("verify")
    vp.add_argument("bundle_path")
    vp.add_argument("--json", action="store_true", help="Emit JSON only")
    vp.add_argument(
        "--pubkey",
        default=str(Path("test_vectors/keys/test_signer_ed25519.pub")),
        help="OpenSSH ssh-ed25519 public key line file path",
    )

    args = ap.parse_args()
    if args.cmd != "verify":
        raise SystemExit(2)

    root = Path(args.bundle_path).resolve()

    checks = {"structure": False, "manifest": False, "hashes": False, "signatures": False, "schema": False}
    errors: List[str] = []

    # Step 1: Structure validation
    manifest_path = root / "manifest.json"
    evidence_path = root / "evidence.json"
    hashes_path = root / "hashes.sha256"
    sig_dir = root / "signatures"
    sig_manifest = sig_dir / "manifest.sig"
    sig_evidence = sig_dir / "evidence.sig"

    required = [manifest_path, evidence_path, hashes_path, sig_dir, sig_manifest, sig_evidence]
    missing = []
    for p in required:
        if p == sig_dir:
            if not p.is_dir():
                missing.append(str(p))
        else:
            if not p.is_file():
                missing.append(str(p))
    if missing:
        bundle_id = "sha256:" + ("0" * 64)
        errors.append("STRUCTURE_MISSING: " + "; ".join(missing))
        out = build_result(bundle_id, "STRUCTURE_INVALID", checks, errors)
        print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 1
    checks["structure"] = True

    # Load JSONs
    try:
        manifest = load_json_file(str(manifest_path))
    except Exception as e:
        bundle_id = "sha256:" + ("0" * 64)
        errors.append(f"MANIFEST_PARSE_FAIL: {e}")
        out = build_result(bundle_id, "STRUCTURE_INVALID", checks, errors)
        print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 1

    # Step 2: Canonical manifest hash verification + bundle_id
    try:
        canon_m = canon_bytes(manifest)
        computed_bundle_id = "sha256:" + sha256_hex_bytes(canon_m)
        declared_bundle_id = str(manifest.get("bundle_id", ""))
        if declared_bundle_id != computed_bundle_id:
            errors.append(f"BUNDLE_ID_MISMATCH: declared={declared_bundle_id} computed={computed_bundle_id}")
            # We still continue to produce a stable output referencing computed id for diagnosis.
            bundle_id = computed_bundle_id
            out = build_result(bundle_id, "BUNDLE_ID_INVALID", checks, errors)
            print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
            return 1
        checks["manifest"] = True
        bundle_id = computed_bundle_id
    except Exception as e:
        bundle_id = "sha256:" + ("0" * 64)
        errors.append(f"MANIFEST_HASH_FAIL: {e}")
        out = build_result(bundle_id, "MANIFEST_HASH_MISMATCH", checks, errors)
        print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 1

    # Step 3: File hashes vs hashes.sha256 + manifest.files[]
    try:
        hashes_list = parse_hashes_file(hashes_path)
        mf_files = manifest.get("files", [])
        if not isinstance(mf_files, list):
            raise ValueError("manifest.files is not an array")
        mf_map = {}
        for it in mf_files:
            if not isinstance(it, dict):
                raise ValueError("manifest.files contains non-object")
            p = str(it.get("path", "")).replace("\\", "/")
            h = str(it.get("sha256", "")).lower()
            mf_map[p] = h
        hs_map = {p: h for (h, p) in hashes_list}
        if set(mf_map.keys()) != set(hs_map.keys()):
            errors.append("HASH_SET_MISMATCH: manifest.files != hashes.sha256 paths")
            raise ValueError("hash set mismatch")

        # Verify each file hash
        ok = True
        for p, expected in sorted(mf_map.items(), key=lambda x: x[0]):
            fp = root / Path(p)
            if not fp.is_file():
                ok = False
                errors.append(f"MISSING_HASHED_FILE: {p}")
                continue
            actual = sha256_hex_file(fp).lower()
            if actual != expected or actual != hs_map[p]:
                ok = False
                errors.append(f"FILE_HASH_BAD: {p} expected={expected} actual={actual}")
        if not ok:
            raise ValueError("file hash mismatch")
        checks["hashes"] = True
    except Exception as e:
        if not any(err.startswith("FILE_HASH_BAD") or err.startswith("MISSING_HASHED_FILE") for err in errors):
            errors.append(f"HASHES_CHECK_FAIL: {e}")
        out = build_result(bundle_id, "FILE_HASH_MISMATCH", checks, errors)
        print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 1

    # Step 4: Signature verification (manifest + evidence)
    try:
        pubkey = load_pubkey_ssh(Path(args.pubkey))
        sig_m = read_sig_file(sig_manifest)
        sig_e = read_sig_file(sig_evidence)

        # Signatures verify canonical bytes of each JSON
        evidence = load_json_file(str(evidence_path))
        canon_e = canon_bytes(evidence)
        verify_sig_ed25519(pubkey, canon_m, sig_m)
        verify_sig_ed25519(pubkey, canon_e, sig_e)

        checks["signatures"] = True
    except Exception as e:
        errors.append(f"SIGNATURE_INVALID: {e}")
        out = build_result(bundle_id, "INVALID_SIGNATURE", checks, errors)
        print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 1

    # Step 5: evidence schema validation
    try:
        evidence = load_json_file(str(evidence_path))
        if not schema_check_evidence(evidence):
            raise ValueError("evidence.json does not match minimal schema requirements")
        checks["schema"] = True
    except Exception as e:
        errors.append(f"SCHEMA_INVALID: {e}")
        out = build_result(bundle_id, "SCHEMA_INVALID", checks, errors)
        print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 1

    out = build_result(bundle_id, "VERIFIED", checks, errors)
    print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
