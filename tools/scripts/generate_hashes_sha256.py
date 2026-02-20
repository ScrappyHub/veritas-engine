# ============================================================
# File: tools/scripts/generate_hashes_sha256.py
# Veritas Engine — Deterministic hashes.sha256 generator (v1)
#
# Policy (v1):
# - hashes.sha256 covers the same file set as manifest.json "files[]"
# - DO NOT include: manifest.json, signatures/*, expected/* (test harness), .gitignore, etc.
# - Paths normalized to "/" and lexicographically sorted by path.
# ============================================================

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
from typing import Iterable, List, Tuple


EXCLUDE_DIRS = {"signatures", "expected", ".git", ".github", "__pycache__"}
EXCLUDE_FILES = {"manifest.json", "hashes.sha256"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_rel(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    return rel


def iter_files(root: Path) -> List[Path]:
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


def build_hash_lines(root: Path) -> List[Tuple[str, str]]:
    files = iter_files(root)
    lines: List[Tuple[str, str]] = []
    for fp in files:
        h = sha256_file(fp)
        lines.append((h, norm_rel(fp, root)))
    # Already sorted by path due to iter_files
    return lines


def write_hashes_sha256(root: Path, out_path: Path) -> None:
    lines = build_hash_lines(root)
    text = "".join([f"{h} {p}\n" for (h, p) in lines])
    out_path.write_bytes(text.encode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle_path", help="Path to bundle root")
    args = ap.parse_args()

    root = Path(args.bundle_path).resolve()
    out_path = root / "hashes.sha256"
    write_hashes_sha256(root, out_path)
    print(f"WROTE: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
