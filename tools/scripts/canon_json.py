# ============================================================
# File: tools/scripts/canon_json.py
# Veritas Engine — Canonical JSON utilities (v1)
# Deterministic: sorted keys, no whitespace, UTF-8, LF.
# ============================================================

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict


def _to_lf(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if not s.endswith("\n"):
        s += "\n"
    return s


def loads_json(text: str) -> Any:
    # Strict JSON parse
    return json.loads(text)


def load_json_file(path: str) -> Any:
    with open(path, "rb") as f:
        b = f.read()
    # Allow UTF-8 without BOM only; if BOM present, json.loads still works but we normalize on write.
    txt = b.decode("utf-8-sig")
    return loads_json(txt)


def dumps_canon(obj: Any) -> str:
    # Canonical JSON (v1):
    # - sort keys
    # - separators to remove whitespace
    # - ensure_ascii False (UTF-8)
    return _to_lf(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def canon_bytes(obj: Any) -> bytes:
    return dumps_canon(obj).encode("utf-8")


def write_canon_json_file(path: str, obj: Any) -> None:
    data = canon_bytes(obj)
    with open(path, "wb") as f:
        f.write(data)


def canonicalize_json_file_in_place(path: str) -> None:
    obj = load_json_file(path)
    write_canon_json_file(path, obj)
