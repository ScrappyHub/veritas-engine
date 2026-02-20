# Canonical JSON Rules v1

All canonical JSON bytes must be:
- UTF-8 without BOM
- LF line endings
- No trailing whitespace
- No pretty-printing (no insignificant whitespace)
- Object keys sorted lexicographically (ascending)
- Arrays kept in defined deterministic order (do not auto-sort unless spec says so)
- Numbers encoded deterministically (avoid floating ambiguity; prefer strings if needed)
- Stable escaping per JSON standard

These rules exist solely to ensure stable hashing and reproducible verification.
