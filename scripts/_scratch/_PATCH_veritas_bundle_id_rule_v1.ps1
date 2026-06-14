param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function ReadUtf8([string]$p){ return [System.IO.File]::ReadAllText($p,(New-Object System.Text.UTF8Encoding($false))) }
function WriteUtf8([string]$p,[string]$t){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $u = ($t -replace "`r`n","`n") -replace "`r","`n"
  if(-not $u.EndsWith("`n")){ $u += "`n" }
  [System.IO.File]::WriteAllText($p,$u,$enc)
}

$ver  = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"
$spec = Join-Path $RepoRoot "spec\integrity_evidence_bundle.v1.md"
if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ throw "MISSING: $ver" }
if(-not (Test-Path -LiteralPath $spec -PathType Leaf)){ throw "MISSING: $spec" }

# ------------------------------
# 1) Patch verifier imports so running by path works (sys.path injection)
# ------------------------------
$s = ReadUtf8 $ver
if($s -notmatch "sys\.path\.insert"){
  $needle = "from __future__ import annotations"
  $ix = $s.IndexOf($needle)
  if($ix -lt 0){ throw "NEEDLE_NOT_FOUND: future import" }
  $insert = @()
  $insert += $needle
  $insert += ""
  $insert += "import sys"
  $insert += "from pathlib import Path as _Path"
  $insert += "sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))"
  $insert += ""
  $s2 = $s.Substring(0,$ix) + (($insert -join "`n") + "`n") + $s.Substring($ix + $needle.Length)
  $s = $s2
}

# ------------------------------
# 2) Patch bundle_id derivation rule to zero manifest.bundle_id before hashing
# ------------------------------
$oldA = "        canon_m = canon_bytes(manifest)"
$oldB = "        computed_bundle_id = `"" + "sha256:" + "`" + sha256_hex_bytes(canon_m)"

if($s -notmatch "zero_manifest = dict\\(manifest\\)"){
  # Replace the exact computed_bundle_id assignment line to use zeroed manifest
  $s = $s -replace "computed_bundle_id\s*=\s*`"sha256:`"\s*\+\s*sha256_hex_bytes\(canon_m\)", "zero_manifest = dict(manifest)`n        zero_manifest[`"bundle_id`"] = `"sha256:`" + (`"0`" * 64)`n        canon_m0 = canon_bytes(zero_manifest)`n        computed_bundle_id = `"sha256:`" + sha256_hex_bytes(canon_m0)`n        canon_m = canon_bytes(manifest)"
}

# Sanity: ensure we now compute using canon_m0
if($s -notmatch "canon_m0"){ throw "PATCH_FAIL: did not inject canon_m0 bundle_id computation" }

WriteUtf8 $ver $s
Write-Host ("PATCH_OK: verifier updated: sys.path + bundle_id zeroing rule") -ForegroundColor Green

# ------------------------------
# 3) Patch spec to document the v1 rule
# ------------------------------
$sp = ReadUtf8 $spec
$hdr = "## Bundle Identity Rule"
$jx = $sp.IndexOf($hdr)
if($jx -lt 0){ throw "SPEC_HDR_NOT_FOUND: $hdr" }
if($sp -notmatch "after setting manifest\.bundle_id to sha256:00"){
  $rule = $hdr + "`n`n" + "v1 Canonical rule (non-self-referential):`n" + "bundle_id = sha256(canonical_bytes(manifest.json) after setting manifest.bundle_id to sha256:00..00)`n"
  $sp2 = $sp.Substring(0,$jx) + $rule + $sp.Substring($jx + $hdr.Length)
  WriteUtf8 $spec $sp2
  Write-Host "PATCH_OK: spec documented bundle_id rule (v1)" -ForegroundColor Green
} else {
  Write-Host "SPEC_OK: rule already documented" -ForegroundColor Yellow
}

Write-Host "PATCH_DONE: Veritas v1 bundle_id convergence repair complete" -ForegroundColor Green
