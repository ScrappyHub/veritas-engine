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

$ver = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"
if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ throw "MISSING: $ver" }
$s = ReadUtf8 $ver

if($s -notmatch "DETERMINISTIC_UTC\s*="){
  $s = $s -replace "STATUSES\s*=\s*\[", ("DETERMINISTIC_UTC = '2026-02-19T00:00:00Z'`n`nSTATUSES = [")
}

if($s -notmatch "def utc_now_iso\(deterministic"){
  $s = $s -replace "def utc_now_iso\(\) -> str:\s*\n\s*return datetime\.now\(timezone\.utc\)\.strftime\(`"%Y-%m-%dT%H:%M:%SZ`"\)\s*\n", "def utc_now_iso(deterministic: bool) -> str:`n    if deterministic:`n        return DETERMINISTIC_UTC`n    return datetime.now(timezone.utc).strftime(`"%Y-%m-%dT%H:%M:%SZ`")`n"
}

if($s -notmatch "--deterministic"){
  $needle = "vp.add_argument(`"--json`", action=`"store_true`", help=`"Emit JSON only`")"
  $k = $s.IndexOf($needle)
  if($k -lt 0){ throw "NEEDLE_NOT_FOUND_JSON_LINE: " + $needle }
  $lineEnd = $s.IndexOf("`n",$k)
  if($lineEnd -lt 0){ throw "NO_NEWLINE_AFTER_JSON_LINE" }
  $insert = "    vp.add_argument(`"--deterministic`", action=`"store_true`", help=`"Deterministic verified_at_utc for test vectors`")`n"
  $s = $s.Substring(0,$lineEnd+1) + $insert + $s.Substring($lineEnd+1)
}

if($s -notmatch "getattr\(args,\s*`"deterministic`""){
  $s = $s -replace "return verify_bundle\(Path\(args\.bundle_path\), args\.pubkey, args\.json\)", "deterministic = bool(getattr(args, `"deterministic`", False))`n    return verify_bundle(Path(args.bundle_path), args.pubkey, args.json, deterministic)"
}

if($s -notmatch "def verify_bundle\([^\)]*deterministic"){
  $pat = "def verify_bundle\(([^)]*)\):"
  $rx  = New-Object System.Text.RegularExpressions.Regex($pat)
  $count = 0
  $s = $rx.Replace($s, { param($m) $script:count++; if($script:count -eq 1){ "def verify_bundle(" + $m.Groups[1].Value + ", deterministic: bool):" } else { $m.Value } })
}

$s = $s -replace "`"verified_at_utc`": utc_now_iso\(\),", "`"verified_at_utc`": utc_now_iso(deterministic),"

WriteUtf8 $ver $s
Write-Host "PATCH_OK: verifier supports --deterministic (fixed verified_at_utc)" -ForegroundColor Green
