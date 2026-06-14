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

if($s -notmatch "add_argument\(\s*`"--deterministic`""){
  $pat = "add_parser\(\s*[`"' ]verify[`"' ]"
  $m = [System.Text.RegularExpressions.Regex]::Match($s,$pat)
  if(-not $m.Success){ throw "VERIFY_PARSER_NOT_FOUND: add_parser(""verify"")" }
  $start = $m.Index
  $nl = $s.IndexOf("`n",$start)
  if($nl -lt 0){ throw "NO_NEWLINE_AFTER_VERIFY_PARSER" }
  $insert = "    vp.add_argument(`"--deterministic`", action=`"store_true`", help=`"Deterministic verified_at_utc for test vectors`")`n"
  # Insert after the verify parser line. If variable name is not vp, we will adjust below.
  $s = $s.Substring(0,$nl+1) + $insert + $s.Substring($nl+1)
}

if($s -match "(\w+)\s*=\s*.*add_parser\(\s*[`"' ]verify[`"' ]"){
  $var = $Matches[1]
  $s = $s -replace "^\s*vp\.add_argument\(`"--deterministic`"", ("    " + $var + ".add_argument(`"--deterministic`"") , "Multiline")
}

if($s -notmatch "getattr\(args,\s*`"deterministic`""){
  $s = $s -replace "return verify_bundle\(Path\(args\.bundle_dir\), args\.[a-zA-Z_]+, args\.json\)", "deterministic = bool(getattr(args, `"deterministic`", False))`n    return verify_bundle(Path(args.bundle_dir), args.pubkey, args.json, deterministic)"
}

if($s -notmatch "def verify_bundle\(.*deterministic"){
  $s = [System.Text.RegularExpressions.Regex]::Replace($s, "def verify_bundle\(([^)]*)\):", "def verify_bundle($1, deterministic: bool):", 1)
}

$s = $s -replace "`"verified_at_utc`": utc_now_iso\(\),", "`"verified_at_utc`": utc_now_iso(deterministic),"

WriteUtf8 $ver $s
Write-Host "PATCH_OK: verifier supports --deterministic (fixed verified_at_utc)" -ForegroundColor Green
