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

# 1) Insert constant if missing
if($s -notmatch "DETERMINISTIC_UTC\s*="){
  $s = $s -replace "STATUSES\s*=\s*\[", ("DETERMINISTIC_UTC = '2026-02-19T00:00:00Z'`n`nSTATUSES = [")
}

# 2) Patch utc_now_iso to accept deterministic flag
if($s -notmatch "def utc_now_iso\(deterministic"){
  $s = $s -replace "def utc_now_iso\(\) -> str:\s*\n\s*return datetime\.now\(timezone\.utc\)\.strftime\(`"%Y-%m-%dT%H:%M:%SZ`"\)\s*\n", "def utc_now_iso(deterministic: bool) -> str:`n    if deterministic:`n        return DETERMINISTIC_UTC`n    return datetime.now(timezone.utc).strftime(`"%Y-%m-%dT%H:%M:%SZ`")`n"
}

# 3) Add CLI flag --deterministic to verify subcommand if missing
if($s -notmatch "add_argument\(`"--deterministic`""){
  $s = $s -replace "vp\.add_argument\(`"--pubkey`".*?\)\s*\n", "$0        vp.add_argument(`"--deterministic`", action=`"store_true`", help=`"Deterministic verified_at_utc for test vectors`")`n"
}

# 4) Thread args.deterministic into build_result by defining det in main()
if($s -notmatch "det\s*=\s*bool\(getattr\(args,\s*`"deterministic`""){
  $s = $s -replace "return verify_bundle\(Path\(args\.bundle_dir\), args\.pubkey, args\.json\)", "det = bool(getattr(args, `"deterministic`", False))`n    return verify_bundle(Path(args.bundle_dir), args.pubkey, args.json, det)"
}

# 5) Update verify_bundle signature to accept det and pass into build_result
if($s -notmatch "def verify_bundle\(.*deterministic"){
  $s = $s -replace "def verify_bundle\((.*?)\):", "def verify_bundle($1, deterministic: bool):"
}

# 6) Update build_result to call utc_now_iso(deterministic)
$s = $s -replace "`"verified_at_utc`": utc_now_iso\(\),", "`"verified_at_utc`": utc_now_iso(deterministic),"

WriteUtf8 $ver $s
Write-Host "PATCH_OK: verifier supports --deterministic (fixed verified_at_utc)" -ForegroundColor Green
