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

# Add CLI flag --deterministic if missing
if($s -notmatch "--deterministic"){
  $s = $s -replace "vp\.add_argument\(`"--pubkey`".*?\)`n", "$0        vp.add_argument(`"--deterministic`", action=`"store_true`", help=`"Deterministic output timestamps for test vectors`")`n"
}

# Replace utc_now_iso() to consult a fixed timestamp when deterministic
if($s -notmatch "DETERMINISTIC_UTC"){
  $ins = @()
  $ins += "DETERMINISTIC_UTC = `\"2026-02-19T00:00:00Z`\""
  $ins += ""
  $s = $s -replace "STATUSES = \[", (($ins -join \"`n\") + \"`nSTATUSES = [\")
}

# Make build_result accept verified_at override via global flag
if($s -notmatch "def utc_now_iso\(deterministic"){
  $s = $s -replace "def utc_now_iso\(\) -> str:\s*\n\s*return datetime\.now\(timezone\.utc\)\.strftime\(`"%Y-%m-%dT%H:%M:%SZ`"\)\n", "def utc_now_iso(deterministic: bool) -> str:`n    if deterministic:`n        return DETERMINISTIC_UTC`n    return datetime.now(timezone.utc).strftime(`"%Y-%m-%dT%H:%M:%SZ`")`n"
}

# Thread args.deterministic into build_result call site by adding a local variable in main
if($s -notmatch "det = bool\(args\.deterministic\)"){
  $s = $s -replace "if args\.cmd != \"verify\":\s*\n\s*raise SystemExit\(2\)\n", "$0`n    det = bool(getattr(args, `\"deterministic`\", False))`n"
}

# Patch build_result to call utc_now_iso(det)
if($s -match "def build_result"){
  $s = $s -replace "`"verified_at_utc`": utc_now_iso\(\),", "`"verified_at_utc`": utc_now_iso(det),"
}

WriteUtf8 $ver $s
Write-Host "PATCH_OK: verifier --deterministic supported (fixed verified_at_utc)" -ForegroundColor Green
