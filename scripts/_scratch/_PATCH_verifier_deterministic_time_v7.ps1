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

if($s -notmatch "def build_result\([^\)]*deterministic"){
  $pat = "def build_result\(([^)]*)\)\s*->"
  $rx  = New-Object System.Text.RegularExpressions.Regex($pat)
  $count = 0
  $s = $rx.Replace($s, { param($m)
    $script:count++
    if($script:count -ne 1){ return $m.Value }
    $args = $m.Groups[1].Value
    if($args -match "deterministic"){ return $m.Value }
    return ("def build_result(" + $args + ", deterministic: bool) ->")
  })
}

if($s -notmatch "build_result\(bundle_id,[^\)]*deterministic"){
  $rx2 = New-Object System.Text.RegularExpressions.Regex("build_result\(\s*bundle_id\s*,\s*([^,]+)\s*,\s*checks\s*,\s*errors\s*\)")
  $s = $rx2.Replace($s, { param($m) "build_result(bundle_id, " + $m.Groups[1].Value + ", checks, errors, deterministic)" })
}

WriteUtf8 $ver $s
Write-Host "PATCH_OK: build_result takes deterministic + callsites pass it" -ForegroundColor Green
