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

if($s -notmatch "deterministic\s*=\s*bool\(getattr\(args,\s*`"deterministic`""){
  $needle = "args = ap.parse_args()"
  $k = $s.IndexOf($needle)
  if($k -lt 0){ throw "NEEDLE_NOT_FOUND: " + $needle }
  $lineEnd = $s.IndexOf("`n",$k)
  if($lineEnd -lt 0){ throw "NO_NEWLINE_AFTER_ARGS_PARSE" }
  $ins = "    deterministic = bool(getattr(args, `"deterministic`", False))`n"
  $s = $s.Substring(0,$lineEnd+1) + $ins + $s.Substring($lineEnd+1)
}

WriteUtf8 $ver $s
Write-Host "PATCH_OK: deterministic defined in main() after parse_args()" -ForegroundColor Green
