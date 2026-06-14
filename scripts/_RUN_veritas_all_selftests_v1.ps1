param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

function ParseGatePs1([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $tok=$null; $err=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and $err.Count -gt 0){
    $e=$err[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$v1 = Join-Path $RepoRoot "scripts\_RUN_veritas_selftest_deterministic_v1.ps1"
$v2 = Join-Path $RepoRoot "scripts\_RUN_veritas_selftest_deterministic_v2_no_noise.ps1"

foreach($p in @($v1,$v2)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("MISSING_SELFTEST: " + $p) }
  ParseGatePs1 -Path $p
}

$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source

$out1 = @(& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $v1 -RepoRoot $RepoRoot)
$n1 = @($out1 | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })
if($n1.Count -ne 1){ Die "V1_STDOUT_NOISE" }
if($n1[0].ToString().Trim() -ne "FULL_GREEN_OK"){ Die ("V1_BAD_OUTPUT: " + $n1[0]) }

$out2 = @(& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $v2 -RepoRoot $RepoRoot)
$n2 = @($out2 | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })
if($n2.Count -ne 1){ Die "V2_STDOUT_NOISE" }
if($n2[0].ToString().Trim() -ne "FULL_GREEN_OK"){ Die ("V2_BAD_OUTPUT: " + $n2[0]) }

Write-Host "FULL_GREEN_OK" -ForegroundColor Green
