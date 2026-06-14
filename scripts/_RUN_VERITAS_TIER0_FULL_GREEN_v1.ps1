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

function Run-And-RequirerSingleGreen([string]$PSExe,[string]$RunnerPath,[string]$RepoRoot,[string]$Label){
  if(-not (Test-Path -LiteralPath $RunnerPath -PathType Leaf)){ Die ("MISSING_RUNNER_" + $Label + ": " + $RunnerPath) }
  ParseGatePs1 -Path $RunnerPath
  $out = @(& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RunnerPath -RepoRoot $RepoRoot)
  $code = $LASTEXITCODE
  if($code -ne 0){ Die ("BAD_EXITCODE_" + $Label + ": " + $code) }
  $nonEmpty = @($out | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })
  if($nonEmpty.Count -ne 1){ Die ("STDOUT_NOISE_" + $Label + ": " + $nonEmpty.Count) }
  $line = $nonEmpty[0].ToString().Trim()
  if($line -ne "FULL_GREEN_OK"){ Die ("BAD_OUTPUT_" + $Label + ": " + $line) }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source

$r1 = Join-Path $RepoRoot "scripts\_RUN_veritas_all_selftests_v1.ps1"
$r2 = Join-Path $RepoRoot "scripts\_RUN_veritas_all_selftests_with_receipts_v1.ps1"
$r3 = Join-Path $RepoRoot "scripts\_RUN_veritas_negative_suite_v1.ps1"

Run-And-RequirerSingleGreen -PSExe $PSExe -RunnerPath $r1 -RepoRoot $RepoRoot -Label "ALL_SELFTESTS"
Run-And-RequirerSingleGreen -PSExe $PSExe -RunnerPath $r2 -RepoRoot $RepoRoot -Label "ALL_SELFTESTS_WITH_RECEIPTS"
Run-And-RequirerSingleGreen -PSExe $PSExe -RunnerPath $r3 -RepoRoot $RepoRoot -Label "NEGATIVE_SUITE"

Write-Host "VERITAS_TIER0_FULL_GREEN_OK" -ForegroundColor Green
