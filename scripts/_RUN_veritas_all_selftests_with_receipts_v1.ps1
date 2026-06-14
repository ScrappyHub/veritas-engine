param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

. (Join-Path $RepoRoot "scripts\_lib_veritas_receipts_v1.ps1")

function ParseGatePs1([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $tok=$null; $err=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and $err.Count -gt 0){ $e=$err[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message) }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$allRunner = Join-Path $RepoRoot "scripts\_RUN_veritas_all_selftests_v1.ps1"
$receiptPath = Join-Path $RepoRoot "proofs\receipts\veritas.ndjson"
$expectedPath = Join-Path $RepoRoot "test_vectors\01_file_hash_mismatch\expected\verification_result.json"
$actualPath = Join-Path $env:TEMP "veritas_actual.json"
$verifierRel = "verifier\cli\veritas_verify.py"
$runnerRel = "scripts\_RUN_veritas_all_selftests_with_receipts_v1.ps1"
$vectorRel = "test_vectors\01_file_hash_mismatch"

if(-not (Test-Path -LiteralPath $allRunner -PathType Leaf)){ Die ("MISSING_ALL_RUNNER: " + $allRunner) }
ParseGatePs1 -Path $allRunner

$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
$lines = @(& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $allRunner -RepoRoot $RepoRoot)
$code = $LASTEXITCODE
$nonEmpty = @($lines | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })
if($nonEmpty.Count -ne 1){ Die ("ALL_SELFTEST_STDOUT_NOISE: " + $nonEmpty.Count) }
$stdout = $nonEmpty[0].ToString().Trim()
if($stdout -ne "FULL_GREEN_OK"){ Die ("ALL_SELFTEST_BAD_OUTPUT: " + $stdout) }
if($code -ne 0){ Die ("ALL_SELFTEST_BAD_EXITCODE: " + $code) }

if(-not (Test-Path -LiteralPath $actualPath -PathType Leaf)){ Die ("MISSING_ACTUAL_JSON: " + $actualPath) }
if(-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)){ Die ("MISSING_EXPECTED_JSON: " + $expectedPath) }

$line = New-VeritasReceiptLine -RepoRoot $RepoRoot -RunnerRel $runnerRel -VerifierRel $verifierRel -VectorRel $vectorRel -ExitCode $code -Result "PASS" -StdoutText $stdout -ExpectedPath $expectedPath -ActualPath $actualPath -ReceiptPath $receiptPath
Append-VeritasReceipt -ReceiptPath $receiptPath -Line $line

Write-Host "FULL_GREEN_OK" -ForegroundColor Green
