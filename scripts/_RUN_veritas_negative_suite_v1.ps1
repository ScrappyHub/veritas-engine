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

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  [System.IO.File]::WriteAllText($Path,$t,(New-Object System.Text.UTF8Encoding($false)))
}

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
$Verifier   = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"
$ReceiptOut = Join-Path $RepoRoot "proofs\receipts\veritas.ndjson"
$ActualDir  = Join-Path $env:TEMP "veritas_negative_actual"
if(-not (Test-Path -LiteralPath $Verifier -PathType Leaf)){ Die ("MISSING_VERIFIER: " + $Verifier) }
if(-not (Test-Path -LiteralPath $ActualDir -PathType Container)){ New-Item -ItemType Directory -Force -Path $ActualDir | Out-Null }

$cases = @(
  [pscustomobject]@{ Name = "01_tampered_file";  Rel = "test_vectors\negative\01_tampered_file";  ExpectStatus = "FILE_HASH_MISMATCH";     ExpectErrorPrefix = "FILE_HASH_BAD:" },
  [pscustomobject]@{ Name = "02_missing_file";   Rel = "test_vectors\negative\02_missing_file";   ExpectStatus = "FILE_HASH_MISMATCH";     ExpectErrorPrefix = "MISSING_HASHED_FILE:" },
  [pscustomobject]@{ Name = "03_missing_manifest"; Rel = "test_vectors\negative\03_missing_manifest"; ExpectStatus = "STRUCTURE_INVALID"; ExpectErrorPrefix = "STRUCTURE_MISSING:" }
)

$PSDummy = $null
foreach($case in $cases){
  $bundlePath = Join-Path $RepoRoot $case.Rel
  if(-not (Test-Path -LiteralPath $bundlePath -PathType Container)){ Die ("MISSING_CASE_DIR: " + $bundlePath) }
  $lines = @(& python $Verifier verify $bundlePath --json --deterministic)
  $code = $LASTEXITCODE
  if(($code -ne 0) -and ($code -ne 1)){ Die ("BAD_EXITCODE_" + $case.Name + ": " + $code) }
  $nonEmpty = @($lines | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })
  if($nonEmpty.Count -ne 1){ Die ("STDOUT_NOISE_" + $case.Name + ": " + $nonEmpty.Count) }
  $jsonText = $nonEmpty[0].ToString().Trim()
  if(-not $jsonText.StartsWith("{")){ Die ("NOT_JSON_OBJECT_" + $case.Name) }
  $actualPath = Join-Path $ActualDir ($case.Name + ".json")
  WriteUtf8NoBomLf -Path $actualPath -Text $jsonText
  $obj = $jsonText | ConvertFrom-Json
  if($obj.status -ne $case.ExpectStatus){ Die ("BAD_STATUS_" + $case.Name + ": " + [string]$obj.status) }
  if($null -eq $obj.errors -or @($obj.errors).Count -lt 1){ Die ("NO_ERRORS_" + $case.Name) }
  $firstErr = [string]@($obj.errors)[0]
  if(-not $firstErr.StartsWith($case.ExpectErrorPrefix)){ Die ("BAD_ERROR_PREFIX_" + $case.Name + ": " + $firstErr) }
  $receiptLine = New-VeritasReceiptLine -RepoRoot $RepoRoot -RunnerRel "scripts\_RUN_veritas_negative_suite_v1.ps1" -VerifierRel "verifier\cli\veritas_verify.py" -VectorRel $case.Rel -ExitCode $code -Result "PASS" -StdoutText $jsonText -ExpectedPath $actualPath -ActualPath $actualPath -ReceiptPath $ReceiptOut
  Append-VeritasReceipt -ReceiptPath $ReceiptOut -Line $receiptLine
}

Write-Host "FULL_GREEN_OK" -ForegroundColor Green
