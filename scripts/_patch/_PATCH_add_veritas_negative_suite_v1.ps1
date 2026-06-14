param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ throw "EnsureDir: empty path" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$t,$enc)
}

function ParseGatePs1([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ throw ("PARSE_GATE_MISSING: " + $Path) }
  $tok=$null; $err=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and $err.Count -gt 0){
    $e=$err[0]
    throw ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$NegRoot  = Join-Path $RepoRoot "test_vectors\negative"
$SrcRoot  = Join-Path $RepoRoot "test_vectors\01_file_hash_mismatch"
$RunPath  = Join-Path $RepoRoot "scripts\_RUN_veritas_negative_suite_v1.ps1"
$ReceiptLib = Join-Path $RepoRoot "scripts\_lib_veritas_receipts_v1.ps1"

if(-not (Test-Path -LiteralPath $SrcRoot -PathType Container)){ throw ("MISSING_SOURCE_VECTOR: " + $SrcRoot) }
if(-not (Test-Path -LiteralPath $ReceiptLib -PathType Leaf)){ throw ("MISSING_RECEIPT_LIB: " + $ReceiptLib) }
EnsureDir $NegRoot

function Copy-VectorDir([string]$Src,[string]$Dst){
  if(Test-Path -LiteralPath $Dst){ Remove-Item -LiteralPath $Dst -Recurse -Force }
  Copy-Item -LiteralPath $Src -Destination $Dst -Recurse -Force
}

# 01_tampered_file
$v1 = Join-Path $NegRoot "01_tampered_file"
Copy-VectorDir -Src $SrcRoot -Dst $v1
$v1Artifact = Join-Path $v1 "artifacts\artifact.bin"
if(-not (Test-Path -LiteralPath $v1Artifact -PathType Leaf)){ throw ("MISSING_ARTIFACT: " + $v1Artifact) }
$appendEnc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::AppendAllText($v1Artifact,"NEG1",$appendEnc)

# 02_missing_file
$v2 = Join-Path $NegRoot "02_missing_file"
Copy-VectorDir -Src $SrcRoot -Dst $v2
$v2Artifact = Join-Path $v2 "artifacts\artifact.bin"
if(-not (Test-Path -LiteralPath $v2Artifact -PathType Leaf)){ throw ("MISSING_ARTIFACT: " + $v2Artifact) }
Remove-Item -LiteralPath $v2Artifact -Force

# 03_missing_manifest
$v3 = Join-Path $NegRoot "03_missing_manifest"
Copy-VectorDir -Src $SrcRoot -Dst $v3
$v3Manifest = Join-Path $v3 "manifest.json"
if(-not (Test-Path -LiteralPath $v3Manifest -PathType Leaf)){ throw ("MISSING_MANIFEST: " + $v3Manifest) }
Remove-Item -LiteralPath $v3Manifest -Force

$run = @()
$run += 'param([Parameter(Mandatory=$true)][string]$RepoRoot)'
$run += '$ErrorActionPreference="Stop"'
$run += 'Set-StrictMode -Version Latest'
$run += ''
$run += 'function Die([string]$m){ throw $m }'
$run += ''
$run += '. (Join-Path $RepoRoot "scripts\_lib_veritas_receipts_v1.ps1")'
$run += ''
$run += 'function ParseGatePs1([string]$Path){'
$run += '  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }'
$run += '  $tok=$null; $err=$null'
$run += '  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)'
$run += '  if($err -and $err.Count -gt 0){ $e=$err[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message) }'
$run += '}'
$run += ''
$run += 'function WriteUtf8NoBomLf([string]$Path,[string]$Text){'
$run += '  $enc = New-Object System.Text.UTF8Encoding($false)'
$run += '  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")'
$run += '  if(-not $t.EndsWith("`n")){ $t += "`n" }'
$run += '  $dir = Split-Path -Parent $Path'
$run += '  if($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }'
$run += '  [System.IO.File]::WriteAllText($Path,$t,(New-Object System.Text.UTF8Encoding($false)))'
$run += '}'
$run += ''
$run += '$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path'
$run += '$Verifier   = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"'
$run += '$ReceiptOut = Join-Path $RepoRoot "proofs\receipts\veritas.ndjson"'
$run += '$ActualDir  = Join-Path $env:TEMP "veritas_negative_actual"'
$run += 'if(-not (Test-Path -LiteralPath $Verifier -PathType Leaf)){ Die ("MISSING_VERIFIER: " + $Verifier) }'
$run += 'if(-not (Test-Path -LiteralPath $ActualDir -PathType Container)){ New-Item -ItemType Directory -Force -Path $ActualDir | Out-Null }'
$run += ''
$run += '$cases = @('
$run += '  [pscustomobject]@{ Name = "01_tampered_file";  Rel = "test_vectors\negative\01_tampered_file";  ExpectStatus = "FILE_HASH_MISMATCH";     ExpectErrorPrefix = "FILE_HASH_BAD:" },'
$run += '  [pscustomobject]@{ Name = "02_missing_file";   Rel = "test_vectors\negative\02_missing_file";   ExpectStatus = "FILE_HASH_MISMATCH";     ExpectErrorPrefix = "FILE_HASH_MISSING:" },'
$run += '  [pscustomobject]@{ Name = "03_missing_manifest"; Rel = "test_vectors\negative\03_missing_manifest"; ExpectStatus = "STRUCTURE_INVALID"; ExpectErrorPrefix = "MISSING_REQUIRED:" }'
$run += ')'
$run += ''
$run += '$PSDummy = $null'
$run += 'foreach($case in $cases){'
$run += '  $bundlePath = Join-Path $RepoRoot $case.Rel'
$run += '  if(-not (Test-Path -LiteralPath $bundlePath -PathType Container)){ Die ("MISSING_CASE_DIR: " + $bundlePath) }'
$run += '  $lines = @(& python $Verifier verify $bundlePath --json --deterministic)'
$run += '  $code = $LASTEXITCODE'
$run += '  if(($code -ne 0) -and ($code -ne 1)){ Die ("BAD_EXITCODE_" + $case.Name + ": " + $code) }'
$run += '  $nonEmpty = @($lines | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })'
$run += '  if($nonEmpty.Count -ne 1){ Die ("STDOUT_NOISE_" + $case.Name + ": " + $nonEmpty.Count) }'
$run += '  $jsonText = $nonEmpty[0].ToString().Trim()'
$run += '  if(-not $jsonText.StartsWith("{")){ Die ("NOT_JSON_OBJECT_" + $case.Name) }'
$run += '  $actualPath = Join-Path $ActualDir ($case.Name + ".json")'
$run += '  WriteUtf8NoBomLf -Path $actualPath -Text $jsonText'
$run += '  $obj = $jsonText | ConvertFrom-Json'
$run += '  if($obj.status -ne $case.ExpectStatus){ Die ("BAD_STATUS_" + $case.Name + ": " + [string]$obj.status) }'
$run += '  if($null -eq $obj.errors -or @($obj.errors).Count -lt 1){ Die ("NO_ERRORS_" + $case.Name) }'
$run += '  $firstErr = [string]@($obj.errors)[0]'
$run += '  if(-not $firstErr.StartsWith($case.ExpectErrorPrefix)){ Die ("BAD_ERROR_PREFIX_" + $case.Name + ": " + $firstErr) }'
$run += '  $receiptLine = New-VeritasReceiptLine -RepoRoot $RepoRoot -RunnerRel "scripts\_RUN_veritas_negative_suite_v1.ps1" -VerifierRel "verifier\cli\veritas_verify.py" -VectorRel $case.Rel -ExitCode $code -Result "PASS" -StdoutText $jsonText -ExpectedPath $actualPath -ActualPath $actualPath -ReceiptPath $ReceiptOut'
$run += '  Append-VeritasReceipt -ReceiptPath $ReceiptOut -Line $receiptLine'
$run += '}'
$run += ''
$run += 'Write-Host "FULL_GREEN_OK" -ForegroundColor Green'

WriteUtf8NoBomLf -Path $RunPath -Text ((@($run) -join "`n") + "`n")
ParseGatePs1 -Path $RunPath
$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RunPath -RepoRoot $RepoRoot | Out-Host
