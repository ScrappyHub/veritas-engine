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
$LibPath   = Join-Path $RepoRoot "scripts\_lib_veritas_receipts_v1.ps1"
$RunPath   = Join-Path $RepoRoot "scripts\_RUN_veritas_all_selftests_with_receipts_v1.ps1"

# ---- receipt library ----
$lib = @()
$lib += 'Set-StrictMode -Version Latest'
$lib += '$ErrorActionPreference="Stop"'
$lib += ''
$lib += 'function EnsureDir([string]$p){'
$lib += '  if([string]::IsNullOrWhiteSpace($p)){ throw "EnsureDir: empty path" }'
$lib += '  if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null }'
$lib += '}'
$lib += ''
$lib += 'function WriteUtf8NoBomLf([string]$Path,[string]$Text){'
$lib += '  $enc = New-Object System.Text.UTF8Encoding($false)'
$lib += '  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")'
$lib += '  if(-not $t.EndsWith("`n")){ $t += "`n" }'
$lib += '  $dir = Split-Path -Parent $Path'
$lib += '  if($dir){ EnsureDir $dir }'
$lib += '  [System.IO.File]::WriteAllText($Path,$t,$enc)'
$lib += '}'
$lib += ''
$lib += 'function AppendUtf8NoBomLf([string]$Path,[string]$Text){'
$lib += '  $enc = New-Object System.Text.UTF8Encoding($false)'
$lib += '  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")'
$lib += '  if(-not $t.EndsWith("`n")){ $t += "`n" }'
$lib += '  $dir = Split-Path -Parent $Path'
$lib += '  if($dir){ EnsureDir $dir }'
$lib += '  [System.IO.File]::AppendAllText($Path,$t,$enc)'
$lib += '}'
$lib += ''
$lib += 'function Get-Sha256HexFromBytes([byte[]]$Bytes){'
$lib += '  $sha = [System.Security.Cryptography.SHA256]::Create()'
$lib += '  try {'
$lib += '    $hash = $sha.ComputeHash($Bytes)'
$lib += '    return -join ($hash | ForEach-Object { $_.ToString("x2") })'
$lib += '  } finally {'
$lib += '    $sha.Dispose()'
$lib += '  }'
$lib += '}'
$lib += ''
$lib += 'function Get-Sha256HexFromFile([string]$Path){'
$lib += '  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ throw ("HASH_FILE_MISSING: " + $Path) }'
$lib += '  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()'
$lib += '}'
$lib += ''
$lib += 'function Get-CanonJson([object]$Obj){'
$lib += '  return ($Obj | ConvertTo-Json -Compress -Depth 100)'
$lib += '}'
$lib += ''
$lib += 'function Get-LastReceiptHash([string]$ReceiptPath){'
$lib += '  if(-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)){ return ("0" * 64) }'
$lib += '  $lines = @(Get-Content -LiteralPath $ReceiptPath -Encoding UTF8 | Where-Object { $_ -ne $null -and $_.Trim().Length -gt 0 })'
$lib += '  if($lines.Count -eq 0){ return ("0" * 64) }'
$lib += '  $last = $lines[$lines.Count - 1] | ConvertFrom-Json'
$lib += '  if($null -eq $last.receipt_hash -or [string]::IsNullOrWhiteSpace([string]$last.receipt_hash)){ return ("0" * 64) }'
$lib += '  return ([string]$last.receipt_hash).ToLowerInvariant()'
$lib += '}'
$lib += ''
$lib += 'function New-VeritasReceiptLine([string]$RepoRoot,[string]$RunnerRel,[string]$VerifierRel,[string]$VectorRel,[int]$ExitCode,[string]$Result,[string]$StdoutText,[string]$ExpectedPath,[string]$ActualPath,[string]$ReceiptPath){'
$lib += '  $prev = Get-LastReceiptHash -ReceiptPath $ReceiptPath'
$lib += '  $runId = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")'
$lib += '  $stdoutBytes = [System.Text.Encoding]::UTF8.GetBytes($StdoutText)'
$lib += '  $stdoutHash = Get-Sha256HexFromBytes -Bytes $stdoutBytes'
$lib += '  $verifierHash = Get-Sha256HexFromFile -Path (Join-Path $RepoRoot $VerifierRel)'
$lib += '  $expectedHash = Get-Sha256HexFromFile -Path $ExpectedPath'
$lib += '  $actualHash = Get-Sha256HexFromFile -Path $ActualPath'
$lib += '  $body = [ordered]@{'
$lib += '    schema = "veritas.receipt.v1"'
$lib += '    run_id = $runId'
$lib += '    ts_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")'
$lib += '    repo_root = $RepoRoot'
$lib += '    runner_rel = $RunnerRel'
$lib += '    verifier_rel = $VerifierRel'
$lib += '    vector_rel = $VectorRel'
$lib += '    exit_code = $ExitCode'
$lib += '    result = $Result'
$lib += '    stdout_sha256 = $stdoutHash'
$lib += '    verifier_sha256 = $verifierHash'
$lib += '    expected_sha256 = $expectedHash'
$lib += '    actual_sha256 = $actualHash'
$lib += '    prev_receipt_hash = $prev'
$lib += '  }'
$lib += '  $canon = Get-CanonJson -Obj $body'
$lib += '  $receiptHash = Get-Sha256HexFromBytes -Bytes ([System.Text.Encoding]::UTF8.GetBytes($canon))'
$lib += '  $full = [ordered]@{}'
$lib += '  foreach($k in $body.Keys){ $full[$k] = $body[$k] }'
$lib += '  $full["receipt_hash"] = $receiptHash'
$lib += '  return (Get-CanonJson -Obj $full)'
$lib += '}'
$lib += ''
$lib += 'function Append-VeritasReceipt([string]$ReceiptPath,[string]$Line){'
$lib += '  AppendUtf8NoBomLf -Path $ReceiptPath -Text $Line'
$lib += '}'

WriteUtf8NoBomLf -Path $LibPath -Text ((@($lib) -join "`n") + "`n")
ParseGatePs1 -Path $LibPath

# ---- receipt runner ----
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
$run += '$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path'
$run += '$allRunner = Join-Path $RepoRoot "scripts\_RUN_veritas_all_selftests_v1.ps1"'
$run += '$receiptPath = Join-Path $RepoRoot "proofs\receipts\veritas.ndjson"'
$run += '$expectedPath = Join-Path $RepoRoot "test_vectors\01_file_hash_mismatch\expected\verification_result.json"'
$run += '$actualPath = Join-Path $env:TEMP "veritas_actual.json"'
$run += '$verifierRel = "verifier\cli\veritas_verify.py"'
$run += '$runnerRel = "scripts\_RUN_veritas_all_selftests_with_receipts_v1.ps1"'
$run += '$vectorRel = "test_vectors\01_file_hash_mismatch"'
$run += ''
$run += 'if(-not (Test-Path -LiteralPath $allRunner -PathType Leaf)){ Die ("MISSING_ALL_RUNNER: " + $allRunner) }'
$run += 'ParseGatePs1 -Path $allRunner'
$run += ''
$run += '$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source'
$run += '$lines = @(& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $allRunner -RepoRoot $RepoRoot)'
$run += '$code = $LASTEXITCODE'
$run += '$nonEmpty = @($lines | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })'
$run += 'if($nonEmpty.Count -ne 1){ Die ("ALL_SELFTEST_STDOUT_NOISE: " + $nonEmpty.Count) }'
$run += '$stdout = $nonEmpty[0].ToString().Trim()'
$run += 'if($stdout -ne "FULL_GREEN_OK"){ Die ("ALL_SELFTEST_BAD_OUTPUT: " + $stdout) }'
$run += 'if($code -ne 0){ Die ("ALL_SELFTEST_BAD_EXITCODE: " + $code) }'
$run += ''
$run += 'if(-not (Test-Path -LiteralPath $actualPath -PathType Leaf)){ Die ("MISSING_ACTUAL_JSON: " + $actualPath) }'
$run += 'if(-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)){ Die ("MISSING_EXPECTED_JSON: " + $expectedPath) }'
$run += ''
$run += '$line = New-VeritasReceiptLine -RepoRoot $RepoRoot -RunnerRel $runnerRel -VerifierRel $verifierRel -VectorRel $vectorRel -ExitCode $code -Result "PASS" -StdoutText $stdout -ExpectedPath $expectedPath -ActualPath $actualPath -ReceiptPath $receiptPath'
$run += 'Append-VeritasReceipt -ReceiptPath $receiptPath -Line $line'
$run += ''
$run += 'Write-Host "FULL_GREEN_OK" -ForegroundColor Green'

WriteUtf8NoBomLf -Path $RunPath -Text ((@($run) -join "`n") + "`n")
ParseGatePs1 -Path $RunPath
$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RunPath -RepoRoot $RepoRoot | Out-Host
