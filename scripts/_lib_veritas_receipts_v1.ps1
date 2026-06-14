Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

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

function AppendUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::AppendAllText($Path,$t,$enc)
}

function Get-Sha256HexFromBytes([byte[]]$Bytes){
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash($Bytes)
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
  } finally {
    $sha.Dispose()
  }
}

function Get-Sha256HexFromFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ throw ("HASH_FILE_MISSING: " + $Path) }
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CanonJson([object]$Obj){
  return ($Obj | ConvertTo-Json -Compress -Depth 100)
}

function Get-LastReceiptHash([string]$ReceiptPath){
  if(-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)){ return ("0" * 64) }
  $lines = @(Get-Content -LiteralPath $ReceiptPath -Encoding UTF8 | Where-Object { $_ -ne $null -and $_.Trim().Length -gt 0 })
  if($lines.Count -eq 0){ return ("0" * 64) }
  $last = $lines[$lines.Count - 1] | ConvertFrom-Json
  if($null -eq $last.receipt_hash -or [string]::IsNullOrWhiteSpace([string]$last.receipt_hash)){ return ("0" * 64) }
  return ([string]$last.receipt_hash).ToLowerInvariant()
}

function New-VeritasReceiptLine([string]$RepoRoot,[string]$RunnerRel,[string]$VerifierRel,[string]$VectorRel,[int]$ExitCode,[string]$Result,[string]$StdoutText,[string]$ExpectedPath,[string]$ActualPath,[string]$ReceiptPath){
  $prev = Get-LastReceiptHash -ReceiptPath $ReceiptPath
  $runId = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
  $stdoutBytes = [System.Text.Encoding]::UTF8.GetBytes($StdoutText)
  $stdoutHash = Get-Sha256HexFromBytes -Bytes $stdoutBytes
  $verifierHash = Get-Sha256HexFromFile -Path (Join-Path $RepoRoot $VerifierRel)
  $expectedHash = Get-Sha256HexFromFile -Path $ExpectedPath
  $actualHash = Get-Sha256HexFromFile -Path $ActualPath
  $body = [ordered]@{
    schema = "veritas.receipt.v1"
    run_id = $runId
    ts_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    repo_root = $RepoRoot
    runner_rel = $RunnerRel
    verifier_rel = $VerifierRel
    vector_rel = $VectorRel
    exit_code = $ExitCode
    result = $Result
    stdout_sha256 = $stdoutHash
    verifier_sha256 = $verifierHash
    expected_sha256 = $expectedHash
    actual_sha256 = $actualHash
    prev_receipt_hash = $prev
  }
  $canon = Get-CanonJson -Obj $body
  $receiptHash = Get-Sha256HexFromBytes -Bytes ([System.Text.Encoding]::UTF8.GetBytes($canon))
  $full = [ordered]@{}
  foreach($k in $body.Keys){ $full[$k] = $body[$k] }
  $full["receipt_hash"] = $receiptHash
  return (Get-CanonJson -Obj $full)
}

function Append-VeritasReceipt([string]$ReceiptPath,[string]$Line){
  AppendUtf8NoBomLf -Path $ReceiptPath -Text $Line
}
