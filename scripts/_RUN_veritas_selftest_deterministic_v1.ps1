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

$ver = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"
if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ throw ("MISSING_VERIFIER: " + $ver) }

$bundlePath   = Join-Path $RepoRoot "test_vectors\01_file_hash_mismatch"
$expectedPath = Join-Path $bundlePath "expected\verification_result.json"
if(-not (Test-Path -LiteralPath $bundlePath -PathType Container)){ throw ("MISSING_BUNDLE: " + $bundlePath) }
if(-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)){ throw ("MISSING_EXPECTED: " + $expectedPath) }

$actualPath = Join-Path $env:TEMP "veritas_actual.json"

# Call verifier with --deterministic
# NOTE: mismatch vectors may exit nonzero; accept (0 or 1) if JSON exists
$actualLines = @(& python $ver verify $bundlePath --json --deterministic)
$code = $LASTEXITCODE
$actual = (@($actualLines) -join "`n")
if([string]::IsNullOrWhiteSpace($actual)){ throw ("VERIFIER_NO_JSON_OUTPUT: exit=" + $code) }
if(($code -ne 0) -and ($code -ne 1)){ throw ("VERIFIER_BAD_EXITCODE: " + $code) }

WriteUtf8NoBomLf -Path $actualPath -Text $actual

# Assert first 3 bytes are 7B 22 62
$b = [System.IO.File]::ReadAllBytes($actualPath)
if($b.Length -lt 3){ throw ("ACTUAL_TOO_SHORT: " + $b.Length) }
if( ($b[0] -ne 0x7B) -or ($b[1] -ne 0x22) -or ($b[2] -ne 0x62) ){ throw ("ACTUAL_HEADER_BYTES_BAD: {0:X2} {1:X2} {2:X2}" -f $b[0],$b[1],$b[2]) }

# Byte-for-byte compare
$aBytes = [System.IO.File]::ReadAllBytes($actualPath)
$eBytes = [System.IO.File]::ReadAllBytes($expectedPath)
if($aBytes.Length -ne $eBytes.Length){ throw ("BYTE_LEN_MISMATCH: actual={0} expected={1}" -f $aBytes.Length,$eBytes.Length) }
for($i=0; $i -lt $aBytes.Length; $i++){ if($aBytes[$i] -ne $eBytes[$i]){ throw ("BYTE_MISMATCH_AT: idx={0} actual=0x{1:X2} expected=0x{2:X2}" -f $i,$aBytes[$i],$eBytes[$i]) } }

Write-Host "FULL_GREEN_OK" -ForegroundColor Green
