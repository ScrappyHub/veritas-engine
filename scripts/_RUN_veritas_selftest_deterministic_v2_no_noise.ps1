param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ throw "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $t=(($Text -replace "`r`n","`n") -replace "`r","`n"); if(-not $t.EndsWith("`n")){ $t += "`n" }; $dir=Split-Path -Parent $Path; if($dir){ EnsureDir $dir }; [System.IO.File]::WriteAllText($Path,$t,$enc) }

$ver = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"
if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ throw ("MISSING_VERIFIER: " + $ver) }
$bundlePath   = Join-Path $RepoRoot "test_vectors\01_file_hash_mismatch"
$expectedPath = Join-Path $bundlePath "expected\verification_result.json"
if(-not (Test-Path -LiteralPath $bundlePath -PathType Container)){ throw ("MISSING_BUNDLE: " + $bundlePath) }
if(-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)){ throw ("MISSING_EXPECTED: " + $expectedPath) }
$actualPath = Join-Path $env:TEMP "veritas_actual.json"

# Capture stdout lines; enforce JSON-only (no extra noise lines)
$lines = @(& python $ver verify $bundlePath --json --deterministic)
$code = $LASTEXITCODE
if(($code -ne 0) -and ($code -ne 1)){ throw ("VERIFIER_BAD_EXITCODE: " + $code) }
$nonEmpty = @($lines | Where-Object { $_ -ne $null -and $_.ToString().Trim().Length -gt 0 })
if($nonEmpty.Count -ne 1){ throw ("VERIFIER_STDOUT_NOISE_LINES: " + $nonEmpty.Count) }
$actual = $nonEmpty[0].ToString()
if(-not $actual.TrimStart().StartsWith("{")){ throw "VERIFIER_OUTPUT_NOT_JSON_OBJECT" }
WriteUtf8NoBomLf -Path $actualPath -Text $actual

# Byte-for-byte compare
$aBytes = [System.IO.File]::ReadAllBytes($actualPath)
$eBytes = [System.IO.File]::ReadAllBytes($expectedPath)
if($aBytes.Length -ne $eBytes.Length){ throw ("BYTE_LEN_MISMATCH: actual={0} expected={1}" -f $aBytes.Length,$eBytes.Length) }
for($i=0; $i -lt $aBytes.Length; $i++){ if($aBytes[$i] -ne $eBytes[$i]){ throw ("BYTE_MISMATCH_AT: idx={0} actual=0x{1:X2} expected=0x{2:X2}" -f $i,$aBytes[$i],$eBytes[$i]) } }

Write-Host "FULL_GREEN_OK" -ForegroundColor Green
