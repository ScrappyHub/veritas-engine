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

$RunPath = Join-Path $RepoRoot "scripts\_RUN_veritas_selftest_deterministic_v1.ps1"

$runner = @()
$runner += 'param([Parameter(Mandatory=$true)][string]$RepoRoot)'
$runner += '$ErrorActionPreference="Stop"'
$runner += 'Set-StrictMode -Version Latest'
$runner += ''
$runner += 'function EnsureDir([string]$p){'
$runner += '  if([string]::IsNullOrWhiteSpace($p)){ throw "EnsureDir: empty path" }'
$runner += '  if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null }'
$runner += '}'
$runner += ''
$runner += 'function WriteUtf8NoBomLf([string]$Path,[string]$Text){'
$runner += '  $enc = New-Object System.Text.UTF8Encoding($false)'
$runner += '  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")'
$runner += '  if(-not $t.EndsWith("`n")){ $t += "`n" }'
$runner += '  $dir = Split-Path -Parent $Path'
$runner += '  if($dir){ EnsureDir $dir }'
$runner += '  [System.IO.File]::WriteAllText($Path,$t,$enc)'
$runner += '}'
$runner += ''
$runner += '$ver = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"'
$runner += 'if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ throw ("MISSING_VERIFIER: " + $ver) }'
$runner += ''
$runner += '$bundlePath   = Join-Path $RepoRoot "test_vectors\01_file_hash_mismatch"'
$runner += '$expectedPath = Join-Path $bundlePath "expected\verification_result.json"'
$runner += 'if(-not (Test-Path -LiteralPath $bundlePath -PathType Container)){ throw ("MISSING_BUNDLE: " + $bundlePath) }'
$runner += 'if(-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)){ throw ("MISSING_EXPECTED: " + $expectedPath) }'
$runner += ''
$runner += '$actualPath = Join-Path $env:TEMP "veritas_actual.json"'
$runner += ''
$runner += '# Call verifier with --deterministic'
$runner += '# NOTE: mismatch vectors may exit nonzero; accept (0 or 1) if JSON exists'
$runner += '$actualLines = @(& python $ver verify $bundlePath --json --deterministic)'
$runner += '$code = $LASTEXITCODE'
$runner += '$actual = (@($actualLines) -join "`n")'
$runner += 'if([string]::IsNullOrWhiteSpace($actual)){ throw ("VERIFIER_NO_JSON_OUTPUT: exit=" + $code) }'
$runner += 'if(($code -ne 0) -and ($code -ne 1)){ throw ("VERIFIER_BAD_EXITCODE: " + $code) }'
$runner += ''
$runner += 'WriteUtf8NoBomLf -Path $actualPath -Text $actual'
$runner += ''
$runner += '# Assert first 3 bytes are 7B 22 62'
$runner += '$b = [System.IO.File]::ReadAllBytes($actualPath)'
$runner += 'if($b.Length -lt 3){ throw ("ACTUAL_TOO_SHORT: " + $b.Length) }'
$runner += 'if( ($b[0] -ne 0x7B) -or ($b[1] -ne 0x22) -or ($b[2] -ne 0x62) ){ throw ("ACTUAL_HEADER_BYTES_BAD: {0:X2} {1:X2} {2:X2}" -f $b[0],$b[1],$b[2]) }'
$runner += ''
$runner += '# Byte-for-byte compare'
$runner += '$aBytes = [System.IO.File]::ReadAllBytes($actualPath)'
$runner += '$eBytes = [System.IO.File]::ReadAllBytes($expectedPath)'
$runner += 'if($aBytes.Length -ne $eBytes.Length){ throw ("BYTE_LEN_MISMATCH: actual={0} expected={1}" -f $aBytes.Length,$eBytes.Length) }'
$runner += 'for($i=0; $i -lt $aBytes.Length; $i++){ if($aBytes[$i] -ne $eBytes[$i]){ throw ("BYTE_MISMATCH_AT: idx={0} actual=0x{1:X2} expected=0x{2:X2}" -f $i,$aBytes[$i],$eBytes[$i]) } }'
$runner += ''
$runner += 'Write-Host "FULL_GREEN_OK" -ForegroundColor Green'

WriteUtf8NoBomLf -Path $RunPath -Text ((@($runner) -join "`n") + "`n")
ParseGatePs1 -Path $RunPath
$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RunPath -RepoRoot $RepoRoot | Out-Host
