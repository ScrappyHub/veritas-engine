param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ throw "EnsureDir: empty path" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
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
  $tok=$null
  $err=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and $err.Count -gt 0){
    $e=$err[0]
    throw ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

$RunPath = Join-Path $RepoRoot "scripts\_RUN_veritas_selftest_deterministic_v1.ps1"

$L = New-Object System.Collections.Generic.List[string]

[void]$L.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot)')
[void]$L.Add('$ErrorActionPreference="Stop"')
[void]$L.Add('Set-StrictMode -Version Latest')
[void]$L.Add('')
[void]$L.Add('function EnsureDir([string]$p){')
[void]$L.Add('  if([string]::IsNullOrWhiteSpace($p)){ throw "EnsureDir: empty path" }')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null }')
[void]$L.Add('}')
[void]$L.Add('')
[void]$L.Add('function WriteUtf8NoBomLf([string]$Path,[string]$Text){')
[void]$L.Add('  $enc = New-Object System.Text.UTF8Encoding($false)')
[void]$L.Add('  $t = (($Text -replace "`r`n","`n") -replace "`r","`n")')
[void]$L.Add('  if(-not $t.EndsWith("`n")){ $t += "`n" }')
[void]$L.Add('  $dir = Split-Path -Parent $Path')
[void]$L.Add('  if($dir){ EnsureDir $dir }')
[void]$L.Add('  [System.IO.File]::WriteAllText($Path,$t,$enc)')
[void]$L.Add('}')
[void]$L.Add('')
[void]$L.Add('$ver = Join-Path $RepoRoot "verifier\cli\veritas_verify.py"')
[void]$L.Add('if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ throw ("MISSING_VERIFIER: " + $ver) }')
[void]$L.Add('')
[void]$L.Add('$bundlePath   = Join-Path $RepoRoot "test_vectors\01_file_hash_mismatch"')
[void]$L.Add('$expectedPath = Join-Path $bundlePath "expected\verification_result.json"')
[void]$L.Add('if(-not (Test-Path -LiteralPath $bundlePath -PathType Container)){ throw ("MISSING_BUNDLE: " + $bundlePath) }')
[void]$L.Add('if(-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)){ throw ("MISSING_EXPECTED: " + $expectedPath) }')
[void]$L.Add('')
[void]$L.Add('$actualPath = Join-Path $env:TEMP "veritas_actual.json"')
[void]$L.Add('')
[void]$L.Add('# Call verifier with --deterministic')
[void]$L.Add('# NOTE: mismatch vectors may exit nonzero; accept (0 or 1) if JSON exists')
[void]$L.Add('$actualLines = @(& python $ver verify $bundlePath --json --deterministic)' )
[void]$L.Add('$code = $LASTEXITCODE' )
[void]$L.Add('$actual = (@($actualLines) -join "`n")' )
[void]$L.Add('if([string]::IsNullOrWhiteSpace($actual)){ throw ("VERIFIER_NO_JSON_OUTPUT: exit=" + $code) }' )
[void]$L.Add('if(($code -ne 0) -and ($code -ne 1)){ throw ("VERIFIER_BAD_EXITCODE: " + $code) }' )
[void]$L.Add('')
[void]$L.Add('# Write actual JSON deterministically')
[void]$L.Add('WriteUtf8NoBomLf -Path $actualPath -Text $actual' )
[void]$L.Add('')
[void]$L.Add('# Assert first 3 bytes are 7B 22 62')
[void]$L.Add('$b = [System.IO.File]::ReadAllBytes($actualPath)' )
[void]$L.Add('if($b.Length -lt 3){ throw ("ACTUAL_TOO_SHORT: " + $b.Length) }' )
[void]$L.Add('if( ($b[0] -ne 0x7B) -or ($b[1] -ne 0x22) -or ($b[2] -ne 0x62) ){ throw ("ACTUAL_HEADER_BYTES_BAD: {0:X2} {1:X2} {2:X2}" -f $b[0],$b[1],$b[2]) }' )
[void]$L.Add('')
[void]$L.Add('# Byte-for-byte compare')
[void]$L.Add('$aBytes = [System.IO.File]::ReadAllBytes($actualPath)' )
[void]$L.Add('$eBytes = [System.IO.File]::ReadAllBytes($expectedPath)' )
[void]$L.Add('if($aBytes.Length -ne $eBytes.Length){ throw ("BYTE_LEN_MISMATCH: actual={0} expected={1}" -f $aBytes.Length,$eBytes.Length) }' )
[void]$L.Add('for($i=0; $i -lt $aBytes.Length; $i++){ if($aBytes[$i] -ne $eBytes[$i]){ throw ("BYTE_MISMATCH_AT: idx={0} actual=0x{1:X2} expected=0x{2:X2}" -f $i,$aBytes[$i],$eBytes[$i]) } }' )
[void]$L.Add('')
[void]$L.Add('Write-Host "FULL_GREEN_OK" -ForegroundColor Green' )

WriteUtf8NoBomLf -Path $RunPath -Text ((@($L) -join "`n") + "`n")
ParseGatePs1 -Path $RunPath
$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RunPath -RepoRoot $RepoRoot | Out-Host
