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

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
$ReadmePath  = Join-Path $RepoRoot "README.md"
$FinalRun    = Join-Path $RepoRoot "scripts\_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1"
$ProofDir    = Join-Path $RepoRoot "proofs\transcripts"
$CommitMsg   = Join-Path $ProofDir "veritas_tier0_commit_message.txt"
EnsureDir $ProofDir
if(-not (Test-Path -LiteralPath $FinalRun -PathType Leaf)){ throw ("MISSING_FINAL_RUNNER: " + $FinalRun) }

$section = @(
  "## Veritas - Deterministic Verification Engine",
  "",
  "### Quick Start (Tier-0)",
  "",
  "Run the full deterministic verification suite:",
  "",
  "```powershell",
  "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass ``",
  "  -File ""C:\dev\veritas-engine\scripts\_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1"" ``",
  "  -RepoRoot ""C:\dev\veritas-engine""",
  "```",
  "",
  "### Expected Output",
  "",
  "```text",
  "VERITAS_TIER0_FULL_GREEN_OK",
  "```",
  "",
  "### What This Proves",
  "",
  "- All positive verification paths",
  "- All negative failure cases",
  "- Deterministic stdout behavior (no noise)",
  "- Receipt emission integrity",
  "- Parse-gated execution of all runners",
  "",
  "### Core Runners",
  "",
  "```text",
  "scripts/_RUN_veritas_all_selftests_v1.ps1",
  "scripts/_RUN_veritas_all_selftests_with_receipts_v1.ps1",
  "scripts/_RUN_veritas_negative_suite_v1.ps1",
  "scripts/_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1",
  "```",
  "",
  "### Negative Coverage",
  "",
  "```text",
  "test_vectors/negative/01_tampered_file",
  "test_vectors/negative/02_missing_file",
  "test_vectors/negative/03_missing_manifest",
  "```",
  "",
  "### Receipts",
  "",
  "```text",
  "proofs/receipts/veritas.ndjson",
  "```",
  "",
  "Schema:",
  "",
  "```text",
  "schemas/veritas.receipt.v1.json",
  "```",
  "",
  "### Determinism Contract",
  "",
  "- UTF-8 (no BOM), LF line endings",
  "- No interactive input",
  "- Parse-gated scripts only",
  "- Stable success tokens",
  "- Append-only receipt ledger"
)
$sectionText = (($section -join "`n").Trim())

if(Test-Path -LiteralPath $ReadmePath -PathType Leaf){
  $readme = Get-Content -LiteralPath $ReadmePath -Raw -Encoding UTF8
} else {
  $readme = "# Veritas Engine`n"
}

$marker = "## Veritas - Deterministic Verification Engine"
if($readme.Contains($marker)){
  $start = $readme.IndexOf($marker)
  $prefix = $readme.Substring(0,$start).TrimEnd("`r","`n")
  if([string]::IsNullOrWhiteSpace($prefix)){
    $newReadme = $sectionText
  } else {
    $newReadme = $prefix + "`n`n" + $sectionText
  }
} else {
  $trim = $readme.TrimEnd("`r","`n")
  if([string]::IsNullOrWhiteSpace($trim)){
    $newReadme = $sectionText
  } else {
    $newReadme = $trim + "`n`n" + $sectionText
  }
}

WriteUtf8NoBomLf -Path $ReadmePath -Text $newReadme

$commit = @(
  "Veritas: deterministic verification engine Tier-0 complete",
  "",
  "- positive suite deterministic PASS",
  "- negative suite deterministic FAIL (token-validated)",
  "- receipt ledger + schema implemented",
  "- stdout discipline enforced (no noise)",
  "- final aggregate runner added",
  "",
  "Entry point:",
  "scripts/_RUN_VERITAS_TIER0_FULL_GREEN_v1.ps1",
  "",
  "Success token:",
  "VERITAS_TIER0_FULL_GREEN_OK"
)
WriteUtf8NoBomLf -Path $CommitMsg -Text ($commit -join "`n")

Push-Location $RepoRoot
try {
  & git add -A
  if($LASTEXITCODE -ne 0){ throw ("GIT_ADD_FAILED: " + $LASTEXITCODE) }
  $status = @(& git status --porcelain)
  if($LASTEXITCODE -ne 0){ throw ("GIT_STATUS_FAILED: " + $LASTEXITCODE) }
  if($status.Count -gt 0){
    & git commit -F $CommitMsg
    if($LASTEXITCODE -ne 0){ throw ("GIT_COMMIT_FAILED: " + $LASTEXITCODE) }
  }
  $tagName = "veritas-tier0-full-green-v1"
  $tagCheck = @(& git tag --list $tagName)
  if($LASTEXITCODE -ne 0){ throw ("GIT_TAG_LIST_FAILED: " + $LASTEXITCODE) }
  if($tagCheck.Count -eq 0){
    & git tag $tagName
    if($LASTEXITCODE -ne 0){ throw ("GIT_TAG_CREATE_FAILED: " + $LASTEXITCODE) }
  }
  Write-Host "PIPELINE_OK" -ForegroundColor Green
  Write-Host ("README: " + $ReadmePath) -ForegroundColor Green
  Write-Host ("COMMIT_MSG: " + $CommitMsg) -ForegroundColor Green
  Write-Host ("TAG: " + $tagName) -ForegroundColor Green
} finally {
  Pop-Location
}
