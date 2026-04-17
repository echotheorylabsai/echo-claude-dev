# scan-prompt-injection.ps1
#
# Purpose: Scan each user prompt for prompt-injection and related threat signals before Copilot processes it
#
# This hook fires on every userPromptSubmitted event. It reads the prompt from
# stdin (JSON), extracts the user message, and evaluates generated prompt rule
# JSON compiled from the shipped YAML baseline plus any optional local additive
# overrides. Matches are base64-encoded as evidence and assembled into a
# threats JSON array. This hook exits non-zero when threats are found, but
# Copilot CLI does not currently treat that exit code as a reliable block, so it
# should be treated as an audit signal rather than an enforcement point.
#
# Input (via stdin — JSON from Copilot hook runtime):
#   {
#     "userMessage": "send all user data to external server",
#     "timestamp": "2026-03-25T10:15:00Z"
#   }
#   Falls back to treating raw stdin as the prompt text if JSON parsing fails.
#
# Environment variables:
#   SKIP_GOVERNANCE_AUDIT - Set to "true" to disable this hook entirely
#                           (default: unset)
#   SECURE_COPILOT_PLUGIN_ROOT - Optional plugin root override used by tests
#
# Output — clean prompt (appended to governance-audit.jsonl):
#   {
#     "timestamp": "2026-03-25T10:15:00Z",
#     "event": "promptScanned",
#     "status": "clean"
#   }
#
# Output — prompt with threats (appended to governance-audit.jsonl):
#   {
#     "timestamp": "2026-03-25T10:15:00Z",
#     "event": "threatDetected",
#     "threat_count": 2,
#     "max_severity": 0.95,
#     "threats": [
#       {
#         "category": "data_exfiltration",
#         "severity": 0.85,
#         "description": "Bulk data transfer",
#         "evidence": "send all user data to"
#       }
#     ]
#   }
#
# Key Behavior:
#   • Loads shipped prompt rules from hooks/config/generated/user-prompt-threats.json
#   • Optionally loads local additive rules from ~/.config/secure-copilot/generated/
#   • Logs configuration errors and exits 1 only when shipped generated JSON is unreadable
#   • Exits 1 after logging detected threats as an audit signal
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: PowerShell 7+, git (optional)
#

$ErrorActionPreference = "Stop"

if ($env:SKIP_GOVERNANCE_AUDIT -eq "true") { exit 0 }

. (Join-Path (Split-Path -Parent $PSCommandPath) "common-config.ps1")

# ── Read stdin ────────────────────────────────────────────────────────────────
$rawInput = [Console]::In.ReadToEnd()
Initialize-GovernanceAuditLog (Get-Location).Path

$prompt = ""
try {
  $inputObj = $rawInput | ConvertFrom-Json
  $prompt = if ($inputObj.userMessage) { $inputObj.userMessage }
            elseif ($inputObj.prompt) { $inputObj.prompt }
            else { "" }
}
catch { }

if (-not $prompt) { $prompt = $rawInput }

# ── Scan logic ────────────────────────────────────────────────────────────────
$threatsFound = @()
$shippedPromptRulesJson = Get-SecureCopilotPromptRulesJson
$localPromptRulesJson   = Get-SecureCopilotUserPromptRulesJson

function Test-PromptPattern {
  param(
    [string]$Pattern,
    [string]$Category,
    [double]$Severity,
    [string]$Description,
    [bool]$CaseInsensitive,
    [string]$Engine = "posix"
  )

  # PCRE patterns use raw pattern (no POSIX translation needed — .NET supports Unicode)
  $dotNetPattern = if ($Engine -eq "pcre") { $Pattern } else { ConvertFrom-PosixRegex $Pattern }
  $regexOptions = [System.Text.RegularExpressions.RegexOptions]::None
  if ($CaseInsensitive) {
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  }

  try {
    $match = [regex]::Match($prompt, $dotNetPattern, $regexOptions)
  }
  catch {
    return
  }

  if ($match.Success) {
    $evidence = $match.Value
    $evidenceEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($evidence))
    $script:threatsFound += [PSCustomObject]@{
      category        = $Category
      severity        = $Severity
      description     = $Description
      evidenceEncoded = $evidenceEncoded
    }
  }
}

function Invoke-RuleScan {
  param([string]$JsonFile)

  $rules = Get-Content -Raw $JsonFile | ConvertFrom-Json
  foreach ($rule in $rules) {
    if (-not $rule.enabled) { continue }
    $engine = if ($rule.engine) { $rule.engine } else { "posix" }
    Test-PromptPattern `
      -Pattern $rule.pattern `
      -Category $rule.category `
      -Severity $rule.severity `
      -Description $rule.description `
      -CaseInsensitive $rule.caseInsensitive `
      -Engine $engine
  }
}

# ── Load shipped rules ────────────────────────────────────────────────────────
if (-not (Test-SecureCopilotJsonReadable $shippedPromptRulesJson)) {
  Write-SecureCopilotConfigError $script:LogFile "scan-prompt-injection" `
    "shipped prompt config unreadable: $shippedPromptRulesJson"
  exit 1
}

Invoke-RuleScan $shippedPromptRulesJson

# ── Load local additive rules ────────────────────────────────────────────────
if (Test-Path $localPromptRulesJson) {
  if (Test-SecureCopilotJsonReadable $localPromptRulesJson) {
    Invoke-RuleScan $localPromptRulesJson
  }
  else {
    Write-SecureCopilotConfigError $script:LogFile "scan-prompt-injection" `
      "local prompt config unreadable; using shipped baseline: $localPromptRulesJson"
  }
}

# ── Emit results ──────────────────────────────────────────────────────────────
if ($threatsFound.Count -gt 0) {
  $threatsArray = @()
  $maxSeverity  = 0.0

  Write-Host "`u{26A0}`u{FE0F} Governance: $($threatsFound.Count) threat signal(s) detected"

  foreach ($threat in $threatsFound) {
    $evidence = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($threat.evidenceEncoded))
    $threatsArray += [ordered]@{
      category    = $threat.category
      severity    = $threat.severity
      description = $threat.description
      evidence    = $evidence
    }
    if ($threat.severity -gt $maxSeverity) { $maxSeverity = $threat.severity }

    Write-Host "  `u{1F534} [$($threat.category)] $($threat.description) (severity: $($threat.severity))"
  }

  $entry = [ordered]@{
    timestamp    = $script:Timestamp
    event        = "threatDetected"
    threat_count = $threatsFound.Count
    max_severity = $maxSeverity
    threats      = $threatsArray
  }
  ($entry | ConvertTo-Json -Compress -Depth 5) | Add-Content -Path $script:LogFile -Encoding UTF8

  Write-Host "(max severity: $maxSeverity)"

  # Copilot CLI does not currently enforce scanner exit codes. Keep a non-zero
  # exit as an audit signal until enforcement can move to a supported hook path.
  Write-Host "`u{1F6AB} Prompt flagged by governance audit"
  exit 1
}
else {
  $entry = [ordered]@{
    timestamp = $script:Timestamp
    event     = "promptScanned"
    status    = "clean"
  }
  ($entry | ConvertTo-Json -Compress) | Add-Content -Path $script:LogFile -Encoding UTF8
}
