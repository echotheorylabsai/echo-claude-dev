# scan-post-tool-injection.ps1
#
# Purpose: Scan tool outputs for indirect prompt injection patterns after tool execution
#
# This hook fires on every postToolUse event. It reads the tool output from
# stdin (JSON), extracts the text content, and evaluates indirect injection
# pattern rules compiled from the shipped YAML baseline plus any optional
# local additive overrides. All patterns use PCRE — PowerShell's .NET regex
# engine natively supports Unicode character classes.
#
# Input (via stdin — JSON from Copilot hook runtime):
#   {
#     "timestamp": 1711817646000,
#     "cwd": "/path/to/project",
#     "toolName": "bash",
#     "toolArgs": "{\"command\": \"cat file.txt\"}",
#     "toolResult": {
#       "resultType": "success",
#       "textResultForLlm": "...tool output text..."
#     }
#   }
#
# Environment variables:
#   SKIP_GOVERNANCE_AUDIT - Set to "true" to disable this hook entirely
#   SECURE_COPILOT_PLUGIN_ROOT - Optional plugin root override used by tests
#
# Key Behavior:
#   • Loads shipped indirect injection rules from hooks/config/generated/indirect-injection-patterns.json
#   • Optionally loads local additive rules from ~/.config/secure-copilot/generated/
#   • Uses .NET regex for PCRE patterns (natively supports Unicode)
#   • Logs configuration errors and exits 1 only when shipped generated JSON is unreadable
#   • Exits 1 after logging detected threats as an audit signal
#   • Skips scanning if tool output is empty or <10 chars
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

$toolName = ""
$toolOutput = ""
try {
  $inputObj = $rawInput | ConvertFrom-Json
  $toolName = if ($inputObj.toolName) { $inputObj.toolName } else { "" }

  # Extract tool output from structured result
  if ($inputObj.toolResult -and $inputObj.toolResult.textResultForLlm) {
    $toolOutput = $inputObj.toolResult.textResultForLlm
  }
  # Fallback: toolResult as plain string
  elseif ($inputObj.toolResult -and $inputObj.toolResult -is [string]) {
    $toolOutput = $inputObj.toolResult
  }
}
catch { }

# Skip scanning if output is empty or too short
if (-not $toolOutput -or $toolOutput.Length -lt 10) { exit 0 }

# ── Scan logic ────────────────────────────────────────────────────────────────
$threatsFound = @()
$shippedIndirectRulesJson = Get-SecureCopilotIndirectRulesJson
$localIndirectRulesJson   = Get-SecureCopilotUserIndirectRulesJson

function Test-IndirectPattern {
  param(
    [string]$Pattern,
    [string]$Category,
    [double]$Severity,
    [string]$Description,
    [bool]$CaseInsensitive
  )

  # PCRE patterns use raw pattern — .NET natively supports Unicode
  $regexOptions = [System.Text.RegularExpressions.RegexOptions]::None
  if ($CaseInsensitive) {
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  }

  try {
    $match = [regex]::Match($toolOutput, $Pattern, $regexOptions)
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

function Invoke-IndirectRuleScan {
  param([string]$JsonFile)

  $rules = Get-Content -Raw $JsonFile | ConvertFrom-Json
  foreach ($rule in $rules) {
    if (-not $rule.enabled) { continue }
    Test-IndirectPattern `
      -Pattern $rule.pattern `
      -Category $rule.category `
      -Severity $rule.severity `
      -Description $rule.description `
      -CaseInsensitive $rule.caseInsensitive
  }
}

# ── Load shipped rules ────────────────────────────────────────────────────────
if (-not (Test-SecureCopilotJsonReadable $shippedIndirectRulesJson)) {
  Write-SecureCopilotConfigError $script:LogFile "scan-post-tool-injection" `
    "shipped indirect injection config unreadable: $shippedIndirectRulesJson"
  exit 1
}

Invoke-IndirectRuleScan $shippedIndirectRulesJson

# ── Load local additive rules ────────────────────────────────────────────────
if (Test-Path $localIndirectRulesJson) {
  if (Test-SecureCopilotJsonReadable $localIndirectRulesJson) {
    Invoke-IndirectRuleScan $localIndirectRulesJson
  }
  else {
    Write-SecureCopilotConfigError $script:LogFile "scan-post-tool-injection" `
      "local indirect injection config unreadable; using shipped baseline: $localIndirectRulesJson"
  }
}

# ── Emit results ──────────────────────────────────────────────────────────────
if ($threatsFound.Count -gt 0) {
  $threatsArray = @()
  $maxSeverity  = 0.0

  Write-Host "`u{26A0}`u{FE0F} Indirect injection: $($threatsFound.Count) threat signal(s) detected in tool output"

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
    event        = "indirectThreatDetected"
    tool         = $toolName
    threat_count = $threatsFound.Count
    max_severity = $maxSeverity
    threats      = $threatsArray
  }
  ($entry | ConvertTo-Json -Compress -Depth 5) | Add-Content -Path $script:LogFile -Encoding UTF8

  Write-Host "(max severity: $maxSeverity)"

  Write-Host "`u{1F6AB} Indirect injection flagged by governance audit"
  exit 1
}
else {
  $entry = [ordered]@{
    timestamp = $script:Timestamp
    event     = "postToolScanned"
    tool      = $toolName
    status    = "clean"
  }
  ($entry | ConvertTo-Json -Compress) | Add-Content -Path $script:LogFile -Encoding UTF8
}
