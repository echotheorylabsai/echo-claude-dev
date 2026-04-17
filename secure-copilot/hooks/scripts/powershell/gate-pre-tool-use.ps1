# gate-pre-tool-use.ps1
#
# Purpose: Enforce baseline governance rules before tool execution
#
# This hook fires on every preToolUse event after the audit hook. It inspects
# the incoming tool request, evaluates generated tool-rule JSON compiled from
# the shipped YAML baseline plus any optional local additive overrides, writes
# structured governance decisions to the audit log, and emits
# `permissionDecision: "deny"` JSON only when blocking.
#
# Input (via stdin — JSON from Copilot hook runtime):
#   {
#     "toolName": "bash",
#     "cwd": "/Users/user/project",
#     "toolArgs": {
#       "command": "rm -rf /"
#     }
#   }
#
# Environment variables:
#   SKIP_GOVERNANCE_AUDIT - Set to "true" to disable this hook entirely
#                           (default: unset)
#   SECURE_COPILOT_PLUGIN_ROOT - Optional plugin root override used by tests
#
# Output — allow:
#   No stdout. The hook logs the allow decision and exits 0.
#
# Output — deny:
#   {
#     "permissionDecision": "deny",
#     "permissionDecisionReason": "Blocked dangerous command: destructive file operations detected"
#   }
#
# Key Behavior:
#   • Loads shipped tool rules from hooks/config/generated/tool-rules.json
#   • Optionally loads local additive rules from ~/.config/secure-copilot/generated/
#   • Preserves first-match deny behavior and silent allow behavior
#   • Logs configuration errors and denies only when shipped generated JSON is unreadable
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: PowerShell 7+, git (optional)
#

$ErrorActionPreference = "Stop"

if ($env:SKIP_GOVERNANCE_AUDIT -eq "true") { exit 0 }

. (Join-Path (Split-Path -Parent $PSCommandPath) "common-config.ps1")

# ── Read stdin ────────────────────────────────────────────────────────────────
$rawInput = [Console]::In.ReadToEnd()
$inputObj = $rawInput | ConvertFrom-Json

$toolName = if ($inputObj.toolName) { $inputObj.toolName } else { "unknown" }
$cwd      = if ($inputObj.cwd) { $inputObj.cwd } else { "" }

# ── Normalize toolArgs ───────────────────────────────────────────────────────
$toolArgsObj = @{}
try {
  if ($inputObj.toolArgs -is [string]) {
    $toolArgsObj = $inputObj.toolArgs | ConvertFrom-Json -AsHashtable
  }
  elseif ($null -ne $inputObj.toolArgs) {
    $toolArgsObj = @{}
    $inputObj.toolArgs.PSObject.Properties | ForEach-Object {
      $toolArgsObj[$_.Name] = $_.Value
    }
  }
}
catch {
  $toolArgsObj = @{}
}

$command  = if ($toolArgsObj.ContainsKey("command"))  { $toolArgsObj["command"] }  else { "" }
$filePath = if ($toolArgsObj.ContainsKey("path"))     { $toolArgsObj["path"] }
            elseif ($toolArgsObj.ContainsKey("filePath")) { $toolArgsObj["filePath"] }
            else { "" }

$shippedToolRulesJson = Get-SecureCopilotToolRulesJson
$localToolRulesJson   = Get-SecureCopilotUserToolRulesJson

Initialize-GovernanceAuditLog $cwd

$decision = "allow"
$reason   = ""

# ── Target value resolver ────────────────────────────────────────────────────
function Get-TargetValue {
  param([string]$TargetField)

  switch ($TargetField) {
    "command" { return $command }
    "path"    { return $filePath }
    default   { return "" }
  }
}

# ── Pattern matcher ──────────────────────────────────────────────────────────
function Test-PatternMatch {
  param(
    [string]$Value,
    [string]$Pattern,
    [bool]$CaseInsensitive
  )

  $dotNetPattern = ConvertFrom-PosixRegex $Pattern
  $regexOptions = [System.Text.RegularExpressions.RegexOptions]::None
  if ($CaseInsensitive) {
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  }

  try {
    return [regex]::IsMatch($Value, $dotNetPattern, $regexOptions)
  }
  catch {
    return $false
  }
}

# ── Reason formatter ─────────────────────────────────────────────────────────
function Format-Reason {
  param(
    [string]$Template,
    [string]$Value
  )
  return $Template -replace '\{value\}', $Value
}

# ── Rule evaluator ───────────────────────────────────────────────────────────
function Invoke-RuleEvaluation {
  param([string]$JsonFile)

  $rules = Get-Content -Raw $JsonFile | ConvertFrom-Json
  foreach ($rule in $rules) {
    if (-not $rule.enabled) { continue }
    if ($rule.action -ne "deny") { continue }
    if ($rule.tool -ne $toolName) { continue }

    $targetValue = Get-TargetValue $rule.targetField
    if (Test-PatternMatch -Value $targetValue -Pattern $rule.pattern -CaseInsensitive $rule.caseInsensitive) {
      $script:decision = "deny"
      $script:reason   = Format-Reason $rule.reason $targetValue
      return $true
    }
  }
  return $false
}

# ── Evaluate shipped rules ───────────────────────────────────────────────────
if (-not (Test-SecureCopilotJsonReadable $shippedToolRulesJson)) {
  $reason   = "Blocked tool execution: secure-copilot shipped tool config unreadable"
  Write-SecureCopilotConfigError $script:LogFile "gate-pre-tool-use" `
    "shipped tool config unreadable: $shippedToolRulesJson"
  $decision = "deny"
}
else {
  $null = Invoke-RuleEvaluation $shippedToolRulesJson

  if ($decision -ne "deny" -and (Test-Path $localToolRulesJson)) {
    if (Test-SecureCopilotJsonReadable $localToolRulesJson) {
      $null = Invoke-RuleEvaluation $localToolRulesJson
    }
    else {
      Write-SecureCopilotConfigError $script:LogFile "gate-pre-tool-use" `
        "local tool config unreadable; using shipped baseline: $localToolRulesJson"
    }
  }
}

# ── Log decision ─────────────────────────────────────────────────────────────
$entry = [ordered]@{
  timestamp = $script:Timestamp
  event     = "preToolDecision"
  tool      = $toolName
  decision  = $decision
  reason    = $reason
}
($entry | ConvertTo-Json -Compress) | Add-Content -Path $script:LogFile -Encoding UTF8

# ── Emit deny payload ────────────────────────────────────────────────────────
if ($decision -eq "deny") {
  $denyPayload = [ordered]@{
    permissionDecision       = "deny"
    permissionDecisionReason = $reason
  }
  ($denyPayload | ConvertTo-Json -Compress)
}
