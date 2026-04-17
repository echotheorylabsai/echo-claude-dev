# log-pre-tool-use.ps1
#
# Purpose: Audit tool invocations before execution (log-only, never denies)
#
# This hook fires on every preToolUse event. It reads the Copilot hook payload,
# normalizes tool arguments, derives project and branch context from the current
# working directory, and appends a structured JSON audit entry to the
# governance audit log. It is intentionally non-blocking and emits no
# permissionDecision output.
#
# Input (via stdin — JSON from Copilot hook runtime):
#   {
#     "toolName": "bash",
#     "cwd": "/Users/user/project",
#     "toolArgs": {
#       "command": "npm test"
#     }
#   }
#
# Environment variables:
#   SKIP_GOVERNANCE_AUDIT - Set to "true" to disable this hook entirely
#                           (default: unset)
#
# Output (appended to ~/progress-ai/secure-copilot/logs/<project>/governance-audit.jsonl):
#   {
#     "timestamp": "2026-03-25T16:30:00Z",
#     "event": "preToolUse",
#     "tool": "bash",
#     "git_branch": "feature/secure-copilot",
#     "args": {
#       "command": "npm test"
#     }
#   }
#
# Key Behavior:
#   • Normalizes toolArgs whether the hook runtime provides JSON text or object
#   • Truncates long bash commands for readable logging
#   • Logs only; never blocks and never emits permissionDecision JSON
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

# ── Normalize toolArgs (string → object) ─────────────────────────────────────
$toolArgsObj = @{}
try {
  if ($inputObj.toolArgs -is [string]) {
    $toolArgsObj = $inputObj.toolArgs | ConvertFrom-Json -AsHashtable
  }
  elseif ($null -ne $inputObj.toolArgs) {
    # Convert PSObject to ordered hashtable for consistent serialization
    $toolArgsObj = @{}
    $inputObj.toolArgs.PSObject.Properties | ForEach-Object {
      $toolArgsObj[$_.Name] = $_.Value
    }
  }
}
catch {
  $toolArgsObj = @{}
}

# ── Git branch ───────────────────────────────────────────────────────────────
$gitBranch = "unknown"
if ($cwd) {
  try {
    Push-Location $cwd
    $gitBranch = & git branch --show-current 2>$null
    Pop-Location
    if (-not $gitBranch) { $gitBranch = "unknown" }
  }
  catch {
    Pop-Location
    $gitBranch = "unknown"
  }
}

Initialize-GovernanceAuditLog $cwd

# ── Truncate long bash commands ──────────────────────────────────────────────
$maxCommandLength = 200
if ($toolName -eq "bash" -and $toolArgsObj.ContainsKey("command")) {
  $cmd = $toolArgsObj["command"]
  if ($cmd.Length -gt $maxCommandLength) {
    $toolArgsObj["command"] = $cmd.Substring(0, $maxCommandLength) + "... [truncated]"
  }
}

# ── Log event ────────────────────────────────────────────────────────────────
$entry = [ordered]@{
  timestamp  = $script:Timestamp
  event      = "preToolUse"
  tool       = $toolName
  git_branch = $gitBranch
  args       = $toolArgsObj
}
($entry | ConvertTo-Json -Compress -Depth 5) | Add-Content -Path $script:LogFile -Encoding UTF8

exit 0
