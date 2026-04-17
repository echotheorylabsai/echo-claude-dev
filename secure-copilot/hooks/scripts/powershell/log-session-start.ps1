# log-session-start.ps1
#
# Purpose: Log a governance audit event when a Copilot session begins
#
# This hook fires at session start. It captures the working directory,
# derives the project name from the git repo root, and
# appends a structured JSON event to the governance audit log. It also
# prints a confirmation message to stdout visible in the Copilot panel.
#
# Input:
#   None (no stdin). Context is derived from the shell environment.
#
# Environment variables:
#   SKIP_GOVERNANCE_AUDIT - Set to "true" to disable this hook entirely
#                           (default: unset)
#
# Output (appended to ~/progress-ai/secure-copilot/logs/<project>/governance-audit.jsonl):
#   {
#     "timestamp": "2026-03-25T10:00:00Z",
#     "event": "sessionStart",
#     "cwd": "/Users/user/project"
#   }
#
# Key Behavior:
#   • Derives project name from git repo root; falls back to basename of CWD
#   • Creates the log directory if it does not exist
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: PowerShell 7+, git (optional)
#

$ErrorActionPreference = "Stop"

# ── Governance guard ──────────────────────────────────────────────────────────
if ($env:SKIP_GOVERNANCE_AUDIT -eq "true") { exit 0 }

. (Join-Path (Split-Path -Parent $PSCommandPath) "common-config.ps1")

# ── Bootstrap: resolve audit context and log path ─────────────────────────────
$cwd = (Get-Location).Path
Initialize-GovernanceAuditLog $cwd

# ── Core logic ────────────────────────────────────────────────────────────────
$entry = [ordered]@{
  timestamp = $script:Timestamp
  event     = "sessionStart"
  cwd       = $cwd
}
($entry | ConvertTo-Json -Compress) | Add-Content -Path $script:LogFile -Encoding UTF8

Write-Host "`u{1F6E1}`u{FE0F} Governance audit active"
exit 0
