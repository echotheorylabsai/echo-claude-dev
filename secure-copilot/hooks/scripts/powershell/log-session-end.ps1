# log-session-end.ps1
#
# Purpose: Log a governance audit summary event when a Copilot session ends
#
# This hook fires at session end. It reads the existing governance audit log,
# scopes events to the current session by locating the last sessionStart line,
# counts total events and threat detections within that window, and appends a
# sessionEnd summary entry to the log.
#
# Input:
#   None (no stdin). Reads the existing governance-audit.jsonl log file.
#
# Environment variables:
#   SKIP_GOVERNANCE_AUDIT - Set to "true" to disable this hook entirely
#                           (default: unset)
#
# Output (appended to ~/progress-ai/secure-copilot/logs/<project>/governance-audit.jsonl):
#   {
#     "timestamp": "2026-03-25T10:30:00Z",
#     "event": "sessionEnd",
#     "total_events": 12,
#     "threats_detected": 1
#   }
#
# Key Behavior:
#   • Locates the last sessionStart entry by line number, so same-second events
#     are still counted correctly
#   • Falls back to counting all log entries if no sessionStart is found
#   • Prints a summary line to stdout: event count and threat count
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: PowerShell 7+, git (optional)
#

$ErrorActionPreference = "Stop"

if ($env:SKIP_GOVERNANCE_AUDIT -eq "true") { exit 0 }

. (Join-Path (Split-Path -Parent $PSCommandPath) "common-config.ps1")

Initialize-GovernanceAuditLog (Get-Location).Path

$total   = 0
$threats = 0

if (Test-Path $script:LogFile) {
  $lines = Get-Content $script:LogFile

  # Find line number of last sessionStart (1-based)
  $sessionStartLine = -1
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '"event"\s*:\s*"sessionStart"') {
      $sessionStartLine = $i
    }
  }

  if ($sessionStartLine -ge 0) {
    # Count events after the last sessionStart
    $sessionLines = $lines[($sessionStartLine + 1)..($lines.Count - 1)]
  }
  else {
    $sessionLines = $lines
  }

  foreach ($line in $sessionLines) {
    if (-not $line) { continue }
    try {
      $obj = $line | ConvertFrom-Json
      if ($obj.timestamp) { $total++ }
      if ($obj.event -eq "threatDetected" -or $obj.event -eq "indirectThreatDetected") { $threats++ }
    }
    catch { continue }
  }
}

$entry = [ordered]@{
  timestamp        = $script:Timestamp
  event            = "sessionEnd"
  total_events     = $total
  threats_detected = $threats
}
($entry | ConvertTo-Json -Compress) | Add-Content -Path $script:LogFile -Encoding UTF8

if ($threats -gt 0) {
  Write-Host "`u{26A0}`u{FE0F} Session ended: $threats threat(s) detected in $total events"
}
else {
  Write-Host "`u{2705} Session ended: $total events, no threats"
}

exit 0
