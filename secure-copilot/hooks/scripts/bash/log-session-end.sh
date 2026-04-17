#!/bin/bash
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
#   • Exits 1 if jq is not installed
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: jq, git (optional)
#

set -euo pipefail

if [[ "${SKIP_GOVERNANCE_AUDIT:-}" == "true" ]]; then
  exit 0
fi

command -v jq &>/dev/null || { echo "log-session-end: jq is required but not installed"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common-config.sh
source "$SCRIPT_DIR/common-config.sh"

setup_governance_audit_log "$(pwd)"

TOTAL=0
THREATS=0
SESSION_START_LINE=""
if [[ -f "$LOG_FILE" ]]; then
  SESSION_START_LINE=$(awk '/"event":"sessionStart"/ { line = NR } END { if (line) print line }' "$LOG_FILE")
  if [[ -n "$SESSION_START_LINE" ]]; then
    SESSION_LINES=$(tail -n +"$((SESSION_START_LINE + 1))" "$LOG_FILE" 2>/dev/null || true)
    if [[ -n "$SESSION_LINES" ]]; then
      TOTAL=$(printf '%s\n' "$SESSION_LINES" | jq -r '.timestamp' 2>/dev/null | awk 'END{print NR}' || echo 0)
      THREATS=$(printf '%s\n' "$SESSION_LINES" | jq -r 'select(.event == "threatDetected" or .event == "indirectThreatDetected") | .event' 2>/dev/null | awk 'END{print NR}' || echo 0)
    fi
  else
    TOTAL=$(jq -r '.timestamp' "$LOG_FILE" 2>/dev/null | awk 'END{print NR}' || echo 0)
    THREATS=$(jq -r 'select(.event == "threatDetected" or .event == "indirectThreatDetected") | .event' "$LOG_FILE" 2>/dev/null | awk 'END{print NR}' || echo 0)
  fi
fi

jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --argjson total "$TOTAL" \
  --argjson threats "$THREATS" \
  '{"timestamp":$timestamp,"event":"sessionEnd","total_events":$total,"threats_detected":$threats}' \
  >> "$LOG_FILE"

if [[ "$THREATS" -gt 0 ]]; then
  echo "⚠️ Session ended: $THREATS threat(s) detected in $TOTAL events"
else
  echo "✅ Session ended: $TOTAL events, no threats"
fi

exit 0
