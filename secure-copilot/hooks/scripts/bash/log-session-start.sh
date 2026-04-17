#!/bin/bash
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
#   • Exits 1 if jq is not installed
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: jq, git (optional)
#

set -euo pipefail

# ── Governance guard ──────────────────────────────────────────────────────────
if [[ "${SKIP_GOVERNANCE_AUDIT:-}" == "true" ]]; then
  exit 0
fi

command -v jq &>/dev/null || { echo "log-session-start: jq is required but not installed"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common-config.sh
source "$SCRIPT_DIR/common-config.sh"

# ── Bootstrap: resolve audit context and log path ─────────────────────────────
CWD=$(pwd)
setup_governance_audit_log "$CWD"

# ── Core logic ────────────────────────────────────────────────────────────────
jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg cwd "$CWD" \
  '{"timestamp":$timestamp,"event":"sessionStart","cwd":$cwd}' \
  >> "$LOG_FILE"

echo "🛡️ Governance audit active"
exit 0
