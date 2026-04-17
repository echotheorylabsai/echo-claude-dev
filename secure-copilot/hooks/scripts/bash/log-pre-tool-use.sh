#!/bin/bash
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
#   • Exits 1 if jq is not installed
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: jq, git (optional)
#

set -euo pipefail

if [[ "${SKIP_GOVERNANCE_AUDIT:-}" == "true" ]]; then
  exit 0
fi

command -v jq &>/dev/null || { echo "log-pre-tool-use: jq is required but not installed"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common-config.sh
source "$SCRIPT_DIR/common-config.sh"

parse_tool_hook_input

GIT_BRANCH="unknown"
if [[ -n "$CWD" ]]; then
  GIT_BRANCH=$(cd "$CWD" && git branch --show-current 2>/dev/null || echo "unknown")
fi

setup_governance_audit_log "$CWD"

MAX_COMMAND_LENGTH=200
if [[ "$TOOL_NAME" == "bash" ]]; then
  COMMAND=$(echo "$TOOL_ARGS_JSON" | jq -r '.command // ""')
  if [[ ${#COMMAND} -gt $MAX_COMMAND_LENGTH ]]; then
    TRUNCATED_COMMAND="${COMMAND:0:$MAX_COMMAND_LENGTH}... [truncated]"
    TOOL_ARGS_JSON=$(echo "$TOOL_ARGS_JSON" | jq --arg cmd "$TRUNCATED_COMMAND" '.command = $cmd')
  fi
fi

jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg tool "$TOOL_NAME" \
  --arg branch "$GIT_BRANCH" \
  --argjson args "$TOOL_ARGS_JSON" \
  '{"timestamp":$timestamp,"event":"preToolUse","tool":$tool,"git_branch":$branch,"args":$args}' \
  >> "$LOG_FILE"

exit 0
