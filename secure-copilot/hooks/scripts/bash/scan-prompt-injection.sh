#!/bin/bash
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
#   • Exits 1 if jq is not installed
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: jq, base64, grep (with -E and -o support), git (optional)
#

set -euo pipefail

if [[ "${SKIP_GOVERNANCE_AUDIT:-}" == "true" ]]; then
  exit 0
fi

command -v jq &>/dev/null || { echo "scan-prompt-injection: jq is required but not installed"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common-config.sh
source "$SCRIPT_DIR/common-config.sh"

INPUT=$(cat)
setup_governance_audit_log "$(pwd)"

PROMPT=$(echo "$INPUT" | jq -r '.userMessage // .prompt // empty' 2>/dev/null || echo "")
if [[ -z "$PROMPT" ]]; then
  PROMPT="$INPUT"
fi

THREATS_FOUND=()
SCAN_SOURCE="scan-prompt-injection"
SCAN_TEXT="$PROMPT"
SHIPPED_PROMPT_RULES_JSON="$(get_secure_copilot_prompt_rules_json)"
LOCAL_PROMPT_RULES_JSON="$(get_secure_copilot_user_prompt_rules_json)"

# shellcheck source=common-scanner.sh
source "$SCRIPT_DIR/common-scanner.sh"

if ! secure_copilot_json_is_readable "$SHIPPED_PROMPT_RULES_JSON"; then
  secure_copilot_log_config_error "$LOG_FILE" "$SCAN_SOURCE" \
    "shipped prompt config unreadable: $SHIPPED_PROMPT_RULES_JSON"
  exit 1
fi

scan_rules_from_json "$SHIPPED_PROMPT_RULES_JSON"

if [[ -f "$LOCAL_PROMPT_RULES_JSON" ]]; then
  if secure_copilot_json_is_readable "$LOCAL_PROMPT_RULES_JSON"; then
    scan_rules_from_json "$LOCAL_PROMPT_RULES_JSON"
  else
    secure_copilot_log_config_error "$LOG_FILE" "$SCAN_SOURCE" \
      "local prompt config unreadable; using shipped baseline: $LOCAL_PROMPT_RULES_JSON"
  fi
fi

assemble_and_log_threats \
  "threatDetected" \
  "Governance" \
  "promptScanned" \
  "Prompt flagged by governance audit"

exit 0
