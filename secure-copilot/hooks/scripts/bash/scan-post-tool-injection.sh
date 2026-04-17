#!/bin/bash
#
# Purpose: Scan tool outputs for indirect prompt injection patterns after tool execution
#
# This hook fires on every postToolUse event. It reads the tool output from
# stdin (JSON), extracts the text content, and evaluates indirect injection
# pattern rules compiled from the shipped YAML baseline plus any optional
# local additive overrides. All patterns use the PCRE engine (perl) for full
# Unicode support. Matches are base64-encoded as evidence and assembled into
# a threats JSON array.
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
# Output — clean tool output (appended to governance-audit.jsonl):
#   {
#     "timestamp": "...",
#     "event": "postToolScanned",
#     "tool": "bash",
#     "status": "clean"
#   }
#
# Output — tool output with indirect injection threats:
#   {
#     "timestamp": "...",
#     "event": "indirectThreatDetected",
#     "tool": "bash",
#     "threat_count": 1,
#     "max_severity": 0.95,
#     "threats": [
#       {
#         "category": "instruction_override",
#         "severity": 0.95,
#         "description": "Ignore previous instructions",
#         "evidence": "ignore all previous instructions"
#       }
#     ]
#   }
#
# Key Behavior:
#   • Loads shipped indirect injection rules from hooks/config/generated/indirect-injection-patterns.json
#   • Optionally loads local additive rules from ~/.config/secure-copilot/generated/
#   • Uses perl for PCRE pattern matching (graceful degradation if perl unavailable)
#   • Logs configuration errors and exits 1 only when shipped generated JSON is unreadable
#   • Exits 1 after logging detected threats as an audit signal
#   • Skips scanning if tool output is empty or <10 chars
#   • Exits 1 if jq is not installed
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: jq, base64, perl (for PCRE), git (optional)
#

set -euo pipefail

if [[ "${SKIP_GOVERNANCE_AUDIT:-}" == "true" ]]; then
  exit 0
fi

command -v jq &>/dev/null || { echo "scan-post-tool-injection: jq is required but not installed"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common-config.sh
source "$SCRIPT_DIR/common-config.sh"

INPUT=$(cat)
setup_governance_audit_log "$(pwd)"

TOOL_NAME=$(echo "$INPUT" | jq -r '.toolName // empty' 2>/dev/null || echo "")
TOOL_OUTPUT=$(echo "$INPUT" | jq -r '.toolResult.textResultForLlm // empty' 2>/dev/null || echo "")

# Fallback: try toolResult as plain string
if [[ -z "$TOOL_OUTPUT" ]]; then
  TOOL_OUTPUT=$(echo "$INPUT" | jq -r 'if .toolResult | type == "string" then .toolResult else empty end' 2>/dev/null || echo "")
fi

# Skip scanning if output is empty or too short
if [[ -z "$TOOL_OUTPUT" ]] || [[ ${#TOOL_OUTPUT} -lt 10 ]]; then
  exit 0
fi

THREATS_FOUND=()
SCAN_SOURCE="scan-post-tool-injection"
SCAN_TEXT="$TOOL_OUTPUT"
SHIPPED_INDIRECT_RULES_JSON="$(get_secure_copilot_indirect_rules_json)"
LOCAL_INDIRECT_RULES_JSON="$(get_secure_copilot_user_indirect_rules_json)"

# shellcheck source=common-scanner.sh
source "$SCRIPT_DIR/common-scanner.sh"

if ! secure_copilot_json_is_readable "$SHIPPED_INDIRECT_RULES_JSON"; then
  secure_copilot_log_config_error "$LOG_FILE" "$SCAN_SOURCE" \
    "shipped indirect injection config unreadable: $SHIPPED_INDIRECT_RULES_JSON"
  exit 1
fi

scan_rules_from_json "$SHIPPED_INDIRECT_RULES_JSON"

if [[ -f "$LOCAL_INDIRECT_RULES_JSON" ]]; then
  if secure_copilot_json_is_readable "$LOCAL_INDIRECT_RULES_JSON"; then
    scan_rules_from_json "$LOCAL_INDIRECT_RULES_JSON"
  else
    secure_copilot_log_config_error "$LOG_FILE" "$SCAN_SOURCE" \
      "local indirect injection config unreadable; using shipped baseline: $LOCAL_INDIRECT_RULES_JSON"
  fi
fi

assemble_and_log_threats \
  "indirectThreatDetected" \
  "Indirect injection" \
  "postToolScanned" \
  "Indirect injection flagged by governance audit" \
  "$TOOL_NAME"

exit 0
