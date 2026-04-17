#!/bin/bash
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
#   • Exits 1 if jq is not installed
#   • Exits 0 (no-op) if SKIP_GOVERNANCE_AUDIT=true
#
# Dependencies: jq, git (optional)
#

set -euo pipefail

if [[ "${SKIP_GOVERNANCE_AUDIT:-}" == "true" ]]; then
  exit 0
fi

command -v jq &>/dev/null || { echo "gate-pre-tool-use: jq is required but not installed"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common-config.sh
source "$SCRIPT_DIR/common-config.sh"

parse_tool_hook_input
COMMAND=$(echo "$TOOL_ARGS_JSON" | jq -r '.command // ""')
FILE_PATH=$(echo "$TOOL_ARGS_JSON" | jq -r '.path // .filePath // ""')
SHIPPED_TOOL_RULES_JSON="$(get_secure_copilot_tool_rules_json)"
LOCAL_TOOL_RULES_JSON="$(get_secure_copilot_user_tool_rules_json)"

setup_governance_audit_log "$CWD"

DECISION="allow"
REASON=""

get_target_value() {
  local target_field="$1"

  case "$target_field" in
    command)
      printf '%s' "$COMMAND"
      ;;
    path)
      printf '%s' "$FILE_PATH"
      ;;
    *)
      printf ''
      ;;
  esac
}

pattern_matches() {
  local value="$1"
  local pattern="$2"
  local case_insensitive="$3"
  local grep_args=(-qE)

  if [[ "$case_insensitive" == "true" ]]; then
    grep_args=(-qiE)
  fi

  printf '%s\n' "$value" | grep "${grep_args[@]}" "$pattern"
}

format_reason() {
  local template="$1"
  local value="$2"
  printf '%s' "${template//\{value\}/$value}"
}

evaluate_rules_from_json() {
  local json_file="$1"
  local rule

  while IFS= read -r rule; do
    local rule_tool
    local target_field
    local pattern
    local reason_template
    local case_insensitive
    local target_value

    rule_tool=$(printf '%s' "$rule" | jq -r '.tool')
    [[ "$rule_tool" == "$TOOL_NAME" ]] || continue

    target_field=$(printf '%s' "$rule" | jq -r '.targetField')
    pattern=$(printf '%s' "$rule" | jq -r '.pattern')
    reason_template=$(printf '%s' "$rule" | jq -r '.reason')
    case_insensitive=$(printf '%s' "$rule" | jq -r '.caseInsensitive')
    target_value=$(get_target_value "$target_field")

    if pattern_matches "$target_value" "$pattern" "$case_insensitive"; then
      DECISION="deny"
      REASON=$(format_reason "$reason_template" "$target_value")
      return 0
    fi
  done < <(jq -c '.[] | select(.enabled == true and .action == "deny")' "$json_file")

  return 1
}

if ! secure_copilot_json_is_readable "$SHIPPED_TOOL_RULES_JSON"; then
  REASON="Blocked tool execution: secure-copilot shipped tool config unreadable"
  secure_copilot_log_config_error "$LOG_FILE" "gate-pre-tool-use" \
    "shipped tool config unreadable: $SHIPPED_TOOL_RULES_JSON"
  DECISION="deny"
else
  evaluate_rules_from_json "$SHIPPED_TOOL_RULES_JSON" || true

  if [[ "$DECISION" != "deny" && -f "$LOCAL_TOOL_RULES_JSON" ]]; then
    if secure_copilot_json_is_readable "$LOCAL_TOOL_RULES_JSON"; then
      evaluate_rules_from_json "$LOCAL_TOOL_RULES_JSON" || true
    else
      secure_copilot_log_config_error "$LOG_FILE" "gate-pre-tool-use" \
        "local tool config unreadable; using shipped baseline: $LOCAL_TOOL_RULES_JSON"
    fi
  fi
fi

jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg tool "$TOOL_NAME" \
  --arg decision "$DECISION" \
  --arg reason "$REASON" \
  '{"timestamp":$timestamp,"event":"preToolDecision","tool":$tool,"decision":$decision,"reason":$reason}' \
  >> "$LOG_FILE"

if [[ "$DECISION" == "deny" ]]; then
  jq -cn --arg reason "$REASON" '{"permissionDecision":"deny","permissionDecisionReason":$reason}'
fi
