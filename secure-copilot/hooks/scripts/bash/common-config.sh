#!/bin/bash

get_secure_copilot_plugin_root() {
  if [[ -n "${SECURE_COPILOT_PLUGIN_ROOT:-}" ]]; then
    printf '%s\n' "$SECURE_COPILOT_PLUGIN_ROOT"
    return
  fi

  local script_dir
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  cd "$script_dir/../../.." && pwd
}

get_secure_copilot_shipped_config_dir() {
  printf '%s\n' "$(get_secure_copilot_plugin_root)/hooks/config"
}

get_secure_copilot_generated_config_dir() {
  printf '%s\n' "$(get_secure_copilot_shipped_config_dir)/generated"
}

get_secure_copilot_prompt_rules_json() {
  printf '%s\n' "$(get_secure_copilot_generated_config_dir)/user-prompt-threats.json"
}

get_secure_copilot_tool_rules_json() {
  printf '%s\n' "$(get_secure_copilot_generated_config_dir)/tool-rules.json"
}

get_secure_copilot_indirect_rules_json() {
  printf '%s\n' "$(get_secure_copilot_generated_config_dir)/indirect-injection-patterns.json"
}

get_secure_copilot_user_override_yaml() {
  printf '%s\n' "${HOME}/.config/secure-copilot/overrides.yaml"
}

get_secure_copilot_user_generated_dir() {
  printf '%s\n' "${HOME}/.config/secure-copilot/generated"
}

get_secure_copilot_user_prompt_rules_json() {
  printf '%s\n' "$(get_secure_copilot_user_generated_dir)/user-prompt-threats.json"
}

get_secure_copilot_user_tool_rules_json() {
  printf '%s\n' "$(get_secure_copilot_user_generated_dir)/tool-rules.json"
}

get_secure_copilot_user_indirect_rules_json() {
  printf '%s\n' "$(get_secure_copilot_user_generated_dir)/indirect-injection-patterns.json"
}

secure_copilot_log_config_error() {
  local log_file="$1"
  local source="$2"
  local message="$3"
  local timestamp

  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if command -v jq >/dev/null 2>&1 && [[ -n "$log_file" ]]; then
    mkdir -p "$(dirname "$log_file")"
    jq -cn \
      --arg timestamp "$timestamp" \
      --arg source "$source" \
      --arg message "$message" \
      '{"timestamp":$timestamp,"event":"configError","source":$source,"message":$message}' \
      >> "$log_file"
  fi

  printf '%s: %s\n' "$source" "$message" >&2
}

secure_copilot_json_is_readable() {
  local json_file="$1"
  [[ -r "$json_file" ]] && jq empty "$json_file" >/dev/null 2>&1
}

# Shared governance context setup used by all hooks.
# Sets: TIMESTAMP, PROJECT_NAME, LOG_DIR, LOG_FILE
# Accepts an optional CWD argument; falls back to $(pwd) when empty so that
# all hooks in the same session resolve to the same project log directory.
setup_governance_audit_log() {
  local cwd="${1:-$(pwd)}"
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  local git_root
  git_root=$(cd "$cwd" && git rev-parse --show-toplevel 2>/dev/null || true)
  PROJECT_NAME=$(basename "${git_root:-$cwd}")

  LOG_DIR="$HOME/progress-ai/secure-copilot/logs/$PROJECT_NAME"
  LOG_FILE="$LOG_DIR/governance-audit.jsonl"
  mkdir -p "$LOG_DIR"
}

# Shared input parsing for preToolUse hooks.
# Reads stdin once, sets: INPUT, TOOL_NAME, CWD, TOOL_ARGS_JSON
parse_tool_hook_input() {
  INPUT=$(cat)
  TOOL_NAME=$(echo "$INPUT" | jq -r '.toolName // "unknown"')
  CWD=$(echo "$INPUT" | jq -r '.cwd // ""')
  TOOL_ARGS_JSON=$(echo "$INPUT" | jq -c '.toolArgs | (if type == "string" then fromjson else . end)' 2>/dev/null || echo '{}')
}
