#!/bin/bash
#
# common-scanner.sh — Shared scanning, evidence assembly, and threat logging
# for scan-prompt-injection.sh and scan-post-tool-injection.sh.
#
# Callers MUST set these variables before invoking functions:
#   SCAN_TEXT        — the text to scan (prompt or tool output)
#   SCAN_SOURCE      — label for log messages (e.g., "scan-prompt-injection")
#   THREATS_FOUND    — initialized as empty array: THREATS_FOUND=()
#   LOG_FILE         — path to governance-audit.jsonl (from setup_governance_audit_log)
#   TIMESTAMP        — ISO 8601 timestamp (from setup_governance_audit_log)
# ── Pattern matching ──────────────────────────────────────────────────────────
# Checks a single rule pattern against SCAN_TEXT. Supports both POSIX (grep -E)
# and PCRE (perl) engines. On match, appends tab-delimited evidence to
# THREATS_FOUND array.

check_pattern() {
  local pattern="$1"
  local category="$2"
  local severity="$3"
  local description="$4"
  local case_insensitive="$5"
  local engine="${6:-posix}"

  if [[ "$engine" == "pcre" ]]; then
    if ! command -v perl >/dev/null 2>&1; then
      if [[ -z "${_PCRE_WARNED:-}" ]]; then
        _PCRE_WARNED=1
        secure_copilot_log_config_error "$LOG_FILE" "$SCAN_SOURCE" \
          "perl not available; skipping PCRE patterns"
      fi
      return
    fi

    local perl_flags=""
    if [[ "$case_insensitive" == "true" ]]; then
      perl_flags="i"
    fi

    if printf '%s\n' "$SCAN_TEXT" | perl -ne "print if m{$pattern}$perl_flags" 2>/dev/null | head -1 | grep -q .; then
      local evidence
      evidence=$(printf '%s\n' "$SCAN_TEXT" | perl -ne "if (m{$pattern}$perl_flags) { print \$&; exit }" 2>/dev/null || true)
      local evidence_encoded
      evidence_encoded=$(printf '%s' "$evidence" | base64 | tr -d '\n')
      THREATS_FOUND+=("$category"$'\t'"$severity"$'\t'"$description"$'\t'"$evidence_encoded")
    fi
    return
  fi

  local detect_args=(-qE)
  local extract_args=(-oE)

  if [[ "$case_insensitive" == "true" ]]; then
    detect_args=(-qiE)
    extract_args=(-oiE)
  fi

  if printf '%s\n' "$SCAN_TEXT" | grep "${detect_args[@]}" "$pattern"; then
    local evidence
    evidence=$(printf '%s\n' "$SCAN_TEXT" | grep "${extract_args[@]}" "$pattern" | head -1 || true)
    local evidence_encoded
    evidence_encoded=$(printf '%s' "$evidence" | base64 | tr -d '\n')
    THREATS_FOUND+=("$category"$'\t'"$severity"$'\t'"$description"$'\t'"$evidence_encoded")
  fi
}

# ── Rule iteration ────────────────────────────────────────────────────────────
# Reads a generated JSON rule file and calls check_pattern for each enabled rule.

scan_rules_from_json() {
  local json_file="$1"
  local rule

  while IFS= read -r rule; do
    local pattern category severity description case_insensitive engine

    pattern=$(printf '%s' "$rule" | jq -r '.pattern')
    category=$(printf '%s' "$rule" | jq -r '.category')
    severity=$(printf '%s' "$rule" | jq -r '.severity | tostring')
    description=$(printf '%s' "$rule" | jq -r '.description')
    case_insensitive=$(printf '%s' "$rule" | jq -r '.caseInsensitive')
    engine=$(printf '%s' "$rule" | jq -r '.engine // "posix"')

    check_pattern "$pattern" "$category" "$severity" "$description" "$case_insensitive" "$engine"
  done < <(jq -c '.[] | select(.enabled == true)' "$json_file")
}

# ── Threat assembly and logging ───────────────────────────────────────────────
# Assembles THREATS_FOUND into a JSON array, logs to the audit file, prints
# user-facing summary, and exits non-zero as an audit signal when threats exist.
#
# Arguments:
#   $1 — event name for log: "threatDetected" or "indirectThreatDetected"
#   $2 — user-facing label: "Governance" or "Indirect injection"
#   $3 — clean event name: "promptScanned" or "postToolScanned"
#   $4 — audit message (e.g., "Prompt flagged by governance audit")
#   $5 — optional tool name (empty for prompt scan, tool name for post-tool)

assemble_and_log_threats() {
  local event_name="$1"
  local label="$2"
  local clean_event="$3"
  local block_message="$4"
  local tool_name="${5:-}"

  if [[ ${#THREATS_FOUND[@]} -gt 0 ]]; then
    local THREATS_JSON="["
    local FIRST=true
    local MAX_SEVERITY="0.0"
    echo "⚠️ $label: ${#THREATS_FOUND[@]} threat signal(s) detected${tool_name:+ in tool output}"
    for threat in "${THREATS_FOUND[@]}"; do
      IFS=$'\t' read -r category severity description evidence_encoded <<< "$threat"
      evidence=$(printf '%s' "$evidence_encoded" | base64 -D 2>/dev/null || printf '%s' "$evidence_encoded" | base64 -d 2>/dev/null || echo "[redacted]")

      if [[ "$FIRST" != "true" ]]; then
        THREATS_JSON+=","
      fi
      FIRST=false

      THREATS_JSON+=$(jq -cn \
        --arg cat "$category" \
        --arg sev "$severity" \
        --arg desc "$description" \
        --arg ev "$evidence" \
        '{"category":$cat,"severity":($sev|tonumber),"description":$desc,"evidence":$ev}')

      if awk "BEGIN{exit !(($severity+0) > ($MAX_SEVERITY+0))}"; then
        MAX_SEVERITY="$severity"
      fi

      echo "  🔴 [$category] $description (severity: $severity)"
    done
    THREATS_JSON+="]"

    local jq_args=(
      --arg timestamp "$TIMESTAMP"
      --arg max_severity "$MAX_SEVERITY"
      --argjson threats "$THREATS_JSON"
      --argjson count "${#THREATS_FOUND[@]}"
    )
    local jq_template='{"timestamp":$timestamp,"event":"'"$event_name"'","threat_count":$count,"max_severity":($max_severity|tonumber),"threats":$threats}'

    if [[ -n "$tool_name" ]]; then
      jq_args+=(--arg tool "$tool_name")
      jq_template='{"timestamp":$timestamp,"event":"'"$event_name"'","tool":$tool,"threat_count":$count,"max_severity":($max_severity|tonumber),"threats":$threats}'
    fi

    jq -cn "${jq_args[@]}" "$jq_template" >> "$LOG_FILE"

    echo "(max severity: $MAX_SEVERITY)"

    # Copilot CLI does not currently enforce scanner exit codes. Keep a non-zero
    # exit as an audit signal until enforcement can move to a supported hook path.
    echo "🚫 $block_message"
    exit 1
  else
    local jq_args=(
      --arg timestamp "$TIMESTAMP"
    )
    local jq_template='{"timestamp":$timestamp,"event":"'"$clean_event"'","status":"clean"}'

    if [[ -n "$tool_name" ]]; then
      jq_args+=(--arg tool "$tool_name")
      jq_template='{"timestamp":$timestamp,"event":"'"$clean_event"'","tool":$tool,"status":"clean"}'
    fi

    jq -cn "${jq_args[@]}" "$jq_template" >> "$LOG_FILE"
  fi
}
