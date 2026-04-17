#!/usr/bin/env python3
"""PreToolUse hook (enforcement) — deny tool calls matching tool-rules.json.

Fail-closed: if shipped config is unreadable, all tool calls are denied until
the config is restored. The only reliable enforcement point in secure-claude.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_claude import config_loader, env, io_utils, logging_utils, paths
from secure_claude.input_parser import parse_tool_event
from secure_claude.regex_engine import CompileError, compile_rule


def _emit_deny(reason: str) -> None:
    io_utils.write_stdout_json(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    )


def _evaluate(tool_name: str, tool_input: dict, rules: list[dict]) -> tuple[dict | None, str]:
    """Return (matched_rule, reason). Returns (None, "") if no rule matches."""
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if rule.get("action", "deny") != "deny":
            continue
        if rule.get("tool") != tool_name:
            continue
        target_field = rule.get("targetField", "command")
        value = tool_input.get(target_field, "")
        if not isinstance(value, str) or not value:
            continue
        try:
            regex = compile_rule(
                pattern=rule["pattern"],
                engine=rule.get("engine"),
                case_insensitive=bool(rule.get("caseInsensitive", False)),
            )
        except (CompileError, KeyError):
            continue
        if regex.search(value):
            reason = rule.get("reason", "Blocked by governance policy").replace("{value}", value)
            return rule, reason
    return None, ""


def main() -> int:
    if env.skip_audit():
        return 0
    payload = io_utils.read_stdin_json()
    ev = parse_tool_event(payload)
    cwd = ev.cwd or str(Path.cwd())
    lf = paths.log_file(cwd)
    root = paths.plugin_root()
    local = paths.local_tool_rules_json()

    try:
        rules = config_loader.load_rules(
            shipped=paths.shipped_tool_rules_json(root),
            local=local if local.exists() else None,
            on_local_error=lambda msg: logging_utils.config_error(
                lf, source="gate-pre-tool-use", message=msg
            ),
        )
    except config_loader.ShippedConfigUnreadable as e:
        logging_utils.config_error(
            lf,
            source="gate-pre-tool-use",
            message=f"shipped tool-rules unreadable: {e}",
        )
        reason = "Governance config unavailable — failing closed"
        logging_utils.audit_log(
            lf,
            {
                "event": "preToolDecision",
                "tool": ev.tool_name,
                "decision": "deny",
                "reason": reason,
            },
        )
        _emit_deny(reason)
        return 0

    _, reason = _evaluate(ev.tool_name, ev.tool_input, rules)
    if reason:
        logging_utils.audit_log(
            lf,
            {
                "event": "preToolDecision",
                "tool": ev.tool_name,
                "decision": "deny",
                "reason": reason,
            },
        )
        _emit_deny(reason)
        return 0

    logging_utils.audit_log(
        lf,
        {"event": "preToolDecision", "tool": ev.tool_name, "decision": "allow", "reason": ""},
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
