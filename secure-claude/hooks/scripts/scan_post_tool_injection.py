#!/usr/bin/env python3
"""PostToolUse hook — scan tool output for indirect prompt injection.

Audit-only: exit code is always 0; Claude Code cannot undo a completed tool call.
A detected threat is surfaced to operators via the JSONL audit log, not by blocking.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_claude import config_loader, env, io_utils, logging_utils, paths, scanner
from secure_claude.input_parser import extract_post_tool_text, parse_tool_event

_MIN_TEXT_LEN = 10


def main() -> int:
    if env.skip_audit():
        return 0
    payload = io_utils.read_stdin_json()
    ev = parse_tool_event(payload)
    cwd = ev.cwd or str(Path.cwd())
    lf = paths.log_file(cwd)
    text = extract_post_tool_text(payload)

    if len(text) < _MIN_TEXT_LEN:
        logging_utils.audit_log(
            lf, {"event": "postToolScanned", "tool": ev.tool_name, "status": "clean"}
        )
        return 0

    root = paths.plugin_root()
    local = paths.local_indirect_patterns_json()
    try:
        rules = config_loader.load_rules(
            shipped=paths.shipped_indirect_patterns_json(root),
            local=local if local.exists() else None,
            on_local_error=lambda msg: logging_utils.config_error(
                lf, source="scan-post-tool-injection", message=msg
            ),
        )
    except config_loader.ShippedConfigUnreadable as e:
        logging_utils.config_error(
            lf,
            source="scan-post-tool-injection",
            message=f"shipped indirect config unreadable: {e}",
        )
        return 0

    threats = scanner.scan_text(text=text, rules=config_loader.filter_enabled(rules))
    if not threats:
        logging_utils.audit_log(
            lf, {"event": "postToolScanned", "tool": ev.tool_name, "status": "clean"}
        )
        return 0

    logging_utils.audit_log(
        lf,
        {
            "event": "indirectThreatDetected",
            "tool": ev.tool_name,
            "threat_count": len(threats),
            "max_severity": scanner.max_severity(threats),
            "threats": scanner.threats_to_json(threats),
        },
    )
    logging_utils.ui_print(
        f"⚠️  Indirect injection: {len(threats)} signal(s) in {ev.tool_name} output"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
