#!/usr/bin/env python3
"""UserPromptSubmit hook — scan prompt for threat signals."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_claude import config_loader, env, io_utils, logging_utils, paths, scanner
from secure_claude.input_parser import extract_user_prompt


def main() -> int:
    if env.skip_audit():
        return 0
    payload = io_utils.read_stdin_json()
    cwd = payload.get("cwd") or str(Path.cwd())
    prompt = extract_user_prompt(payload)
    lf = paths.log_file(cwd)
    root = paths.plugin_root()

    local = paths.local_prompt_threats_json()
    try:
        rules = config_loader.load_rules(
            shipped=paths.shipped_prompt_threats_json(root),
            local=local if local.exists() else None,
            on_local_error=lambda msg: logging_utils.config_error(
                lf, source="scan-prompt-injection", message=msg
            ),
        )
    except config_loader.ShippedConfigUnreadable as e:
        logging_utils.config_error(
            lf,
            source="scan-prompt-injection",
            message=f"shipped prompt config unreadable: {e}",
        )
        return 0  # audit-only; do not block prompts on config failure

    threats = scanner.scan_text(text=prompt, rules=config_loader.filter_enabled(rules))
    if not threats:
        logging_utils.audit_log(lf, {"event": "promptScanned", "status": "clean"})
        return 0

    max_sev = scanner.max_severity(threats)
    logging_utils.audit_log(
        lf,
        {
            "event": "threatDetected",
            "threat_count": len(threats),
            "max_severity": max_sev,
            "threats": scanner.threats_to_json(threats),
        },
    )
    logging_utils.ui_print(
        f"⚠️  Governance: {len(threats)} threat signal(s) detected (max severity {max_sev})"
    )
    for t in threats:
        logging_utils.ui_print(f"  🔴 [{t.category}] {t.description} (severity: {t.severity})")
    logging_utils.ui_print("🚫 Prompt flagged by governance audit")
    return 2  # Claude Code: exit 2 blocks the prompt + feeds stderr to the model


if __name__ == "__main__":
    sys.exit(main())
