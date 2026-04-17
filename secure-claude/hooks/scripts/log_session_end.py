#!/usr/bin/env python3
"""SessionEnd hook — emit summary with total_events and threats_detected."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_claude import env, io_utils, logging_utils, paths

_THREAT_EVENTS = {"threatDetected", "indirectThreatDetected"}


def _count_since_last_session_start(log_file: Path) -> tuple[int, int]:
    if not log_file.exists():
        return 0, 0
    lines = log_file.read_text(encoding="utf-8").splitlines()
    start_idx = -1
    for i in range(len(lines) - 1, -1, -1):
        try:
            rec = json.loads(lines[i])
        except json.JSONDecodeError:
            continue
        if rec.get("event") == "sessionStart":
            start_idx = i
            break
    scope = lines[start_idx + 1 :] if start_idx >= 0 else lines
    total = 0
    threats = 0
    for line in scope:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        if rec.get("event") in _THREAT_EVENTS:
            threats += 1
    return total, threats


def main() -> int:
    if env.skip_audit():
        return 0
    payload = io_utils.read_stdin_json()
    cwd = payload.get("cwd") or str(Path.cwd())
    lf = paths.log_file(cwd)
    total, threats = _count_since_last_session_start(lf)
    logging_utils.audit_log(
        lf, {"event": "sessionEnd", "total_events": total, "threats_detected": threats}
    )
    if threats:
        logging_utils.ui_print(f"⚠️  Session ended: {threats} threat(s) detected in {total} events")
    else:
        logging_utils.ui_print(f"✅ Session ended: {total} events, no threats")
    return 0


if __name__ == "__main__":
    sys.exit(main())
