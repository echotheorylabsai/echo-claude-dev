#!/usr/bin/env python3
"""SubagentStop hook — emit subagentStop audit event."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_claude import env, io_utils, logging_utils, paths


def main() -> int:
    if env.skip_audit():
        return 0
    payload = io_utils.read_stdin_json()
    cwd = payload.get("cwd") or str(Path.cwd())
    lf = paths.log_file(cwd)
    logging_utils.audit_log(
        lf,
        {
            "event": "subagentStop",
            "agent_type": payload.get("agent_type") or "unknown",
            "agent_id": payload.get("agent_id") or "",
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
