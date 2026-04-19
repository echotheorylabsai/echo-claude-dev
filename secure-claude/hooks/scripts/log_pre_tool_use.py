#!/usr/bin/env python3
"""PreToolUse hook (audit) — log every tool invocation attempt.

This is the audit hook in the PreToolUse chain — it never blocks.
The enforcement gate (gate_pre_tool_use.py) runs separately.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_claude import env, io_utils, logging_utils, paths
from secure_claude.input_parser import parse_tool_event

_BASH_CMD_TRUNCATE = 200


def _git_branch(cwd: str) -> str:
    try:
        r = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
        )
        return r.stdout.strip() or "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def _truncate_bash_command(args: dict) -> dict:
    out = dict(args)
    cmd = out.get("command")
    if isinstance(cmd, str) and len(cmd) > _BASH_CMD_TRUNCATE:
        out["command"] = cmd[:_BASH_CMD_TRUNCATE] + "... [truncated]"
    return out


def main() -> int:
    if env.skip_audit():
        return 0
    payload = io_utils.read_stdin_json()
    ev = parse_tool_event(payload)
    cwd = ev.cwd or str(Path.cwd())
    args = _truncate_bash_command(ev.tool_input) if ev.tool_name == "Bash" else ev.tool_input
    logging_utils.audit_log(
        paths.log_file(cwd),
        {
            "event": "preToolUse",
            "tool": ev.tool_name,
            "git_branch": _git_branch(cwd),
            "args": args,
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
