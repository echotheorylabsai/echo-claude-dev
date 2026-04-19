#!/usr/bin/env python3
"""SessionStart hook — emit sessionStart audit event and UI banner."""

from __future__ import annotations

import sys
from pathlib import Path

# Make the package importable when invoked directly as a hook.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_claude import env, io_utils, logging_utils, paths


def main() -> int:
    if env.skip_audit():
        return 0
    payload = io_utils.read_stdin_json()
    cwd = payload.get("cwd") or str(Path.cwd())
    lf = paths.log_file(cwd)
    logging_utils.audit_log(lf, {"event": "sessionStart", "cwd": cwd})
    logging_utils.ui_print("🛡️  secure-claude governance audit active")
    return 0


if __name__ == "__main__":
    sys.exit(main())
