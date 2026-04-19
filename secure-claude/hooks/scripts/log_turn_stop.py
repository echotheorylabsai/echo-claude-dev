#!/usr/bin/env python3
"""Stop hook — emit turnStop audit event.

IMPORTANT: This hook must produce NO stdout and always exit 0.
Claude Code's Stop hook can return {"decision":"block"} to force continuation;
we deliberately do not do that — audit only.
"""

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
    logging_utils.audit_log(lf, {"event": "turnStop"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
