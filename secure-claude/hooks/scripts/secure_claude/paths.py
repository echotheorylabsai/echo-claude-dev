"""Path resolution for secure-claude plugin."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def plugin_root() -> Path:
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if env:
        return Path(env)
    # hooks/scripts/secure_claude/paths.py → up 3 levels = secure-claude/
    return Path(__file__).resolve().parents[3]


def project_name(cwd: str) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip()).name
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return Path(cwd).name


def log_dir(cwd: str) -> Path:
    home = Path(os.environ.get("HOME", os.path.expanduser("~")))
    return home / "progress-ai" / "secure-claude" / "logs" / project_name(cwd)


def log_file(cwd: str) -> Path:
    return log_dir(cwd) / "governance-audit.jsonl"


def local_override_dir() -> Path:
    home = Path(os.environ.get("HOME", os.path.expanduser("~")))
    return home / ".config" / "secure-claude"


def shipped_prompt_threats_json(root: Path) -> Path:
    return root / "hooks" / "config" / "generated" / "user-prompt-threats.json"


def shipped_tool_rules_json(root: Path) -> Path:
    return root / "hooks" / "config" / "generated" / "tool-rules.json"


def shipped_indirect_patterns_json(root: Path) -> Path:
    return root / "hooks" / "config" / "generated" / "indirect-injection-patterns.json"


def local_prompt_threats_json() -> Path:
    return local_override_dir() / "generated" / "user-prompt-threats.json"


def local_tool_rules_json() -> Path:
    return local_override_dir() / "generated" / "tool-rules.json"


def local_indirect_patterns_json() -> Path:
    return local_override_dir() / "generated" / "indirect-injection-patterns.json"
