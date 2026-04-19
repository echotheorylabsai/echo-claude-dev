"""Path resolution for secure-claude plugin."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]")


def _sanitize(name: str) -> str:
    cleaned = _SAFE_NAME_RE.sub("_", name).strip("._") or "unknown"
    return cleaned[:128]


def _home() -> Path:
    raw = os.environ.get("HOME") or ""
    return Path(raw) if raw else Path.home()


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
            return _sanitize(Path(out.stdout.strip()).name)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return _sanitize(Path(cwd).name)


def log_dir(cwd: str) -> Path:
    return _home() / "echo-theory-labs" / "secure-claude" / "logs" / project_name(cwd)


def log_file(cwd: str) -> Path:
    return log_dir(cwd) / "governance-audit.jsonl"


def local_override_dir() -> Path:
    return _home() / ".config" / "secure-claude"


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
