import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "hooks" / "scripts" / "log_pre_tool_use.py"


def _env(home: Path, *, skip: bool = False) -> dict:
    env = {
        **os.environ,
        "HOME": str(home),
        "CLAUDE_PLUGIN_ROOT": str(PLUGIN_ROOT),
        "PYTHONPATH": str(PLUGIN_ROOT / "hooks" / "scripts"),
    }
    if skip:
        env["SKIP_GOVERNANCE_AUDIT"] = "true"
    else:
        env.pop("SKIP_GOVERNANCE_AUDIT", None)
    return env


def _run(payload, home, *, skip=False):
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=_env(home, skip=skip),
        timeout=10,
    )


def _last_rec(home: Path, cwd: Path) -> dict:
    lf = home / "echo-theory-labs/secure-claude/logs" / cwd.name / "governance-audit.jsonl"
    return json.loads(lf.read_text().strip().splitlines()[-1])


def test_bash_command_logged_with_args(tmp_path):
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": "echo hello"},
    }
    r = _run(payload, tmp_path)
    assert r.returncode == 0, r.stderr
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["event"] == "preToolUse"
    assert rec["tool"] == "Bash"
    assert rec["args"] == {"command": "echo hello"}
    assert "git_branch" in rec
    assert rec["timestamp"].endswith("Z")


def test_bash_long_command_truncated(tmp_path):
    long_cmd = "x" * 300
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": long_cmd},
    }
    r = _run(payload, tmp_path)
    assert r.returncode == 0
    rec = _last_rec(tmp_path, tmp_path)
    cmd_out = rec["args"]["command"]
    assert cmd_out.endswith("[truncated]")
    assert len(cmd_out) <= 215  # 200 + suffix


def test_edit_path_preserved_not_truncated(tmp_path):
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "cwd": str(tmp_path),
        "tool_input": {"file_path": "/a/b/c.py", "old_string": "x", "new_string": "y"},
    }
    r = _run(payload, tmp_path)
    assert r.returncode == 0
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["tool"] == "Edit"
    assert rec["args"]["file_path"] == "/a/b/c.py"


def test_malformed_tool_input_normalized_to_empty(tmp_path):
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": "{malformed",
    }
    r = _run(payload, tmp_path)
    assert r.returncode == 0
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["args"] == {}


def test_git_branch_captured_in_repo(tmp_path):
    # Init a git repo and create a branch so branch detection has something to report
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "checkout", "-b", "feature/test"], cwd=tmp_path, check=True, capture_output=True
    )
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": "ls"},
    }
    r = _run(payload, tmp_path)
    assert r.returncode == 0
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["git_branch"] == "feature/test"


def test_git_branch_unknown_outside_repo(tmp_path):
    # No git init in tmp_path — should fall back to "unknown"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": "ls"},
    }
    r = _run(payload, tmp_path)
    assert r.returncode == 0
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["git_branch"] == "unknown"


def test_skip_flag_bypasses(tmp_path):
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": "rm -rf /"},
    }
    r = _run(payload, tmp_path, skip=True)
    assert r.returncode == 0
    lf = tmp_path / "echo-theory-labs/secure-claude/logs" / tmp_path.name / "governance-audit.jsonl"
    assert not lf.exists()


def test_unknown_tool_still_logged(tmp_path):
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "SomeFutureTool",
        "cwd": str(tmp_path),
        "tool_input": {"foo": "bar"},
    }
    r = _run(payload, tmp_path)
    assert r.returncode == 0
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["tool"] == "SomeFutureTool"
    assert rec["args"] == {"foo": "bar"}
