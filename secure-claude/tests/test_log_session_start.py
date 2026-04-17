import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "hooks" / "scripts" / "log_session_start.py"


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


def _log_path(home: Path, cwd: Path) -> Path:
    return home / "progress-ai/secure-claude/logs" / cwd.name / "governance-audit.jsonl"


def test_session_start_writes_jsonl_record(tmp_path):
    r = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(
            {"hook_event_name": "SessionStart", "source": "startup", "cwd": str(tmp_path)}
        ),
        capture_output=True,
        text=True,
        env=_env(tmp_path),
    )
    assert r.returncode == 0, r.stderr
    log = _log_path(tmp_path, tmp_path)
    assert log.exists()
    rec = json.loads(log.read_text().strip())
    assert rec["event"] == "sessionStart"
    assert rec["cwd"] == str(tmp_path)
    assert rec["timestamp"].endswith("Z")


def test_session_start_prints_banner_to_stderr(tmp_path):
    r = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps({"hook_event_name": "SessionStart", "cwd": str(tmp_path)}),
        capture_output=True,
        text=True,
        env=_env(tmp_path),
    )
    assert r.returncode == 0
    # Banner should mention governance/secure-claude; we don't pin exact wording
    assert "secure-claude" in r.stderr.lower() or "governance" in r.stderr.lower()


def test_session_start_skip_when_flag_set(tmp_path):
    r = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps({"hook_event_name": "SessionStart", "cwd": str(tmp_path)}),
        capture_output=True,
        text=True,
        env=_env(tmp_path, skip=True),
    )
    assert r.returncode == 0
    log = _log_path(tmp_path, tmp_path)
    assert not log.exists()


def test_session_start_no_stdin_still_succeeds(tmp_path):
    # Hook invoked without piped input (e.g., dev-run) — should not hang or crash
    r = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input="",
        capture_output=True,
        text=True,
        env=_env(tmp_path),
        timeout=5,
    )
    assert r.returncode == 0
    # With empty stdin, cwd falls back to Path.cwd() — log will be under tmp_path basename if cwd is set,
    # else under os.getcwd() basename. Either way, exit 0 is the contract.
