import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "hooks" / "scripts" / "log_turn_stop.py"


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
        timeout=5,
    )


def _last_rec(home, cwd):
    lf = home / "progress-ai/secure-claude/logs" / cwd.name / "governance-audit.jsonl"
    return json.loads(lf.read_text().strip().splitlines()[-1])


def test_logs_turn_stop_event(tmp_path):
    r = _run({"cwd": str(tmp_path)}, tmp_path)
    assert r.returncode == 0, r.stderr
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["event"] == "turnStop"


def test_exits_0_with_empty_stdout(tmp_path):
    r = _run({"cwd": str(tmp_path)}, tmp_path)
    assert r.returncode == 0
    # Must NOT emit any JSON to stdout (no {"decision":"block"} or anything else)
    assert r.stdout == ""


def test_skip_flag_no_log(tmp_path):
    r = _run({"cwd": str(tmp_path)}, tmp_path, skip=True)
    assert r.returncode == 0
    lf = tmp_path / "progress-ai/secure-claude/logs" / tmp_path.name / "governance-audit.jsonl"
    assert not lf.exists()


def test_empty_stdin_succeeds(tmp_path):
    r = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input="",
        capture_output=True,
        text=True,
        env=_env(tmp_path),
        timeout=5,
    )
    assert r.returncode == 0
    assert r.stdout == ""
