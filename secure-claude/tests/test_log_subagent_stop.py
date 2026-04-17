import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "hooks" / "scripts" / "log_subagent_stop.py"


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


def test_writes_agent_type_and_id(tmp_path):
    r = _run(
        {"cwd": str(tmp_path), "agent_type": "orchestrator", "agent_id": "abc-123"},
        tmp_path,
    )
    assert r.returncode == 0, r.stderr
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["event"] == "subagentStop"
    assert rec["agent_type"] == "orchestrator"
    assert rec["agent_id"] == "abc-123"


def test_missing_fields_use_defaults(tmp_path):
    r = _run({"cwd": str(tmp_path)}, tmp_path)
    assert r.returncode == 0, r.stderr
    rec = _last_rec(tmp_path, tmp_path)
    assert rec["agent_type"] == "unknown"
    assert rec["agent_id"] == ""


def test_skip_flag_no_log(tmp_path):
    r = _run({"cwd": str(tmp_path), "agent_type": "x"}, tmp_path, skip=True)
    assert r.returncode == 0
    lf = tmp_path / "progress-ai/secure-claude/logs" / tmp_path.name / "governance-audit.jsonl"
    assert not lf.exists()


def test_exits_0_no_stdout(tmp_path):
    r = _run({"cwd": str(tmp_path), "agent_type": "worker", "agent_id": "w1"}, tmp_path)
    assert r.returncode == 0
    assert r.stdout == ""
