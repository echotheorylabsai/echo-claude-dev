import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "hooks" / "scripts" / "log_session_end.py"


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


def _run(stdin_obj: dict, home: Path, *, skip: bool = False):
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(stdin_obj),
        capture_output=True,
        text=True,
        env=_env(home, skip=skip),
        timeout=5,
    )


def _log_path(home: Path, cwd: Path) -> Path:
    return home / "progress-ai/secure-claude/logs" / cwd.name / "governance-audit.jsonl"


def _write_log(home: Path, cwd: Path, records: list[dict]) -> Path:
    lf = _log_path(home, cwd)
    lf.parent.mkdir(parents=True, exist_ok=True)
    lf.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return lf


def test_session_end_counts_events_since_last_session_start(tmp_path):
    cwd = tmp_path
    _write_log(
        tmp_path,
        cwd,
        [
            {"event": "sessionStart", "cwd": str(cwd), "timestamp": "2026-04-17T00:00:00Z"},
            {"event": "promptScanned", "status": "clean", "timestamp": "2026-04-17T00:00:01Z"},
            {
                "event": "threatDetected",
                "threat_count": 1,
                "max_severity": 0.9,
                "threats": [],
                "timestamp": "2026-04-17T00:00:02Z",
            },
            {
                "event": "preToolUse",
                "tool": "Bash",
                "git_branch": "x",
                "args": {},
                "timestamp": "2026-04-17T00:00:03Z",
            },
            {
                "event": "indirectThreatDetected",
                "tool": "Bash",
                "threat_count": 1,
                "max_severity": 0.9,
                "threats": [],
                "timestamp": "2026-04-17T00:00:04Z",
            },
        ],
    )
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path)
    assert r.returncode == 0, r.stderr
    last = json.loads(_log_path(tmp_path, cwd).read_text().strip().splitlines()[-1])
    assert last["event"] == "sessionEnd"
    assert last["total_events"] == 4
    assert last["threats_detected"] == 2


def test_session_end_only_counts_most_recent_session(tmp_path):
    cwd = tmp_path
    _write_log(
        tmp_path,
        cwd,
        [
            # First session — should be ignored
            {"event": "sessionStart", "cwd": str(cwd), "timestamp": "2026-04-16T00:00:00Z"},
            {"event": "threatDetected", "timestamp": "2026-04-16T00:00:01Z"},
            {
                "event": "sessionEnd",
                "total_events": 1,
                "threats_detected": 1,
                "timestamp": "2026-04-16T00:00:02Z",
            },
            # Second session — current
            {"event": "sessionStart", "cwd": str(cwd), "timestamp": "2026-04-17T00:00:00Z"},
            {"event": "promptScanned", "status": "clean", "timestamp": "2026-04-17T00:00:01Z"},
        ],
    )
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path)
    assert r.returncode == 0
    last = json.loads(_log_path(tmp_path, cwd).read_text().strip().splitlines()[-1])
    assert last["total_events"] == 1  # only promptScanned from most recent session
    assert last["threats_detected"] == 0


def test_session_end_no_prior_session_start_counts_all(tmp_path):
    cwd = tmp_path
    _write_log(
        tmp_path,
        cwd,
        [
            {"event": "promptScanned", "status": "clean", "timestamp": "2026-04-17T00:00:01Z"},
            {"event": "threatDetected", "timestamp": "2026-04-17T00:00:02Z"},
        ],
    )
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path)
    assert r.returncode == 0
    last = json.loads(_log_path(tmp_path, cwd).read_text().strip().splitlines()[-1])
    assert last["total_events"] == 2
    assert last["threats_detected"] == 1


def test_session_end_no_log_file_yet(tmp_path):
    cwd = tmp_path
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path)
    assert r.returncode == 0
    # Log file is created by audit_log; should contain one sessionEnd record with zeros
    last = json.loads(_log_path(tmp_path, cwd).read_text().strip().splitlines()[-1])
    assert last["event"] == "sessionEnd"
    assert last["total_events"] == 0
    assert last["threats_detected"] == 0


def test_session_end_ui_message_on_clean_session(tmp_path, capsys):
    cwd = tmp_path
    _write_log(
        tmp_path,
        cwd,
        [
            {"event": "sessionStart", "timestamp": "2026-04-17T00:00:00Z"},
            {"event": "promptScanned", "status": "clean", "timestamp": "2026-04-17T00:00:01Z"},
        ],
    )
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path)
    assert r.returncode == 0
    assert "no threats" in r.stderr.lower() or "1 event" in r.stderr.lower()


def test_session_end_ui_message_on_dirty_session(tmp_path):
    cwd = tmp_path
    _write_log(
        tmp_path,
        cwd,
        [
            {"event": "sessionStart", "timestamp": "2026-04-17T00:00:00Z"},
            {"event": "threatDetected", "timestamp": "2026-04-17T00:00:01Z"},
        ],
    )
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path)
    assert r.returncode == 0
    assert "threat" in r.stderr.lower()


def test_session_end_skip_flag_noop(tmp_path):
    cwd = tmp_path
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path, skip=True)
    assert r.returncode == 0
    # No log file created when skip flag is set
    assert not _log_path(tmp_path, cwd).exists()


def test_session_end_handles_corrupt_jsonl_lines(tmp_path):
    cwd = tmp_path
    lf = _log_path(tmp_path, cwd)
    lf.parent.mkdir(parents=True)
    lf.write_text(
        json.dumps({"event": "sessionStart", "timestamp": "2026-04-17T00:00:00Z"}) + "\n"
        "THIS IS NOT JSON\n" + json.dumps({"event": "promptScanned"}) + "\n"
    )
    r = _run({"hook_event_name": "SessionEnd", "cwd": str(cwd)}, tmp_path)
    assert r.returncode == 0, r.stderr
    last = json.loads(lf.read_text().strip().splitlines()[-1])
    # Corrupt line skipped; only the valid promptScanned counted
    assert last["total_events"] == 1
