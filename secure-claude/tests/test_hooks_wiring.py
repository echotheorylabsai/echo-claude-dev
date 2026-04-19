import json
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
HOOKS_JSON = PLUGIN_ROOT / "hooks" / "hooks.json"


def _load():
    return json.loads(HOOKS_JSON.read_text())


def test_hooks_json_parses():
    cfg = _load()
    assert "hooks" in cfg


def test_all_expected_events_wired():
    cfg = _load()
    expected = {
        "SessionStart",
        "SessionEnd",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "SubagentStop",
        "PreCompact",
        "Notification",
        "Stop",
    }
    assert expected.issubset(set(cfg["hooks"].keys()))


def test_pre_tool_use_chain_has_log_then_gate():
    cfg = _load()
    pt = cfg["hooks"]["PreToolUse"]
    assert len(pt) >= 1
    cmds = [h["command"] for entry in pt for h in entry["hooks"]]
    assert any("log_pre_tool_use.py" in c for c in cmds)
    assert any("gate_pre_tool_use.py" in c for c in cmds)
    # log should come before gate within the same matcher entry
    # Find the PreToolUse matcher entry that contains both
    for entry in pt:
        entry_cmds = [h["command"] for h in entry["hooks"]]
        if any("log_pre_tool_use.py" in c for c in entry_cmds) and any(
            "gate_pre_tool_use.py" in c for c in entry_cmds
        ):
            log_idx = next(i for i, c in enumerate(entry_cmds) if "log_pre_tool_use.py" in c)
            gate_idx = next(i for i, c in enumerate(entry_cmds) if "gate_pre_tool_use.py" in c)
            assert log_idx < gate_idx, "log_pre_tool_use must run before gate_pre_tool_use"
            break


def test_pre_tool_use_matcher_covers_bash_edit_write_notebookedit():
    cfg = _load()
    pt = cfg["hooks"]["PreToolUse"]
    matchers = [entry.get("matcher", "") for entry in pt]
    combined = "|".join(matchers)
    for tool in ("Bash", "Edit", "Write", "NotebookEdit"):
        assert tool in combined, f"PreToolUse matcher does not reference {tool}: {matchers}"


def test_post_tool_use_matcher_reasonable():
    cfg = _load()
    pt = cfg["hooks"]["PostToolUse"]
    matchers = [entry.get("matcher", "") for entry in pt]
    combined = "|".join(matchers)
    # At least cover the same tools + Read/WebFetch (which can surface injected content)
    for tool in ("Bash", "Edit", "Write", "Read", "WebFetch"):
        assert tool in combined


def test_session_start_matcher_covers_startup_resume_clear():
    cfg = _load()
    entries = cfg["hooks"]["SessionStart"]
    matchers = [e.get("matcher", "") for e in entries]
    combined = "|".join(matchers)
    for src in ("startup", "resume", "clear"):
        assert src in combined


def test_pre_compact_matcher_covers_manual_auto():
    cfg = _load()
    entries = cfg["hooks"]["PreCompact"]
    matchers = [e.get("matcher", "") for e in entries]
    combined = "|".join(matchers)
    for trig in ("manual", "auto"):
        assert trig in combined


def test_notification_matches_permission_prompt():
    cfg = _load()
    entries = cfg["hooks"]["Notification"]
    matchers = [e.get("matcher", "") for e in entries]
    combined = "|".join(matchers)
    assert "permission_prompt" in combined


def test_commands_use_claude_plugin_root_variable():
    raw = HOOKS_JSON.read_text()
    assert "${CLAUDE_PLUGIN_ROOT}" in raw


def test_commands_use_uv_run():
    """All hook commands must invoke uv run to ensure pinned interpreter/deps."""
    cfg = _load()
    for event, entries in cfg["hooks"].items():
        for entry in entries:
            for h in entry["hooks"]:
                assert h["type"] == "command", f"{event}: all hooks must be type=command"
                assert "uv run" in h["command"], f"{event}: command missing uv run: {h['command']}"


def test_all_hook_scripts_referenced_actually_exist():
    cfg = _load()
    for event, entries in cfg["hooks"].items():
        for entry in entries:
            for h in entry["hooks"]:
                cmd = h["command"]
                # Find the .py file path in the command
                for token in cmd.split():
                    if token.endswith(".py"):
                        # Resolve ${CLAUDE_PLUGIN_ROOT} → PLUGIN_ROOT for this check
                        path_str = token.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT))
                        assert Path(path_str).exists(), f"{event}: script not found: {token}"


def test_timeouts_present_and_sane():
    cfg = _load()
    for event, entries in cfg["hooks"].items():
        for entry in entries:
            for h in entry["hooks"]:
                assert "timeout" in h, f"{event}: hook missing timeout"
                t = h["timeout"]
                assert isinstance(t, int) and 1 <= t <= 60, f"{event}: unreasonable timeout: {t}"
