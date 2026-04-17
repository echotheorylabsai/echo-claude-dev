import json
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
COMPILE = PLUGIN_ROOT / "hooks" / "scripts" / "compile_config.py"
GENERATED = PLUGIN_ROOT / "hooks" / "config" / "generated"


def run_compile(args, env=None):
    return subprocess.run(
        [sys.executable, str(COMPILE), *args],
        cwd=PLUGIN_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def test_compile_shipped_produces_three_valid_rule_packs():
    result = run_compile(["--mode", "shipped"])
    assert result.returncode == 0, f"stderr: {result.stderr}"
    for name in (
        "user-prompt-threats.json",
        "tool-rules.json",
        "indirect-injection-patterns.json",
    ):
        data = json.loads((GENERATED / name).read_text())
        assert isinstance(data, list)
        assert data, f"{name} is empty"
        for rule in data:
            assert "id" in rule
            assert "pattern" in rule


def test_tool_rules_use_claude_code_tool_names():
    rules = json.loads((GENERATED / "tool-rules.json").read_text())
    tools_seen = {r["tool"] for r in rules}
    # Must be subset of Claude Code tool names
    assert tools_seen.issubset({"Bash", "Edit", "Write", "NotebookEdit"})
    # Must include at least Bash, Edit, Write
    assert {"Bash", "Edit", "Write"}.issubset(tools_seen)


def test_tool_rules_shipped_ids_are_unique():
    rules = json.loads((GENERATED / "tool-rules.json").read_text())
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))


def test_prompt_threats_ids_are_unique():
    rules = json.loads((GENERATED / "user-prompt-threats.json").read_text())
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))


def test_indirect_patterns_ids_are_unique():
    rules = json.loads((GENERATED / "indirect-injection-patterns.json").read_text())
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))


def test_overrides_reject_shipped_id_collision(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    override_dir = tmp_path / ".config" / "secure-claude"
    override_dir.mkdir(parents=True)
    # Get a shipped tool-rule id to clash against
    shipped_rules = json.loads((GENERATED / "tool-rules.json").read_text())
    shipped_id = shipped_rules[0]["id"]
    (override_dir / "overrides.yaml").write_text(
        f"toolRules:\n"
        f"  - id: {shipped_id}\n"
        f"    tool: Bash\n"
        f"    targetField: command\n"
        f"    pattern: 'x'\n"
        f"    reason: 'y'\n"
    )
    env = {**__import__("os").environ, "HOME": str(tmp_path)}
    result = run_compile(["--mode", "overrides"], env=env)
    assert result.returncode != 0
    # Error message should mention the colliding id somewhere
    combined = (result.stdout + result.stderr).lower()
    assert shipped_id.lower() in combined or "collision" in combined or "shipped" in combined


def test_tool_rules_target_fields_match_claude_code_schemas():
    rules = json.loads((GENERATED / "tool-rules.json").read_text())
    expected = {
        "Bash": "command",
        "Edit": "file_path",
        "Write": "file_path",
        "NotebookEdit": "notebook_path",
    }
    for r in rules:
        assert r["targetField"] == expected[r["tool"]], (
            f"rule {r['id']} tool={r['tool']} targetField={r['targetField']} "
            f"expected {expected[r['tool']]}"
        )


def test_overrides_accept_new_id(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    override_dir = tmp_path / ".config" / "secure-claude"
    override_dir.mkdir(parents=True)
    (override_dir / "overrides.yaml").write_text(
        "toolRules:\n"
        "  - id: custom-new-abcdefg\n"  # unique id, very unlikely to collide
        "    tool: Bash\n"
        "    targetField: command\n"
        "    pattern: 'zzzznewpattern'\n"
        "    reason: 'custom'\n"
    )
    env = {**__import__("os").environ, "HOME": str(tmp_path)}
    result = run_compile(["--mode", "overrides"], env=env)
    assert result.returncode == 0, f"stderr: {result.stderr}"
