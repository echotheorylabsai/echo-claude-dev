import subprocess

from secure_claude import paths


def test_plugin_root_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
    assert paths.plugin_root() == tmp_path


def test_plugin_root_fallback(monkeypatch):
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    assert paths.plugin_root().name == "secure-claude"


def test_log_file_path(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    lf = paths.log_file(cwd=str(tmp_path))
    assert lf.name == "governance-audit.jsonl"
    assert "progress-ai/secure-claude/logs" in str(lf)


def test_project_name_from_git(tmp_path, monkeypatch):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    monkeypatch.chdir(tmp_path)
    assert paths.project_name(str(tmp_path)) == tmp_path.name


def test_project_name_fallback_to_cwd_basename(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert paths.project_name(str(tmp_path)) == tmp_path.name


def test_shipped_config_paths():
    root = paths.plugin_root()
    assert paths.shipped_prompt_threats_json(root).name == "user-prompt-threats.json"
    assert paths.shipped_tool_rules_json(root).name == "tool-rules.json"
    assert paths.shipped_indirect_patterns_json(root).name == "indirect-injection-patterns.json"


def test_local_override_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    d = paths.local_override_dir()
    assert str(d).endswith(".config/secure-claude")
