from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
README = PLUGIN_ROOT / "README.md"


def test_readme_exists():
    assert README.exists()


def test_readme_mentions_marketplace_name():
    assert "echo-theory-labs" in README.read_text()


def test_readme_documents_all_hook_scripts():
    content = README.read_text()
    for hook in [
        "log_session_start.py",
        "log_session_end.py",
        "scan_prompt_injection.py",
        "log_pre_tool_use.py",
        "gate_pre_tool_use.py",
        "scan_post_tool_injection.py",
        "log_subagent_stop.py",
        "log_pre_compact.py",
        "log_notification.py",
        "log_turn_stop.py",
    ]:
        assert hook in content, f"README missing reference to {hook}"


def test_readme_has_mermaid_diagram():
    assert "```mermaid" in README.read_text()


def test_readme_documents_prerequisites_uv():
    content = README.read_text().lower()
    assert "uv" in content
    assert "python" in content
    assert "3.11" in content


def test_readme_documents_skip_flag():
    assert "SKIP_GOVERNANCE_AUDIT" in README.read_text()


def test_readme_no_copilot_references():
    content = README.read_text()
    # No literal "Copilot" as a product reference
    lower = content.lower()
    assert "github copilot cli" not in lower
    assert "copilot cli" not in lower
    # Raw "copilot" can appear in generic English but shouldn't in this README
    assert "copilot" not in lower, "README still contains 'copilot' — replace with Claude Code"


def test_readme_documents_enforcement_model():
    content = README.read_text().lower()
    # Must clarify which hook is the reliable blocker
    assert "gate_pre_tool_use" in content
    assert "enforcement" in content or "block" in content


def test_readme_documents_jsonl_schema():
    content = README.read_text()
    # Must reference the log path pattern
    assert "governance-audit.jsonl" in content
