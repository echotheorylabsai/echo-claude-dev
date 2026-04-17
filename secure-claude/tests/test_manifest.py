import json
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def test_plugin_manifest_fields():
    manifest = json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == "secure-claude"
    assert manifest["version"] == "1.0.0"
    assert manifest["hooks"] == "./hooks/hooks.json"
    assert "governance" in manifest["keywords"]
    assert manifest["license"] == "MIT"


def test_marketplace_manifest_fields():
    mkt = json.loads((PLUGIN_ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert mkt["name"] == "echo-theory-labs"
    assert mkt["owner"]["name"]
    assert any(p["name"] == "secure-claude" for p in mkt["plugins"])
    entry = next(p for p in mkt["plugins"] if p["name"] == "secure-claude")
    assert entry["source"] == "."
    assert entry["category"] == "security"
