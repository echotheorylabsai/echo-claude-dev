import json
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = PLUGIN_ROOT / "log-viewer" / "dashboard.html"
EXAMPLE_JSONL = PLUGIN_ROOT / "log-viewer" / "example-governance-audit.jsonl"


def test_dashboard_exists():
    assert DASHBOARD.exists(), "dashboard.html missing"


def test_dashboard_no_copilot_branding():
    content = DASHBOARD.read_text()
    # Allow historical mentions inside comments starting with <!-- legacy: ... -->
    # Everywhere else: no lowercase "copilot" or "Copilot CLI".
    assert "GitHub Copilot CLI" not in content
    assert "Secure Copilot" not in content


def test_example_jsonl_exists_and_valid():
    assert EXAMPLE_JSONL.exists(), "example jsonl missing"
    lines = [line for line in EXAMPLE_JSONL.read_text().splitlines() if line.strip()]
    assert lines, "example jsonl is empty"
    for line in lines:
        json.loads(line)  # each line must be valid JSON


def test_example_jsonl_covers_all_event_types():
    records = [json.loads(line) for line in EXAMPLE_JSONL.read_text().splitlines() if line.strip()]
    events_present = {r.get("event") for r in records}
    required_events = {
        "sessionStart",
        "sessionEnd",
        "promptScanned",
        "threatDetected",
        "preToolUse",
        "preToolDecision",
        "postToolScanned",
        "indirectThreatDetected",
        "configError",
        "subagentStop",
        "preCompact",
        "notification",
        "turnStop",
    }
    missing = required_events - events_present
    assert not missing, f"example jsonl missing events: {missing}"


def test_example_jsonl_threat_records_have_schema_fields():
    """JSONL schema contract preserved from secure-copilot: threat events must have threat_count, max_severity, threats[]."""
    records = [json.loads(line) for line in EXAMPLE_JSONL.read_text().splitlines() if line.strip()]
    for r in records:
        if r.get("event") in ("threatDetected", "indirectThreatDetected"):
            assert "threat_count" in r
            assert "max_severity" in r
            assert "threats" in r
            assert isinstance(r["threats"], list)
            for t in r["threats"]:
                assert "category" in t
                assert "severity" in t
                assert "description" in t
                assert "evidence" in t


def test_example_jsonl_pre_tool_decision_schema():
    records = [json.loads(line) for line in EXAMPLE_JSONL.read_text().splitlines() if line.strip()]
    for r in records:
        if r.get("event") == "preToolDecision":
            assert "tool" in r
            assert "decision" in r
            assert r["decision"] in ("allow", "deny")
            assert "reason" in r


def test_example_jsonl_session_end_schema():
    records = [json.loads(line) for line in EXAMPLE_JSONL.read_text().splitlines() if line.strip()]
    for r in records:
        if r.get("event") == "sessionEnd":
            assert "total_events" in r
            assert "threats_detected" in r
            assert isinstance(r["total_events"], int)
            assert isinstance(r["threats_detected"], int)
