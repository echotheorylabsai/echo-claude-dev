import json

from secure_claude import logging_utils


def test_audit_log_writes_record(tmp_path):
    lf = tmp_path / "audit.jsonl"
    logging_utils.audit_log(lf, {"event": "test", "k": "v"})
    rec = json.loads(lf.read_text().strip())
    assert rec["event"] == "test"
    assert rec["k"] == "v"
    assert "timestamp" in rec  # auto-added if missing
    assert rec["timestamp"].endswith("Z")


def test_audit_log_preserves_existing_timestamp(tmp_path):
    lf = tmp_path / "audit.jsonl"
    logging_utils.audit_log(lf, {"timestamp": "2020-01-01T00:00:00Z", "event": "x"})
    rec = json.loads(lf.read_text().strip())
    assert rec["timestamp"] == "2020-01-01T00:00:00Z"


def test_audit_log_does_not_mutate_caller_dict(tmp_path):
    lf = tmp_path / "audit.jsonl"
    original = {"event": "t"}
    logging_utils.audit_log(lf, original)
    assert "timestamp" not in original  # caller's dict must be untouched


def test_config_error_emits_configError_event(tmp_path, capsys):
    lf = tmp_path / "audit.jsonl"
    logging_utils.config_error(lf, source="test-hook", message="bad config")
    rec = json.loads(lf.read_text().strip())
    assert rec["event"] == "configError"
    assert rec["source"] == "test-hook"
    assert rec["message"] == "bad config"
    err = capsys.readouterr().err
    assert "bad config" in err


def test_ui_print_goes_to_stderr(capsys):
    logging_utils.ui_print("hello")
    assert capsys.readouterr().err.strip() == "hello"
