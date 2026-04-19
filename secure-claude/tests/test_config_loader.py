import json

import pytest

from secure_claude import config_loader


def test_load_rules_from_shipped_ok(tmp_path):
    p = tmp_path / "shipped.json"
    p.write_text(json.dumps([{"id": "r1"}]))
    rules = config_loader.load_rules(shipped=p, local=None)
    assert rules == [{"id": "r1"}]


def test_load_rules_merges_local(tmp_path):
    s = tmp_path / "s.json"
    s.write_text(json.dumps([{"id": "r1"}]))
    local = tmp_path / "local.json"
    local.write_text(json.dumps([{"id": "r2"}]))
    rules = config_loader.load_rules(shipped=s, local=local)
    assert {r["id"] for r in rules} == {"r1", "r2"}


def test_load_rules_local_unreadable_falls_back(tmp_path):
    s = tmp_path / "s.json"
    s.write_text(json.dumps([{"id": "r1"}]))
    missing = tmp_path / "nonexistent.json"
    errors = []
    rules = config_loader.load_rules(shipped=s, local=missing, on_local_error=errors.append)
    assert rules == [{"id": "r1"}]
    assert len(errors) == 1


def test_load_rules_local_bad_json_falls_back(tmp_path):
    s = tmp_path / "s.json"
    s.write_text(json.dumps([{"id": "r1"}]))
    local = tmp_path / "bad.json"
    local.write_text("{not json")
    errors = []
    rules = config_loader.load_rules(shipped=s, local=local, on_local_error=errors.append)
    assert rules == [{"id": "r1"}]
    assert len(errors) == 1


def test_load_rules_shipped_missing_raises(tmp_path):
    with pytest.raises(config_loader.ShippedConfigUnreadable):
        config_loader.load_rules(shipped=tmp_path / "missing.json", local=None)


def test_load_rules_shipped_invalid_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(config_loader.ShippedConfigUnreadable):
        config_loader.load_rules(shipped=p, local=None)


def test_load_rules_shipped_not_array_raises(tmp_path):
    p = tmp_path / "obj.json"
    p.write_text('{"not": "array"}')
    with pytest.raises(config_loader.ShippedConfigUnreadable):
        config_loader.load_rules(shipped=p, local=None)


def test_filter_enabled_default_true():
    rules = [{"id": "a", "enabled": True}, {"id": "b", "enabled": False}, {"id": "c"}]
    assert [r["id"] for r in config_loader.filter_enabled(rules)] == ["a", "c"]


def test_local_none_does_not_invoke_callback(tmp_path):
    s = tmp_path / "s.json"
    s.write_text(json.dumps([{"id": "r1"}]))
    errors = []
    config_loader.load_rules(shipped=s, local=None, on_local_error=errors.append)
    assert errors == []
