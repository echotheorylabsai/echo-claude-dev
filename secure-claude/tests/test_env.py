from secure_claude import env


def test_skip_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SKIP_GOVERNANCE_AUDIT", raising=False)
    assert env.skip_audit() is False


def test_skip_enabled_for_truthy_values(monkeypatch):
    for v in ["true", "True", "TRUE", "1", "yes", "Yes", "YES"]:
        monkeypatch.setenv("SKIP_GOVERNANCE_AUDIT", v)
        assert env.skip_audit() is True, f"expected True for {v!r}"


def test_skip_disabled_for_falsy_values(monkeypatch):
    for v in ["false", "False", "0", "no", "", "   "]:
        monkeypatch.setenv("SKIP_GOVERNANCE_AUDIT", v)
        assert env.skip_audit() is False, f"expected False for {v!r}"


def test_skip_disabled_for_garbage(monkeypatch):
    monkeypatch.setenv("SKIP_GOVERNANCE_AUDIT", "maybe")
    assert env.skip_audit() is False
