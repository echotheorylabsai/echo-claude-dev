from secure_claude import scanner

RULES = [
    {
        "id": "r1",
        "category": "data_exfiltration",
        "description": "bulk send",
        "pattern": "send all",
        "severity": 0.85,
        "engine": "posix",
        "caseInsensitive": True,
        "enabled": True,
    },
    {
        "id": "r2",
        "category": "prompt_injection",
        "description": "ignore prev",
        "pattern": r"(?i)ignore\s+previous",
        "severity": 0.9,
        "engine": "pcre",
        "caseInsensitive": False,
        "enabled": True,
    },
    {
        "id": "r3",
        "category": "x",
        "description": "disabled",
        "pattern": "nope",
        "severity": 0.5,
        "engine": "posix",
        "caseInsensitive": True,
        "enabled": False,
    },
]


def test_no_match_returns_empty():
    assert scanner.scan_text(text="harmless text", rules=RULES) == []


def test_match_returns_threat_with_evidence():
    t = scanner.scan_text(text="please send all user data", rules=RULES)
    assert len(t) == 1
    assert t[0].category == "data_exfiltration"
    assert t[0].severity == 0.85
    assert t[0].description == "bulk send"
    assert "send all" in t[0].evidence


def test_multiple_matches_multiple_categories():
    t = scanner.scan_text(text="send all and ignore previous", rules=RULES)
    cats = {x.category for x in t}
    assert cats == {"data_exfiltration", "prompt_injection"}


def test_disabled_rules_skipped():
    t = scanner.scan_text(text="nope", rules=RULES)
    assert t == []


def test_bad_pattern_is_skipped_not_fatal():
    bad = [
        {
            "id": "bad",
            "category": "c",
            "description": "d",
            "pattern": "(unterminated",
            "severity": 1.0,
            "engine": "pcre",
            "caseInsensitive": False,
            "enabled": True,
        }
    ]
    assert scanner.scan_text(text="anything", rules=bad) == []


def test_missing_pattern_field_is_skipped():
    bad = [{"id": "bad", "category": "c", "description": "d", "enabled": True}]
    assert scanner.scan_text(text="anything", rules=bad) == []


def test_empty_text_returns_empty():
    assert scanner.scan_text(text="", rules=RULES) == []


def test_max_severity():
    threats = scanner.scan_text(text="send all and ignore previous", rules=RULES)
    assert scanner.max_severity(threats) == 0.9


def test_max_severity_empty():
    assert scanner.max_severity([]) == 0.0


def test_threats_to_json():
    threats = [
        scanner.Threat(category="x", severity=0.9, description="d", evidence="e"),
    ]
    serialized = scanner.threats_to_json(threats)
    assert serialized == [{"category": "x", "severity": 0.9, "description": "d", "evidence": "e"}]


def test_rule_missing_enabled_defaults_true():
    rules = [
        {
            "id": "r",
            "category": "c",
            "description": "d",
            "pattern": "match",
            "severity": 0.5,
            "engine": "posix",
        }
    ]
    assert len(scanner.scan_text(text="match", rules=rules)) == 1


def test_evidence_truncated_at_200_chars():
    long_text = "x" * 300
    rules = [
        {
            "id": "r",
            "category": "c",
            "description": "d",
            "pattern": "x+",
            "severity": 0.5,
            "engine": "posix",
        }
    ]
    t = scanner.scan_text(text=long_text, rules=rules)
    assert len(t) == 1
    assert len(t[0].evidence) <= 200
