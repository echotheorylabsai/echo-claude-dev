import io
import json

from secure_claude import io_utils


def test_read_stdin_json(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO('{"a":1}'))
    assert io_utils.read_stdin_json() == {"a": 1}


def test_read_stdin_json_invalid_returns_raw(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert io_utils.read_stdin_json() == {"_raw": "not json"}


def test_read_stdin_json_empty(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert io_utils.read_stdin_json() == {}


def test_read_stdin_json_non_object_returns_raw(monkeypatch):
    # Valid JSON but not a dict — must still return dict-shaped result
    monkeypatch.setattr("sys.stdin", io.StringIO('["a","b"]'))
    result = io_utils.read_stdin_json()
    assert "_raw" in result


def test_write_stdout_json(capsys):
    io_utils.write_stdout_json({"ok": True})
    out = capsys.readouterr().out.strip()
    assert json.loads(out) == {"ok": True}


def test_append_jsonl_atomic(tmp_path):
    lf = tmp_path / "audit.jsonl"
    io_utils.append_jsonl(lf, {"event": "a"})
    io_utils.append_jsonl(lf, {"event": "b"})
    lines = lf.read_text().strip().splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["a", "b"]


def test_append_jsonl_creates_parent_dirs(tmp_path):
    lf = tmp_path / "a" / "b" / "c.jsonl"
    io_utils.append_jsonl(lf, {"x": 1})
    assert lf.exists()


def test_append_jsonl_preserves_non_ascii(tmp_path):
    lf = tmp_path / "audit.jsonl"
    io_utils.append_jsonl(lf, {"msg": "café 🛡️"})
    rec = json.loads(lf.read_text().strip())
    assert rec["msg"] == "café 🛡️"


def test_utc_timestamp_iso8601_z():
    ts = io_utils.utc_timestamp()
    assert ts.endswith("Z")
    assert "T" in ts
    assert len(ts) == 20  # YYYY-MM-DDTHH:MM:SSZ
