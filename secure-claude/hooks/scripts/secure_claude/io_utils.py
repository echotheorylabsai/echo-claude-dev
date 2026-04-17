from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path


def read_stdin_json() -> dict:
    """Read all of stdin and parse as JSON dict.

    Returns {} for empty/whitespace input or TTY.
    Returns {"_raw": <text>} for non-dict or invalid JSON.
    """
    if sys.stdin.isatty():
        return {}
    raw = sys.stdin.read()
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": raw}
    if not isinstance(parsed, dict):
        return {"_raw": raw}
    return parsed


def write_stdout_json(obj: dict) -> None:
    """Write compact JSON to stdout followed by a newline, then flush."""
    print(json.dumps(obj, separators=(",", ":")), flush=True)


def append_jsonl(path: Path, record: dict) -> None:
    """Append one JSON record as a line to a JSONL file, creating parent dirs."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def utc_timestamp() -> str:
    """Return current UTC time as ISO8601 string: YYYY-MM-DDTHH:MM:SSZ."""
    now = datetime.now(tz=UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")
