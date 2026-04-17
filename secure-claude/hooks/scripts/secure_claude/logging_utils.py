from __future__ import annotations

import sys
from pathlib import Path

from .io_utils import append_jsonl, utc_timestamp


def audit_log(log_file: Path, record: dict) -> None:
    """Append a shallow copy of *record* to *log_file*, adding timestamp if absent."""
    entry = dict(record)
    if "timestamp" not in entry:
        entry["timestamp"] = utc_timestamp()
    append_jsonl(Path(log_file), entry)


def config_error(log_file: Path, *, source: str, message: str) -> None:
    """Log a configError event and emit a message to stderr."""
    audit_log(log_file, {"event": "configError", "source": source, "message": message})
    sys.stderr.write(f"[secure-claude] config error ({source}): {message}\n")


def ui_print(msg: str) -> None:
    """Write *msg* to stderr."""
    sys.stderr.write(msg + "\n")
