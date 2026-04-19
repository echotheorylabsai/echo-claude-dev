from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

__all__ = ["ShippedConfigUnreadable", "filter_enabled", "load_rules"]


class ShippedConfigUnreadable(RuntimeError):
    """Raised when the shipped rule pack cannot be read or is not a JSON array."""


def _read_json_array(path: Path) -> list[dict]:
    """Read *path* as JSON; return the array or raise the caller's exception."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise exc
    if not isinstance(data, list):
        raise TypeError(f"{path} is not a JSON array")
    return data


def load_rules(
    *,
    shipped: Path,
    local: Path | None,
    on_local_error: Callable[[str], None] | None = None,
) -> list[dict]:
    """Load and merge rule packs.

    The shipped pack is fail-closed: any problem raises *ShippedConfigUnreadable*.
    The local pack is fail-open: errors are passed to *on_local_error* (if provided)
    and the function falls back to the shipped rules.
    """
    # --- shipped (fail-closed) ---
    try:
        shipped_rules: list[dict] = _read_json_array(shipped)
    except Exception as exc:
        raise ShippedConfigUnreadable(f"Cannot load shipped config {shipped}: {exc}") from exc

    # --- local (fail-open) ---
    if local is None:
        return shipped_rules

    try:
        local_rules: list[dict] = _read_json_array(local)
        return shipped_rules + local_rules
    except Exception as exc:
        if on_local_error is not None:
            on_local_error(f"Cannot load local config {local}: {exc}")
        return shipped_rules


def filter_enabled(rules: list[dict]) -> list[dict]:
    """Return only rules where ``enabled`` is truthy (defaults to ``True``)."""
    return [r for r in rules if r.get("enabled", True)]
