from __future__ import annotations

import os


def skip_audit() -> bool:
    """Return True iff SKIP_GOVERNANCE_AUDIT env var is a truthy value (case-insensitive, stripped).

    Truthy values: "1", "true", "yes" (case-insensitive).
    All other values (including empty string) return False.
    """
    value = os.getenv("SKIP_GOVERNANCE_AUDIT", "").strip().lower()
    return value in {"1", "true", "yes"}
