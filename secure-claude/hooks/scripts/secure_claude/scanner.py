from __future__ import annotations

import sys
from dataclasses import dataclass

from .regex_engine import CompileError, compile_rule

__all__ = ["Threat", "max_severity", "scan_text", "threats_to_json"]


@dataclass
class Threat:
    category: str
    severity: float
    description: str
    evidence: str


def scan_text(*, text: str, rules: list[dict]) -> list[Threat]:
    """Evaluate *rules* against *text* and return matching threats.

    Parameters
    ----------
    text:
        The input string to scan.
    rules:
        A list of rule dicts.  Each rule must have at minimum ``pattern``,
        ``category``, ``description``, and ``severity`` keys.  Optional
        keys: ``id``, ``engine``, ``caseInsensitive``, ``enabled``.

    Returns
    -------
    list[Threat]
        Threats in rule-order; empty when there are no matches.
    """
    if not text:
        return []

    threats: list[Threat] = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_id = rule.get("id", "<unknown>")

        try:
            pattern: str = rule["pattern"]
        except KeyError as exc:
            print(
                f"[secure-claude] skipped bad rule {rule_id}: {exc}",
                file=sys.stderr,
            )
            continue

        try:
            regex = compile_rule(
                pattern=pattern,
                engine=rule.get("engine"),
                case_insensitive=bool(rule.get("caseInsensitive", False)),
            )
        except (CompileError, Exception) as exc:
            print(
                f"[secure-claude] skipped bad rule {rule_id}: {exc}",
                file=sys.stderr,
            )
            continue

        match = regex.search(text)
        if match:
            threats.append(
                Threat(
                    category=rule["category"],
                    severity=rule["severity"],
                    description=rule["description"],
                    evidence=match.group(0)[:200],
                )
            )

    return threats


def max_severity(threats: list[Threat]) -> float:
    """Return the highest severity across *threats*, or ``0.0`` if empty."""
    if not threats:
        return 0.0
    return max(t.severity for t in threats)


def threats_to_json(threats: list[Threat]) -> list[dict]:
    """Serialise *threats* to a list of plain dicts."""
    return [
        {
            "category": t.category,
            "severity": t.severity,
            "description": t.description,
            "evidence": t.evidence,
        }
        for t in threats
    ]
