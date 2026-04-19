from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class ToolEvent:
    tool_name: str
    cwd: str
    tool_input: dict = field(default_factory=dict)


def parse_tool_event(payload: dict) -> ToolEvent:
    """Normalise a Claude Code PreToolUse / PostToolUse payload into a ToolEvent."""
    tool_name = payload.get("tool_name") or "unknown"
    cwd = payload.get("cwd") or ""

    raw_input = payload.get("tool_input")
    if isinstance(raw_input, dict):
        tool_input = raw_input
    elif isinstance(raw_input, str):
        try:
            parsed = json.loads(raw_input)
            tool_input = parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, ValueError):
            tool_input = {}
    else:
        tool_input = {}

    return ToolEvent(tool_name=tool_name, cwd=cwd, tool_input=tool_input)


_KNOWN_RESPONSE_KEYS = ("text", "textResultForLlm", "stdout", "output", "content")


def extract_post_tool_text(payload: dict) -> str:
    """Return a plain-text representation of a PostToolUse tool response."""
    resp = payload.get("tool_response") or payload.get("tool_output")
    if resp is None:
        return ""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        for key in _KNOWN_RESPONSE_KEYS:
            val = resp.get(key)
            if val and isinstance(val, str):
                return val
        return json.dumps(resp, ensure_ascii=False)
    return str(resp)


def extract_user_prompt(payload: dict) -> str:
    """Return the user prompt string from a UserPromptSubmit payload."""
    for key in ("prompt", "userMessage", "user_prompt", "_raw"):
        val = payload.get(key)
        if val and isinstance(val, str):
            return val
    return ""
