# End-to-End Simulator

The simulator exercises the whole hook surface without a live Claude Code session.
It compiles the config, drives 26 scenarios across all 10 hooks, and asserts the
resulting JSONL against expected shapes.

## Run it

```bash
cd secure-claude

# Run all scenarios
uv run python scripts/simulate_hooks.py

# Keep generated logs for inspection
KEEP_TMP=1 uv run python scripts/simulate_hooks.py
```

## What it covers

- Config compilation (shipped + overrides) and duplicate-ID rejection
- Prompt threat detection across all six categories
- Tool allow/deny decisions for Bash, Edit, Write, NotebookEdit
- Indirect injection across Read, WebFetch, Grep, Glob results
- Local override **adds** but cannot weaken shipped rules
- Malformed config → fall back to shipped baseline with `configError`
- Missing shipped config → gate fails closed, scanners fail open
- Subagent, compact, notification, turn-stop audit records

## Output

On success, the simulator prints a green summary with counts per scenario and
exits `0`. On failure, the first mismatched assertion is printed with the offending
JSONL record.

## Unit tests

```bash
cd secure-claude
uv run pytest -q
```

181 tests cover individual modules (paths, io_utils, regex_engine, config_loader,
scanner, gate, each hook script).
