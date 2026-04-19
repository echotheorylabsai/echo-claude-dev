# Security Model

## Trust boundaries

| Layer | Trust level | Why |
|-------|-------------|-----|
| Claude Code stdin JSON | **Untrusted** | Contains attacker-controlled tool input and prompt text |
| `hooks/config/generated/*.json` | Trusted | Built from shipped YAML at plugin install time |
| `~/.config/secure-claude/generated/*.json` | Semi-trusted | Must not collide with shipped IDs |
| Audit JSONL log | Trusted output | Only secure-claude appends; single-writer contract |

## Fail semantics

- **Gate (`gate_pre_tool_use`)** — fail-closed. If shipped config is unreadable or malformed, every tool call is denied until the config is restored, and a `configError` is logged.
- **Scanners (`scan_*`)** — fail-open. Scan failures skip the scan and log a `configError`; they do not block the user. Breaking a user's workflow on an audit failure is worse than a missed scan.
- **Loggers (`log_*`)** — fail-open. Log write failures are swallowed; governance must never interrupt the session.

## Input handling

- `stdin` JSON is parsed with `json.loads` (stdlib); invalid JSON produces a `configError` and exits `0`.
- All `tool_input` field values are treated as untrusted strings. Regex matches capture evidence truncated at 200 chars.
- The `{value}` interpolation in deny reasons is capped at 200 chars before being written to the audit log or Claude Code stdout.
- `project_name` used in the log path is sanitized against `[^A-Za-z0-9_.-]` (replaced with `_`) and truncated to 128 chars, preventing path traversal via crafted repo names.

## Subprocess usage

- All subprocess calls pass arguments as a list (`subprocess.run([...])`), never `shell=True`.
- The only subprocess call is `git rev-parse --show-toplevel` with a 2-second timeout.

## Deserialization

- YAML rule packs use `yaml.safe_load` exclusively — no arbitrary object loading.
- All JSON parsing uses the stdlib `json` module.
- No unsafe binary deserializers are used anywhere in the code path.

## Dashboard

- The dashboard runs entirely in the browser off `file://` — no network requests, no cookies, no external fonts.
- All JSONL-derived values rendered into HTML pass through an HTML-escape helper.

## Supply chain

- Runtime dependency: `PyYAML >= 6.0.2` (patched for CVE-2022-1471) — sole runtime dep.
- Dev-only: `pytest`, `ruff`.
- Lower-bound pins only; no loose wildcard versions.

## Reporting

Found a security issue? Please report it via a
[private security advisory on GitHub](https://github.com/echotheorylabsai/echo-claude-dev/security/advisories/new).
Do not open a public issue for security reports.
