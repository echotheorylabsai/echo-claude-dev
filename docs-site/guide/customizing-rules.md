# Customizing Rules

`secure-claude` ships three YAML rule packs. You can add your own rules as **local
overrides** — the compiler merges them into the runtime JSON *without* allowing
overrides to weaken the shipped baseline.

## File layout

```text
secure-claude/hooks/config/
├── user-prompt-threats.yaml          # prompt-scan rules
├── tool-rules.yaml                   # tool-gate deny rules
├── indirect-injection-patterns.yaml  # post-tool indirect-injection rules
└── generated/
    ├── user-prompt-threats.json      # compiled runtime artifact
    ├── tool-rules.json
    └── indirect-injection-patterns.json

~/.config/secure-claude/              # optional user-local overrides
├── overrides.yaml
└── generated/
    └── *.json
```

## Override mechanism

- Local overrides may **add** new rules.
- Local overrides **cannot reuse a shipped rule ID** — the compiler rejects those at build time, so you can't silently weaken or replace enforcement.
- If a local generated JSON is malformed or missing, hooks fall back to the shipped baseline and emit a `configError` audit record.

## Compile commands

```bash
cd secure-claude

# Regenerate shipped JSON after editing any YAML source
uv run python hooks/scripts/compile_config.py --mode shipped

# Compile optional local overrides
uv run python hooks/scripts/compile_config.py --mode overrides

# Verify generated JSON is up to date (CI-safe — fails if stale)
uv run python hooks/scripts/compile_config.py --mode shipped --check
```

## Rule shape

Every rule has this common shape (field names vary slightly per pack):

```yaml
- id: unique-rule-id
  enabled: true
  severity: 0.9        # 0.0 – 1.0
  category: system_destruction
  description: "Short human summary"
  pattern: 'rm\s+-rf\s+/'
  engine: pcre         # or "posix-ere"
  caseInsensitive: true
  tool: Bash           # tool-rules only
  targetField: command # tool-rules only — field inside tool_input
  action: deny         # tool-rules only
  reason: "Blocked: destructive file operation: {value}"
```

## Supported `targetField` values (tool-rules)

| Tool | targetField |
|------|-------------|
| Bash | `command` |
| Edit | `file_path` |
| Write | `file_path` |
| NotebookEdit | `notebook_path` |

## Regex engines

- `posix-ere` — POSIX Extended Regular Expressions; translated to Python `re` at compile time (character classes like `[[:space:]]` are converted).
- `pcre` — Perl-style; a subset translated to Python `re` (including `\x{NNNN}` Unicode escapes).

Both engines are compiled at build time to fail fast on invalid syntax.

## Example: add a project-specific deny rule

```yaml
# ~/.config/secure-claude/overrides.yaml
toolRules:
  - id: local-block-prod-deploy
    enabled: true
    tool: Bash
    targetField: command
    pattern: 'kubectl.*--namespace\s+prod'
    engine: pcre
    caseInsensitive: true
    action: deny
    severity: 0.95
    reason: "Production kubectl blocked by local policy"
```

```bash
uv run python hooks/scripts/compile_config.py --mode overrides
```
