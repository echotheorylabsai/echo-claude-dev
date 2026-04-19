# Disabling Governance

## Fully disable

Set `SKIP_GOVERNANCE_AUDIT=true` in the environment. Every hook exits `0` immediately.
No audit records are written, no rules are evaluated, no tool calls are gated.

```bash
# Session-scoped
export SKIP_GOVERNANCE_AUDIT=true

# Single command
SKIP_GOVERNANCE_AUDIT=true claude
```

Accepted truthy values: `1`, `true`, `yes` (case-insensitive). Anything else leaves
the plugin active.

## Uninstall

```bash
claude plugin uninstall secure-claude
```

Audit logs at `~/echo-theory-labs/secure-claude/logs/` are preserved on uninstall — delete
them manually if you want them gone.

## Local overrides directory

```bash
rm -rf ~/.config/secure-claude
```

This removes any user-local overrides. The shipped rules continue to work.
