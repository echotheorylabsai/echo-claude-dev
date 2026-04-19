# Hooks Reference

Every hook is a thin Python entry-point under `secure-claude/hooks/scripts/` that
reads JSON from stdin and delegates to the `secure_claude` package.

## Wired events

| Stage | Hook event | Script | Purpose | Enforcement |
|-------|-----------|--------|---------|-------------|
| Session boot | `SessionStart` | `log_session_start.py` | Audit session start, record cwd | — |
| Prompt scan | `UserPromptSubmit` | `scan_prompt_injection.py` | Detect prompt threats (6 categories) | exit 2 blocks |
| Tool audit | `PreToolUse` | `log_pre_tool_use.py` | Record tool name, branch, args | — |
| Tool gate | `PreToolUse` | `gate_pre_tool_use.py` | Deny dangerous tool calls | **real deny** |
| Output scan | `PostToolUse` | `scan_post_tool_injection.py` | Detect indirect injection | audit-only |
| Subagent | `SubagentStop` | `log_subagent_stop.py` | Record subagent completions | — |
| Compaction | `PreCompact` | `log_pre_compact.py` | Breadcrumb before context compaction | — |
| Permission | `Notification` | `log_notification.py` | Audit permission prompts shown to user | — |
| Turn end | `Stop` | `log_turn_stop.py` | Per-turn ledger boundary | — |
| Session end | `SessionEnd` | `log_session_end.py` | Summary counts | — |

## Matchers

Hook matchers are set in `hooks/hooks.json`:

| Event | Matcher |
|-------|---------|
| `PreToolUse` | `Bash\|Edit\|Write\|NotebookEdit` |
| `PostToolUse` | `Bash\|Edit\|Write\|Read\|WebFetch\|Grep\|Glob\|NotebookEdit` |
| `SessionStart` | `startup\|resume\|clear` |
| `PreCompact` | `manual\|auto` |
| `Notification` | `permission_prompt` |

## Deny output shape

`gate_pre_tool_use` writes this exact JSON to stdout when a rule matches:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked: <rule reason with matched value, capped at 200 chars>"
  }
}
```

## Rule categories

### Prompt scanning (`scan_prompt_injection.py`)

| Category | Example signals | Severity |
|----------|----------------|----------|
| `data_exfiltration` | Bulk transfer, HTTP POST with data | 0.70 – 0.95 |
| `privilege_escalation` | `sudo`/root access, `chmod 777` | 0.80 – 0.95 |
| `system_destruction` | `rm -rf /`, `DROP DATABASE` | 0.90 – 0.95 |
| `prompt_injection` | Instruction overrides, role reassignment | 0.60 – 0.90 |
| `credential_exposure` | Hardcoded API keys, AWS `AKIA…` | 0.90 – 0.95 |
| `encoding_obfuscation` | Zero-width Unicode, homoglyphs, base64+exec | 0.85 – 0.95 |

### Tool gating (`gate_pre_tool_use.py`)

Nine deny-rule groups:

| Rule group | Blocked patterns |
|-----------|-----------------|
| `bash-destructive-file-ops` | `rm -rf`, `dd if/of=`, `mkfs`, `sudo rm` |
| `bash-protected-file-deletion` | Deleting `.env*` or `.git/` |
| `bash-destructive-git-operation` | `git push --force` to main/master, `git reset --hard`, `git clean -fd` |
| `bash-destructive-database-operation` | `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, bare `DELETE FROM` |
| `bash-fork-bomb` | Classic fork-bomb pattern |
| `bash-remote-script-pipe` | `curl … \| bash`, `wget … \| sh` |
| `bash-network-exposure` | `nc -l`, `python -m http.server`, `php -S` |
| `edit-sensitive-file` | `.env`, `secrets`, `credentials`, `.ssh/`, `.aws/`, `.npmrc` |
| `create-system-path` | `/etc/`, `/bin/`, `/sbin/`, `/usr/bin/` |

### Indirect injection (`scan_post_tool_injection.py`)

| Category | Example signals | Severity |
|----------|----------------|----------|
| `instruction_override` | "Ignore previous instructions", fake system prompts | 0.70 – 0.95 |
| `role_playing_dan` | DAN jailbreak, developer mode | 0.90 – 0.95 |
| `encoding_obfuscation` | Zero-width Unicode, base64+exec | 0.70 – 0.95 |
| `context_manipulation` | HTML comment injection, fake role markers | 0.90 – 0.95 |
