# What is secure-claude?

`secure-claude` is a [Claude Code](https://code.claude.com) plugin that wraps every
session in a governance layer: lifecycle events are logged, prompts and tool outputs
are scanned for threat signals, and dangerous tool invocations are blocked *before*
they execute.

## Why it exists

Claude Code can execute shell commands, edit files, and fetch remote content. In
practice, that means a single misread prompt can trigger `rm -rf`, leak secrets via
`curl`, or overwrite `/etc/hosts`. `secure-claude` adds a governance layer between
the model and your machine.

## Three things it does

1. **Audits** every hook event to an append-only JSONL log.
2. **Scans** user prompts and tool outputs against regex rule packs across ten threat categories.
3. **Gates** `Bash`, `Edit`, `Write`, and `NotebookEdit` calls against a deny list — the only hook that can *actually* stop a tool call before it runs.

## What it is not

- Not a sandbox. The tool still runs inside your shell; the gate blocks matching commands but cannot contain a command that slips through.
- Not an ML model. Detection is regex-based and heuristic — fast, auditable, and limited.
- Not an anti-virus. Don't rely on it as the only line of defense.

## Next steps

- [Install the plugin →](/guide/installation)
- [Understand the architecture →](/guide/architecture)
- [View the JSONL schema →](/reference/schema)
