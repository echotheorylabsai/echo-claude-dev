---
layout: home

hero:
  name: secure-claude
  text: Governance for Claude Code
  tagline: Audit, scan, and gate every tool call and prompt — cross-platform Python hooks with a browser dashboard.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/echotheorylabsai/echo-claude-dev

features:
  - icon: 🛡️
    title: Real Enforcement
    details: PreToolUse gate blocks dangerous commands before they run — rm -rf, fork bombs, sensitive file edits, and more.
  - icon: 🔍
    title: Threat Scanning
    details: Six prompt-injection categories and four indirect-injection categories evaluated on every prompt and tool output.
  - icon: 📊
    title: Local-First Dashboard
    details: Browser-side JSONL viewer with KPIs, timeline, filters, and threat charts. No data leaves your machine.
  - icon: 🐍
    title: Pure Python
    details: No Bash, no PowerShell. Runs identically on macOS, Linux, and Windows via uv. One codebase, everywhere.
  - icon: 🔐
    title: Fail-Closed Gate
    details: If governance config is unreadable, the gate denies every tool call. Observability hooks stay fail-open so workflows never break silently.
  - icon: 🧩
    title: Override-Friendly
    details: Add local rules without touching the shipped baseline. The compiler rejects overrides that reuse shipped IDs.
---

## Quick Look

```bash
claude plugin marketplace add echo-theory-labs
claude plugin install secure-claude@echo-theory-labs
```

That's it. Start a Claude Code session — every tool call and prompt is now audited at
`~/progress-ai/secure-claude/logs/<project>/governance-audit.jsonl`.

## Who is this for?

| You are… | You get… |
|---------|---------|
| A developer using Claude Code on a real codebase | Protection against `rm -rf`, sensitive file edits, credential leaks |
| A team running AI agents in shared environments | An append-only JSONL audit trail for every tool call |
| A security engineer auditing AI tool usage | A transparent, open-source governance layer with customizable rules |
