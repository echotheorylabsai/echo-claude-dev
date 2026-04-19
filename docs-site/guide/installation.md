# Installation

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| [Claude Code](https://code.claude.com) | any recent | The host that fires hook events |
| Python | 3.11+ | Managed automatically by uv via `.python-version` |
| [uv](https://docs.astral.sh/uv/) | latest | Dependency manager + script runner |
| Git | any | Optional — used for branch and project-name detection |

### Install uv

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# macOS (Homebrew)
brew install uv

# Windows
winget install astral-sh.uv
```

## Install the plugin

### Option 1 — from the marketplace (recommended)

```bash
claude plugin marketplace add echo-theory-labs
claude plugin install secure-claude@echo-theory-labs
```

### Option 2 — from a local clone

```bash
git clone https://github.com/echotheorylabsai/echo-claude-dev.git
claude plugin install /absolute/path/to/echo-claude-dev/secure-claude
```

## First-run sync

Inside the plugin directory, run `uv sync` once to create the virtual environment and
install dependencies. Hooks invoke `uv run` at runtime; uv caches the environment
after the first call.

```bash
cd /path/to/secure-claude
uv sync
```

## Verify

Start a Claude Code session and check the audit log:

```bash
tail -f ~/progress-ai/secure-claude/logs/<your-project>/governance-audit.jsonl
```

A `sessionStart` event confirms the plugin is active.

## Disabling temporarily

Set `SKIP_GOVERNANCE_AUDIT=true` in the environment — every hook exits `0` immediately
and no audit records are written.

```bash
SKIP_GOVERNANCE_AUDIT=true claude
```
