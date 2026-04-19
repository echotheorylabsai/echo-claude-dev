# echo-claude-dev

Home of **secure-claude** — governance, audit, and tool-gating hooks for
[Claude Code](https://code.claude.com).

📖 **Documentation:** <https://echotheorylabsai.github.io/echo-claude-dev/>

## Repository layout

| Path | Purpose |
|------|---------|
| [`secure-claude/`](./secure-claude/) | The plugin source (Python hooks, YAML rules, dashboard, tests) |
| [`docs-site/`](./docs-site/) | VitePress source for the Pages documentation site |
| [`.github/workflows/`](./.github/workflows/) | GitHub Actions — deploys `docs-site` on push to `main` |

## Quick start

```bash
claude plugin marketplace add echo-theory-labs
claude plugin install secure-claude@echo-theory-labs
```

Full install, configuration, architecture, and JSONL schema docs live at the
[documentation site](https://echotheorylabsai.github.io/echo-claude-dev/).

## License

MIT — see [`secure-claude/LICENSE`](./secure-claude/) for details.
