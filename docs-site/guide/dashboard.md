# Dashboard

Open `secure-claude/log-viewer/dashboard.html` in any modern browser. Drag-drop your
`governance-audit.jsonl` file (or click **Load Log**).

All processing is client-side — no data leaves the browser. No build step, no server.

## Features

| Panel | What it shows |
|-------|---------------|
| **KPI summary** | Total events · threats · indirect threats · denies · prompts scanned · config errors |
| **Event timeline** | Color-coded bar chart of event distribution over time (auto-bucketed) |
| **Event type chart** | Count per event type, sorted by frequency |
| **Tool decisions** | Allow vs. deny count per tool, color-coded |
| **Threat categories** | Category count and max severity — red ≥ 0.9, amber ≥ 0.7 |
| **Event log** | Filterable, searchable, paginated; expand any row for full JSON |
| **Export** | Download the currently-filtered events as JSON |

## Filtering

Click any event-type chip to toggle that category. Use the search box for full-text
search across the whole JSON record (not just rendered fields).

## File location

```text
~/echo-theory-labs/secure-claude/logs/<project>/governance-audit.jsonl
```

`<project>` is the git repo basename, sanitized to `[A-Za-z0-9_.-]` and truncated
to 128 chars. If you are not inside a git repo, the working-directory basename is
used (with the same sanitization).
