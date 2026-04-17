# secure-copilot

Governance hooks for GitHub Copilot CLI sessions — **log** lifecycle events, **scan** prompts and tool outputs for threat signals, and **gate** dangerous tool invocations before they execute.

```bash
copilot plugin install ./catalog/security/plugins/secure-copilot
```

**Prerequisites:**

| Component | Required for |
|-----------|-------------|
| `jq` | All bash hooks (JSON processing) |
| `perl` | PCRE pattern matching in bash hooks |
| PowerShell 7+ | Windows hooks (no other external dependencies) |
| `python3` + `PyYAML` | Config compilation only (not needed at runtime) |

---

## How It Works

The plugin wires into five Copilot CLI lifecycle events. Each event triggers one or more hook scripts that scan, log, or gate activity around the Copilot session.

```
                            ┌──────────────────────────┐
                            │      Copilot CLI         │
                            └────────────┬─────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
         ▼                               ▼                               ▼
  ┌─────────────┐               ┌───────────────────┐           ┌──────────────┐
  │sessionStart │               │userPromptSubmitted│           │  preToolUse  │
  │             │               │                   │           │              │
  │ log-session │               │   scan-prompt-    │           │  (2 hooks)   │
  │ -start.sh   │               │   injection.sh    │           │              │
  │             │               │                   │           │ 1. log-pre-  │
  │ Logs cwd    │               │   6 threat        │           │ tool-use.sh  │
  └──────┬──────┘               │   categories      │           │ (audit only) │
         │                      │   POSIX + PCRE    │           │              │
         │                      │   exit 1 on       │           │ 2. gate-pre- │
         │                      │   detection       │           │ tool-use.sh  │
         │                      │   (audit signal)  │           │ (allow/deny) │
         │                      └───────┬───────────┘           └──────┬───────┘
         │                              │                              │
         │                              ▼                    ┌─────────┴────────┐
         │           not enforced by current runtime         │                  │
         │                                                  allow             deny
         │                                                 (silent)     ┌───────────┐
         │                                                              │ stdout:   │
         │                                                              │ deny JSON │
         │                                                              └───────────┘
         │
         │            ┌────────────────┐                ┌─────────────┐
         │            │  postToolUse   │                │ sessionEnd  │
         │            │                │                │             │
         │            │ scan-post-tool │                │ log-session │
         │            │ -injection.sh  │                │ -end.sh     │
         │            │                │                │             │
         │            │ 4 indirect     │                │ Summary     │
         │            │ injection      │                │ counts for  │
         │            │ categories     │                │ the session │
         │            │ (PCRE only)    │                └──────┬──────┘
         │            │ exit 1 on      │                       │
         │            │ detection      │                       │
         │            │ (audit signal) │                       │
         │            └───────┬────────┘                       │
         │                    │                                │
         │                    ▼                                │
         │      not enforced by current runtime                │
         │                                                     │
         └──────────────────────┬──────────────────────────────┘
                                ▼
                  ┌───────────────────────────┐
                  │  governance-audit.jsonl   │
                  │  (append-only audit log)  │
                  └───────────────────────────┘
```

**Naming convention:** `log-*` = audit records only · `scan-*` = inspect content + log findings · `gate-*` = enforce deny decisions.

> Copilot CLI selects `bash` (macOS/Linux) or `powershell` (Windows) automatically via `hooks.json`.

---

## Enforcement Model

| Hook stage | Behavior | Runtime effect |
|------------|----------|----------------|
| `userPromptSubmitted` | Scan prompt, log threat details, exit `1` on detection | **Audit signal only** — Copilot CLI does not reliably block on this hook's exit code |
| `preToolUse` | Log tool request, then emit allow/deny JSON | **Real enforcement** — deny JSON blocks the tool call |
| `postToolUse` | Scan tool output, log threat details, exit `1` on detection | **Audit signal only** — Copilot CLI ignores this hook's output and exit code |

> **Key point:** `gate-pre-tool-use` is the only reliable enforcement hook in the current Copilot CLI runtime. The scanners still exit non-zero on detections so local harnesses and audit pipelines can treat them as signals, but they do not block the agent by themselves.

---

## Prompt Scanning (`userPromptSubmitted`)

`scan-prompt-injection.sh` evaluates every user prompt against heuristic regex rules across **6 threat categories**:

| Category | Signals detected | Severity |
|----------|-----------------|----------|
| `data_exfiltration` | Bulk data transfer, explicit exfiltration intent, HTTP POST with data, sensitive uploads | 0.70 – 0.95 |
| `privilege_escalation` | `sudo` / root access, `chmod 777`, adding users to sudoers/administrators | 0.80 – 0.95 |
| `system_destruction` | `rm -rf /`, `DROP DATABASE`, `TRUNCATE TABLE`, mass wipe intent | 0.90 – 0.95 |
| `prompt_injection` | Instruction overrides, role reassignment, `system: you are` prefix | 0.60 – 0.90 |
| `credential_exposure` | Hardcoded API keys/passwords/tokens, AWS access key patterns (`AKIA…`) | 0.90 – 0.95 |
| `encoding_obfuscation` | Zero-width Unicode, Cyrillic homoglyphs, base64 decode+execute, hex escape sequences | 0.85 – 0.95 |

**Regex engines** — rules specify `posix` (default) or `pcre` via the `engine` field:
- **`posix`** — matched by `grep -E` (bash) or .NET regex (PowerShell)
- **`pcre`** — matched by `perl` (bash) or .NET regex natively (PowerShell). Used for Unicode character class rules (zero-width chars, homoglyphs).

---

## Tool Gating (`preToolUse`)

Two hooks fire in sequence on every tool invocation:

1. **`log-pre-tool-use.sh`** — Audit-only. Normalizes `toolArgs` (string → JSON), truncates long bash commands (>200 chars), logs tool name + branch + args. **Never blocks.**
2. **`gate-pre-tool-use.sh`** — Evaluates deny rules. On match, emits `{"permissionDecision":"deny", …}` JSON to stdout. On allow, logs the decision but produces **no stdout**.

**Gated tools:** `bash`, `edit`, `create`

### `bash` deny rules (7 rules)

| Rule ID | Blocked patterns |
|---------|-----------------|
| `bash-destructive-file-ops` | `rm -rf`, `dd if/of=`, `mkfs`, `sudo rm` |
| `bash-protected-file-deletion` | Deleting `.env*` files or `.git/` directory |
| `bash-destructive-git-operation` | `git push --force` to `main`/`master`, `git reset --hard`, `git clean -fd` |
| `bash-destructive-database-operation` | `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, bare `DELETE FROM <table>;` |
| `bash-fork-bomb` | Classic fork-bomb pattern |
| `bash-remote-script-pipe` | `curl … \| bash`, `wget … \| sh` |
| `bash-network-exposure` | `nc -l`, `python -m http.server`, `php -S`, `ruby -run -e httpd` |

### `edit` / `create` deny rules (2 rules)

| Rule ID | Blocked patterns |
|---------|-----------------|
| `edit-sensitive-file` | Paths matching `.env`, `secrets`, `credentials`, `.ssh/`, `.aws/credentials`, `.npmrc`, `.pypirc` |
| `create-system-path` | Paths under `/etc/`, `/bin/`, `/sbin/`, `/usr/bin/` |

---

## Indirect Injection Scanning (`postToolUse`)

`scan-post-tool-injection.sh` inspects `toolResult.textResultForLlm` from every tool call for **indirect prompt injection** — malicious instructions embedded in content returned by tools (files, web pages, MCP server responses).

All patterns use the **PCRE** engine. Tool outputs shorter than **10 characters** are skipped.

| Category | Signals detected | Severity |
|----------|-----------------|----------|
| `instruction_override` | "Ignore previous instructions", fake system prompts, fake `[/system]`/`</system>` markers, delimiter-based overrides | 0.70 – 0.95 |
| `role_playing_dan` | DAN jailbreak, restriction/safety bypass, "developer mode enabled", evil/unrestricted persona switch | 0.90 – 0.95 |
| `encoding_obfuscation` | Zero-width Unicode, Unicode whitespace manipulation, Cyrillic homoglyphs, base64 decode+execute, hex escape sequences | 0.70 – 0.95 |
| `context_manipulation` | HTML comment injection, code comment injection, fake JSON `{"role":"system"}`, false AI company authority claims, fake `[INST]`/`[SYS]` markers | 0.90 – 0.95 |

---

## Attack Category Coverage Matrix

The matrix below shows **which detection stage** covers each attack vector and the runtime behavior.

```
Detection Stage:   🔍 = Prompt Scan    🚧 = Tool Gate    🔬 = Post-Tool Scan
Behavior:          ● = Blocks via deny JSON   ○ = Audit/log signal only
```

| Attack Vector | 🔍 Prompt | 🚧 Tool Gate | 🔬 Post-Tool | Severity Range |
|:---|:---:|:---:|:---:|:---:|
| **Data Exfiltration** | | | | |
| ├ Bulk data transfer | ○ | | | 0.85 |
| ├ Explicit exfiltration intent | ○ | | | 0.95 |
| ├ HTTP POST with data (`curl -d`) | ○ | | | 0.70 |
| └ Sensitive uploads | ○ | | | 0.95 |
| **Privilege Escalation** | | | | |
| ├ `sudo` / root access | ○ | | | 0.80 |
| ├ `chmod 777` | ○ | | | 0.90 |
| └ Sudoers / admin group modification | ○ | | | 0.95 |
| **System Destruction** | | | | |
| ├ `rm -rf /` | ○ | ● | | 0.95 |
| ├ `DROP TABLE` / `DROP DATABASE` / `TRUNCATE` | ○ | ● | | 0.90 |
| └ Mass wipe intent | ○ | | | 0.90 |
| **Prompt Injection** | | | | |
| ├ Instruction override | ○ | | ○ | 0.90 – 0.95 |
| ├ Role reassignment | ○ | | | 0.70 |
| └ System prompt prefix | ○ | | | 0.60 |
| **Credential Exposure** | | | | |
| ├ Hardcoded credentials | ○ | | | 0.90 |
| └ AWS key patterns (`AKIA…`) | ○ | | | 0.95 |
| **Encoding Obfuscation** | | | | |
| ├ Zero-width / invisible Unicode | ○ | | ○ | 0.95 |
| ├ Cyrillic homoglyphs | ○ | | ○ | 0.90 |
| ├ Base64 decode + execute | ○ | | ○ | 0.90 |
| └ Hex escape sequences | ○ | | ○ | 0.70 – 0.85 |
| **Destructive Tool Use** | | | | |
| ├ Destructive file ops | | ● | | — |
| ├ Protected file deletion (`.env*`, `.git/`) | | ● | | — |
| ├ Force-push to `main`/`master` | | ● | | — |
| ├ Fork bomb | | ● | | — |
| ├ Remote script pipe (`curl \| bash`) | | ● | | — |
| ├ Network server exposure | | ● | | — |
| ├ Sensitive file edits | | ● | | — |
| └ System path file creation | | ● | | — |
| **Indirect Injection** | | | | |
| ├ Fake system prompts / delimiters | | | ○ | 0.70 – 0.95 |
| ├ DAN / jailbreak personas | | | ○ | 0.90 – 0.95 |
| ├ HTML / code comment injection | | | ○ | 0.90 – 0.95 |
| ├ Fake JSON `{"role":"system"}` | | | ○ | 0.90 |
| ├ False AI company authority claims | | | ○ | 0.90 |
| └ Restriction / safety bypass | | | ○ | 0.90 |

**Legend:** ● Real runtime block via `preToolUse` deny JSON · ○ Audit/log signal only · Blank = not covered at this stage.

---

## Config Model

### File Layout

```text
hooks/
├── hooks.json                            ← hook wiring (event → script mapping)
├── config/
│   ├── user-prompt-threats.yaml           ← human-edited prompt scan rules
│   ├── tool-rules.yaml                   ← human-edited tool gate rules
│   ├── indirect-injection-patterns.yaml  ← human-edited indirect injection rules
│   └── generated/
│       ├── user-prompt-threats.json      ← compiled runtime artifact
│       ├── tool-rules.json               ← compiled runtime artifact
│       └── indirect-injection-patterns.json ← compiled runtime artifact
└── scripts/
    ├── compile-config.py                 ← YAML → JSON compiler
    ├── bash/                             ← macOS / Linux hooks
    │   ├── common-config.sh              ← shared path resolution & logging
    │   ├── common-scanner.sh             ← shared scanning & threat assembly
    │   ├── log-session-start.sh
    │   ├── scan-prompt-injection.sh
    │   ├── log-pre-tool-use.sh
    │   ├── gate-pre-tool-use.sh
    │   ├── scan-post-tool-injection.sh
    │   └── log-session-end.sh
    └── powershell/                       ← Windows hooks (same filenames, .ps1)
        └── …

~/.config/secure-copilot/                 ← optional user-local config
├── overrides.yaml                        ← additive rules (cannot weaken shipped IDs)
└── generated/
    ├── user-prompt-threats.json          ← compiled local prompt overrides
    ├── tool-rules.json                   ← compiled local tool overrides
    └── indirect-injection-patterns.json  ← compiled local indirect injection overrides
```

### Config Compilation Flow

```
  ┌──────────────────────┐         ┌───────────────────────┐
  │  user-prompt-threats │         │  overrides.yaml       │
  │  tool-rules.yaml     │         │  (~/.config/secure-   │
  │  indirect-injection- │         │   copilot/)           │
  │  patterns.yaml       │         │                       │
  └──────────┬───────────┘         └───────────┬───────────┘
             │                                 │
             ▼                                 ▼
  ┌────────────────────────────────────────────────────────┐
  │              compile-config.py                         │
  │                                                        │
  │  • Validates YAML structure & regex syntax             │
  │  • Merges global → category → rule defaults            │
  │  • Rejects duplicate IDs                               │
  │  • Rejects overrides that reuse shipped rule IDs       │
  │  • Outputs flat JSON arrays                            │
  └──────────┬─────────────────────────────┬───────────────┘
             │                             │
     --mode shipped                --mode local
             │                             │
             ▼                             ▼
  ┌──────────────────┐          ┌──────────────────────┐
  │ hooks/config/    │          │ ~/.config/secure-    │
  │ generated/*.json │          │ copilot/generated/   │
  │ (shipped rules)  │          │ *.json (additive)    │
  └──────────────────┘          └──────────────────────┘
```

**Key rules:**
- Hooks read **only** the generated JSON at runtime — never the YAML directly.
- Local overrides may **add** new rules but may **not** replace or weaken shipped rule IDs. The compiler rejects any override that reuses a shipped ID.
- If local generated JSON is malformed, hooks fall back to the shipped baseline and log a `configError`.

### Compile Commands

Install the compiler dependency:

```bash
python3 -m pip install -r catalog/security/plugins/secure-copilot/requirements.txt
```

Regenerate shipped JSON after editing any YAML source (compiles all three config files):

```bash
python3 catalog/security/plugins/secure-copilot/hooks/scripts/compile-config.py --mode shipped
```

Verify generated JSON is up to date (fails if stale):

```bash
python3 catalog/security/plugins/secure-copilot/hooks/scripts/compile-config.py --mode shipped --check
```

Compile optional local overrides from `~/.config/secure-copilot/overrides.yaml`:

```bash
python3 catalog/security/plugins/secure-copilot/hooks/scripts/compile-config.py --mode local
```

---

## Audit Log

All events are appended to a single JSONL file:

```text
~/progress-ai/secure-copilot/logs/<project>/governance-audit.jsonl
```

`<project>` = git repository root basename (e.g., `ai-dev-accelerator`), or working directory basename if not in a git repo.

### Event Types

| Event | Source hook | Description |
|-------|-----------|-------------|
| `sessionStart` | `log-session-start` | Working directory for the current session |
| `promptScanned` | `scan-prompt-injection` | Clean prompt — no threats found |
| `threatDetected` | `scan-prompt-injection` | Matched threats with category, severity, and evidence |
| `preToolUse` | `log-pre-tool-use` | Tool name, git branch, and normalized arguments |
| `preToolDecision` | `gate-pre-tool-use` | Allow or deny decision with reason |
| `postToolScanned` | `scan-post-tool-injection` | Clean tool output — no indirect threats |
| `indirectThreatDetected` | `scan-post-tool-injection` | Indirect injection threats with category, severity, and evidence |
| `configError` | Any hook | Unreadable generated JSON or config failures |
| `sessionEnd` | `log-session-end` | Summary counts (total events, threats) scoped to this session |

```bash
# Find all governance logs on disk
find ~/progress-ai/secure-copilot/logs -name "governance-audit.jsonl"
```

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Shipped prompt JSON unreadable | Logs `configError`, exits 1 |
| Shipped indirect-injection JSON unreadable | Logs `configError`, exits 1 |
| Shipped tool JSON unreadable | Logs `configError`, emits deny JSON (fail-closed) |
| Local generated JSON unreadable | Logs `configError`, falls back to shipped baseline |
| Malformed `toolArgs` string | Normalized to `{}`, logged normally, **not denied** |
| `SKIP_GOVERNANCE_AUDIT=true` | All hooks exit 0 immediately — no audit records written |

---

## Local Simulation

Run the full test harness without a global plugin install:

```bash
bash catalog/security/plugins/secure-copilot/scripts/simulate-hooks.sh
```

```powershell
pwsh -NoProfile -File catalog/security/plugins/secure-copilot/scripts/simulate-hooks.ps1
```

The bash and PowerShell simulators together exercise **200+ assertion checks** covering:
- Config compilation, stale-artifact rejection, and parity checks
- Clean prompt logging and threat detection with non-zero audit signaling
- Allow/deny for all 9 tool gate rules (destructive bash, protected files, git, DB, fork bombs, remote pipes, network, sensitive edits, system paths)
- Indirect injection scanning: clean outputs, instruction overrides, DAN jailbreaks, HTML/code comment injection, fake JSON system roles, and audit signaling
- Encoding obfuscation detection (base64 decode+execute, hex escape sequences)
- Local override compilation, runtime loading, and weakening-override rejection
- Malformed config fallback (local → shipped baseline, shipped → fail-closed)
- Malformed `toolArgs` normalization
- `sessionEnd` summary count validation

> This is a local harness for the hook scripts, not a substitute for end-to-end testing inside an installed Copilot runtime.

### Keeping Simulated Logs

```bash
KEEP_TMP=1 bash catalog/security/plugins/secure-copilot/scripts/simulate-hooks.sh
```

```powershell
$env:KEEP_TMP = "1"; pwsh -NoProfile -File catalog/security/plugins/secure-copilot/scripts/simulate-hooks.ps1
```

When `KEEP_TMP=1` is set, the cleanup step prints the temp home path. The log file is then available at `<tmp-home>/progress-ai/secure-copilot/logs/ai-dev-accelerator/governance-audit.jsonl`.

---

## Governance Audit Dashboard

Viewer assets live under `catalog/security/plugins/secure-copilot/log-viewer/`:

- `dashboard.html` — interactive governance log dashboard
- `example-governance-audit.jsonl` — sample log file for local preview

```bash
open catalog/security/plugins/secure-copilot/log-viewer/dashboard.html
```

[![secure-copilot dashboard preview](../../../../examples/secure-copilot-dashboard.gif)](../../../../examples/secure-copilot-dashboard.gif)

Load a `governance-audit.jsonl` file via **drag-and-drop** or the **Load Log** button.

| Feature | Description |
|---------|-------------|
| **KPI summary** | Total events, threats, indirect threats, denies, prompts scanned, config errors |
| **Event timeline** | Color-coded bar chart of event distribution over time |
| **Breakdown charts** | Event types, tool decisions (allow/deny by tool), threat categories with severity |
| **Filterable event log** | Event-type chip filters, full-text search, expandable JSON rows, sortable columns, pagination |
| **Export** | Download filtered events as JSON |

All processing is client-side — no data leaves the browser.

---

## Sample Hook Outputs

Session start:
```text
🛡️ Governance audit active
```

Prompt threat detected:
```text
⚠️ Governance: 1 threat signal(s) detected
  🔴 [prompt_injection] Instruction override (severity: 0.9)
(max severity: 0.9)
🚫 Prompt flagged by governance audit
```

Tool denied:
```json
{
  "permissionDecision":"deny",
  "permissionDecisionReason":"Blocked dangerous command: destructive file operations detected"
}
```

Indirect injection detected in tool output:
```text
⚠️ Indirect injection: 1 threat signal(s) detected in tool output
  🔴 [instruction_override] Ignore previous instructions (severity: 0.95)
(max severity: 0.95)
🚫 Indirect injection flagged by governance audit
```

Config error fallback:
```json
{
  "timestamp":"...",
  "event":"configError",
  "source":"gate-pre-tool-use",
  "message":"local tool config unreadable; using shipped baseline: ..."
}
```

---

## Limits

- Regex-based detection is heuristic — treat scanners as best-effort, not complete threat coverage.
- `gate-pre-tool-use` is the only reliable enforcement point. Prompt and indirect injection scanners are advisory, even though they exit non-zero on detections.
- Bash hooks require `jq` and `perl` (for PCRE). PowerShell hooks need only PowerShell 7+ (uses native .NET regex and JSON cmdlets).
- PowerShell hooks translate POSIX ERE character classes (e.g., `[[:space:]]`) to .NET equivalents at load time. PCRE patterns skip this translation since .NET regex supports them natively.

---

## Future Ideas

- Project-specific deny-rule policies
- Additional threat categories and test fixtures
- Richer per-session governance reports
