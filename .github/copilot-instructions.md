# Copilot instructions (IS305/deal-monitor)

## Big picture
- Main runner is the PowerShell script [deal-monitor.ps1](../deal-monitor.ps1). It:
  - Loads settings from [config.json](../config.json)
  - Loads keywords from [keywords.txt](../keywords.txt) (preferred UX)
  - Fetches deals from `sources` (most reliable: `type: "reddit"` via Reddit public JSON)
  - Filters + scores matches, sends Discord webhook notifications
  - Dedupes using [history.json](../history.json) (MD5-like 32-hex IDs)
  - Writes daily logs to [logs/](../logs/)

- Optional Discord “control channel” exists in two modes:
  - Polling mode (PowerShell): `Try-ApplyDiscordControl` reads recent channel messages on each run and updates `keywords.txt` / filters.
  - Instant mode (C# bot): [control-bot/Program.cs](../control-bot/Program.cs) is an always-on Discord gateway bot that applies commands immediately.

## Key files and conventions
- [config.json](../config.json)
  - `discord_webhook_url`: send-only notifications (treat as secret)
  - `filters`: `max_price` (number or `null`), `min_discount_percent` (int or `null`)
  - `sources`: prefer `{"type":"reddit","subreddit":"buildapcsales"}`; RSS/scraping are less reliable.
  - `discord_control`: `{ enabled, channel_id, token_env, allowed_user_ids, ack }`
- [keywords.txt](../keywords.txt)
  - One keyword per line; `#` comments allowed.
  - Keyword priority in PowerShell: CLI `-Keywords` → `keywords.txt` → `config.json` keywords.
- [history.json](../history.json)
  - Stores string IDs; loader is intentionally repair-tolerant (it extracts any 32-hex tokens and rewrites a clean JSON array).
- [control_state.json](../control_state.json)
  - Stores the last processed Discord control message id (prevents reprocessing).

## Running locally
- Deal monitor (PowerShell 5.1+):
  - `powershell.exe -ExecutionPolicy Bypass -File .\deal-monitor.ps1`
  - Useful flags: `-KeywordsFile`, `-Keywords`, `-MaxPrice`, `-MinDiscountPercent`, `-ConfigureKeywords`
- Test webhook quickly: [test-notification.ps1](../test-notification.ps1)
- Instant control bot (.NET 8): see [control-bot/README.md](../control-bot/README.md)
  - Requires env var `DISCORD_BOT_TOKEN` (do not store tokens in git/config)
  - Optionally set `DEAL_MONITOR_DIR` to point at the repo root so the bot finds `config.json`/`keywords.txt`
  - The Discord app must have **Message Content Intent** enabled.

## Scheduling (Windows)
- Use Task Scheduler to run the PowerShell script; examples live in [TASK_SCHEDULER_SETUP.md](../TASK_SCHEDULER_SETUP.md) but paths are machine-specific—update `E:\...\deal-monitor` accordingly.

## Debugging and gotchas
- Logs: check [logs/](../logs/) for `deal-monitor_YYYY-MM-DD.log`.
- Windows PowerShell 5.1 UTF-8: Discord REST calls must send UTF-8 JSON bytes (see `Invoke-DiscordApi`), otherwise Discord may reject payloads.
- If the C# bot shows gateway `401 Unauthorized`, the token env var is missing/incorrect in *that* process context.

## When changing code
- Keep PowerShell compatible with 5.1 (TLS 1.2 setup, avoid PS7-only syntax).
- Preserve history/dedupe behavior (don’t regress `Load-History` repair + `Save-History` trimming).
- Avoid adding brittle store-specific scraping; prefer Reddit JSON or explicit JSON endpoints.
