# Copilot instructions (IS305/deal-monitor)

## Big picture
- Main runner is the PowerShell script [deal-monitor.ps1](../deal-monitor.ps1). It:
  - Loads settings from [config.json](../config.json)
  - Loads keywords from [keywords.txt](../keywords.txt) (preferred UX)
  - Supports **multi-watch** mode: each watch in `config.watches[]` has its own name, keywords, max_price, min_discount_percent. Falls back to legacy single-keyword mode if no watches defined.
  - Fetches deals from `sources` (most reliable: `type: "reddit"` via Reddit public JSON)
  - Filters + scores matches via `Filter-Deal` (iterates watches, first match wins)
  - Sends Discord webhook notifications (UTF-8 bytes, with 429 rate-limit retry)
  - Dedupes using [history.json](../history.json) (MD5-like 32-hex IDs, crash-safe per-send saves)
  - Writes daily logs to [logs/](../logs/) with auto-rotation (deletes logs older than 30 days)
  - Supports Reddit flair/category filtering via `-Flairs` CLI param or `filters.flairs` config

- Optional Discord "control channel" exists in two modes:
  - Polling mode (PowerShell): `Try-ApplyDiscordControl` reads recent channel messages on each run and updates `keywords.txt` / filters / watches.
  - Instant mode (C# bot): [control-bot/Program.cs](../control-bot/Program.cs) is an always-on Discord gateway bot that applies commands immediately.

## Key files and conventions
- [config.json](../config.json)
  - `discord_webhook_url`: send-only notifications (treat as secret)
  - `filters`: `max_price` (number or `null`), `min_discount_percent` (int or `null`), `flairs` (array of strings or `null`)
  - `sources`: prefer `{"type":"reddit","subreddit":"buildapcsales"}`; supports multiple subreddits. RSS/scraping are less reliable.
  - `discord_control`: `{ enabled, channel_id, token_env, allowed_user_ids, ack }`
  - `watches`: array of `{ name, keywords[], max_price, min_discount_percent }` — each watch is an independent search group with its own filters
- [keywords.txt](../keywords.txt)
  - One keyword per line; `#` comments allowed.
  - Keyword priority in PowerShell: CLI `-Keywords` → `keywords.txt` → `config.json` keywords.
  - Keywords are **case-insensitive** (PowerShell `-match` is case-insensitive by default).
- [history.json](../history.json)
  - Stores string IDs; loader is intentionally repair-tolerant (it extracts any 32-hex tokens and rewrites a clean JSON array).
  - Saved after each notification send (crash-safe), not batched at end of run.
- [control_state.json](../control_state.json)
  - Stores the last processed Discord control message id (prevents reprocessing).

## Discord bot commands
The C# bot supports these commands in the control channel:
- `!help` — Full command reference with descriptions and notes
- `!keywords set kw1, kw2` / `!keywords show` — Manage simple keywords
- `!watch add Name | kw1, kw2 | max:500 | discount:15` — Create/update a watch group
- `!watch list` / `!watch remove Name` / `!watch clear` — Manage watches
- `!maxprice 200` / `!mindiscount 15` — Set global filters
- `!scan` — Run deal-monitor.ps1 on-demand (passes `-SkipDiscordControl` to avoid polling loop; prevents concurrent scans; reports summary back to Discord)
- `!clearhistory` — Reset seen-deals history so all deals re-send
- `!status` / `!ping`

## Running locally
- Deal monitor (PowerShell 5.1+):
  - `powershell.exe -ExecutionPolicy Bypass -File .\deal-monitor.ps1`
  - Useful flags: `-KeywordsFile`, `-Keywords`, `-Flairs`, `-MaxPrice`, `-MinDiscountPercent`, `-ConfigureKeywords`, `-SkipDiscordControl`
- Test webhook quickly: [test-notification.ps1](../test-notification.ps1)
- Instant control bot (.NET 8): see [control-bot/README.md](../control-bot/README.md)
  - Requires env var `DISCORD_BOT_TOKEN` (do not store tokens in git/config)
  - Optionally set `DEAL_MONITOR_DIR` to point at the repo root so the bot finds `config.json`/`keywords.txt`
  - The Discord app must have **Message Content Intent** enabled.
  - **Only run one bot instance at a time** — multiple instances cause duplicate Discord responses.

## Scheduling (Windows)
- Use Task Scheduler to run the PowerShell script; examples live in [TASK_SCHEDULER_SETUP.md](../TASK_SCHEDULER_SETUP.md) but paths are machine-specific—update `E:\...\deal-monitor` accordingly.

## Debugging and gotchas
- Logs: check [logs/](../logs/) for `deal-monitor_YYYY-MM-DD.log`.
- Windows PowerShell 5.1 UTF-8: Discord REST calls must send UTF-8 JSON bytes (see `Invoke-DiscordApi`), otherwise Discord may reject payloads.
- If the C# bot shows gateway `401 Unauthorized`, the token env var is missing/incorrect in *that* process context.
- Price parsing regex: `\$\s*(\d[\d,]*(?:\.\d{1,2})?)` — handles prices like `$1149.99`, `$1,299.00`, `$50`.
- Multiple bot instances: Kill all `dotnet`/`control-bot` processes before starting a new one to avoid duplicate responses.
- `!scan` runs the PS script with `-SkipDiscordControl` so it doesn't poll Discord and respond to stale messages during a bot-triggered scan.

## When changing code
- Keep PowerShell compatible with 5.1 (TLS 1.2 setup, avoid PS7-only syntax).
- Preserve history/dedupe behavior (don't regress `Load-History` repair + `Save-History` trimming).
- Preserve crash-safe history saves (save after each send, not batched).
- Avoid adding brittle store-specific scraping; prefer Reddit JSON or explicit JSON endpoints.
- When adding watch commands, update both PowerShell `Try-ApplyDiscordControl` and C# bot `OnMessageReceivedAsync`.
