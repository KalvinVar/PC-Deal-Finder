# Deal Monitor - Automated Deal Alerts via Discord

A PowerShell-based deal monitoring system that tracks Reddit and other deal sources, filters by keywords and criteria, scores deals by "hotness", and sends notifications to Discord. Includes a C# Discord bot for instant remote control.

## Features

✅ **Multi-Source Support** - Monitor multiple subreddits, RSS feeds, and JSON endpoints  
✅ **Multi-Watch System** - Create independent search groups (e.g., GPUs under $1200 AND monitors under $200) each with their own keywords and filters  
✅ **Smart Filtering** - Filter by keywords, max price, minimum discount %, and Reddit flairs  
✅ **Hotness Scoring** - Automatically scores deals based on discount %, price threshold, and keyword relevance  
✅ **Discord Notifications** - Rich embedded notifications with color-coded urgency  
✅ **Discord Bot Control** - Always-on C# bot for instant command responses (`!scan`, `!watch`, `!clearhistory`, etc.)  
✅ **On-Demand Scanning** - Type `!scan` in Discord to run the monitor immediately  
✅ **Duplicate Prevention** - Tracks sent deals with crash-safe per-send history saves  
✅ **Rate Limit Handling** - Automatic retry with Discord 429 rate limits  
✅ **Log Rotation** - Daily log files with auto-cleanup of logs older than 30 days  
✅ **Task Scheduler Ready** - Designed for automated Windows Task Scheduler execution  

## Quick Start

### 1. Prerequisites

- **Windows 10/11** with PowerShell 5.1+
- **Discord Webhook URL** (see setup below)
- **.NET 8 SDK** (optional, for the Discord control bot)

### 2. Get Your Discord Webhook URL

1. Open Discord → your server
2. Right-click the channel → **Edit Channel** → **Integrations** → **Webhooks** → **New Webhook**
3. Click **Copy Webhook URL**

### 3. Configure

Copy `config.example.json` to `config.json` and fill in your webhook URL.

**Simple mode** — edit `keywords.txt` (one keyword per line):

```text
DDR5
48GB
RAM
```

**Watch mode** — add watches to `config.json` for independent search groups:

```json
{
  "watches": [
    {
      "name": "GPU",
      "keywords": ["5080", "5070 ti"],
      "max_price": 1200,
      "min_discount_percent": 0
    },
    {
      "name": "MONITOR",
      "keywords": ["1440p", "4K", "OLED"],
      "max_price": 300,
      "min_discount_percent": 10
    }
  ]
}
```

Each watch has its own keywords and price/discount filters. Watches take priority over simple keywords when both are set.

**Configuration Options:**

| Field | Description |
|-------|-------------|
| `discord_webhook_url` | Your Discord webhook URL (required) |
| `keywords` | Legacy keyword array (case-insensitive). Used if no watches defined. |
| `watches` | Array of watch groups, each with `name`, `keywords[]`, `max_price`, `min_discount_percent` |
| `filters.max_price` | Global max price fallback (number or `null`) |
| `filters.min_discount_percent` | Global min discount % fallback (number or `null`) |
| `filters.flairs` | Reddit flair filter (array of strings or `null`) |
| `sources` | Array of deal sources (Reddit subreddits, RSS feeds, JSON endpoints) |
| `discord_control` | Bot control settings (see Discord Bot section) |

### 4. Test Run

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\deal-monitor.ps1
```

You should see log messages, matching deals sent to Discord, and `history.json` created.

### 5. CLI Flags

```powershell
.\deal-monitor.ps1 -Keywords "DDR5","48GB" -MaxPrice 240
.\deal-monitor.ps1 -Flairs "GPU","CPU"
.\deal-monitor.ps1 -ConfigureKeywords          # interactive keyword setup
.\deal-monitor.ps1 -SkipDiscordControl          # skip Discord polling (used by bot's !scan)
```

## Discord Bot (Remote Control)

### Why a Bot?

Discord webhooks are **send-only**. To receive commands in Discord (change keywords, trigger scans, etc.), you need a bot.

### Setup

1. Create a bot in the [Discord Developer Portal](https://discord.com/developers/applications)
2. Enable **Message Content Intent** under the bot settings
3. Invite it to your server with permissions: View Channel, Read Message History, Send Messages
4. Set your bot token as an environment variable:
   ```powershell
   [Environment]::SetEnvironmentVariable('DISCORD_BOT_TOKEN', 'YOUR_TOKEN', 'User')
   ```
5. Configure `discord_control` in `config.json`:
   ```json
   "discord_control": {
     "enabled": true,
     "channel_id": "YOUR_CHANNEL_ID",
     "token_env": "DISCORD_BOT_TOKEN",
     "allowed_user_ids": ["YOUR_USER_ID"],
     "ack": true
   }
   ```

### Running the Bot

```powershell
cd control-bot
$env:DISCORD_BOT_TOKEN = [Environment]::GetEnvironmentVariable('DISCORD_BOT_TOKEN', 'User')
$env:DEAL_MONITOR_DIR = "E:\IS305\deal-monitor"
dotnet run -c Release
```

> **Important:** Only run one bot instance at a time — multiple instances cause duplicate responses.

### Bot Commands

| Command | Description |
|---------|-------------|
| `!help` | Full command reference with examples and notes |
| `!scan` | Run the deal monitor immediately and report results |
| `!clearhistory` | Reset seen-deals history so all deals re-send |
| `!watch add Name \| kw1, kw2 \| max:500 \| discount:15` | Create/update a watch group |
| `!watch list` | Show all active watches with their filters |
| `!watch remove Name` | Delete a watch by name |
| `!watch clear` | Remove all watches |
| `!keywords set kw1, kw2, kw3` | Replace simple keywords (comma-separated) |
| `!keywords show` | Show current keywords |
| `!maxprice 200` | Set global max price filter |
| `!mindiscount 15` | Set global min discount % filter |
| `!status` | Show current config summary |
| `!ping` | Check if bot is alive |

**Examples:**
```
!watch add GPU | 5080, 5070 ti | max:1200
!watch add MONITOR | 1440p, 4K | max:300 | discount:10
!watch list
!scan
!clearhistory
```

## Multi-Watch System

Watches let you search for different product categories with independent filters:

```
GPU watch:     keywords=["5080"]      max=$1200  discount=0%
MONITOR watch: keywords=["1440p"]     max=$165   discount=0%
CPU watch:     keywords=["9800X3D"]   max=$500   discount=10%
```

- First matching watch wins for each deal
- Each watch's price/discount filters are independent
- Discord notifications show which watch matched: `[GPU] RTX 5080 - $1149.99`
- If no watches are defined, falls back to legacy `keywords` + `filters` mode

## How Hotness Scoring Works

Each deal gets a "hotness score" (0-100 points):

| Factor | Points |
|--------|--------|
| Discount % | Up to 50 pts (1:1 with discount %) |
| Price < $100 | +20 pts |
| Price $100–$299 | +15 pts |
| Price $300–$499 | +10 pts |
| Price $500–$999 | +5 pts |
| Keyword matches | +5 pts each (max 30) |

**Discord Color Coding:**
- 🔴 **Red** (70+) — HOT DEAL
- 🟠 **Orange** (50–69) — Great deal
- 🔵 **Blue** (30–49) — Good deal
- ⚪ **Gray** (0–29) — Decent deal

## Schedule Automatic Runs

### Task Scheduler (GUI)

1. Open **Task Scheduler** → **Create Basic Task**
2. Name: "Deal Monitor"
3. Trigger: Repeat every 2 hours (or your preference)
4. Action: Start a program
   - Program: `powershell.exe`
   - Arguments: `-ExecutionPolicy Bypass -File "E:\IS305\deal-monitor\deal-monitor.ps1"`
   - Start in: `E:\IS305\deal-monitor`

### Task Scheduler (PowerShell)

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument '-ExecutionPolicy Bypass -File "E:\IS305\deal-monitor\deal-monitor.ps1"' `
  -WorkingDirectory "E:\IS305\deal-monitor"

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
  -RepetitionInterval (New-TimeSpan -Hours 2)

$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "DealMonitor" `
  -Action $action -Trigger $trigger -Settings $settings `
  -Description "Automated PC parts deal monitoring with Discord notifications"
```

## Adding More Sources

### Multiple Subreddits

```json
"sources": [
  { "type": "reddit", "name": "buildapcsales", "subreddit": "buildapcsales" },
  { "type": "reddit", "name": "deals", "subreddit": "deals" },
  { "type": "reddit", "name": "hardwareswap", "subreddit": "hardwareswap" }
]
```

### RSS Feeds

```json
{ "type": "rss", "name": "Slickdeals", "url": "https://slickdeals.net/newsearch.php?mode=popdeals&searcharea=deals&searchin=first&rss=1" }
```

### Custom JSON API

```json
{ "type": "json", "name": "Custom Store API", "url": "https://api.example.com/deals" }
```

## File Structure

```
deal-monitor/
├── deal-monitor.ps1          # Main script (~1500 lines)
├── config.json               # Runtime configuration (gitignored)
├── config.example.json       # Template for new setups
├── keywords.txt              # Simple keyword list (one per line)
├── history.json              # Sent deal IDs (auto-created)
├── control_state.json        # Last processed Discord message ID
├── test-notification.ps1     # Quick webhook test
├── .gitignore
├── .github/
│   └── copilot-instructions.md
├── control-bot/              # C# Discord bot
│   ├── Program.cs
│   ├── control-bot.csproj
│   └── README.md
├── logs/                     # Daily logs (auto-created, auto-rotated)
│   └── deal-monitor_YYYY-MM-DD.log
└── data/                     # (if applicable)
```

## Troubleshooting

### No Discord Notifications
1. Check webhook URL — test manually with `test-notification.ps1`
2. Check filters — keywords might not match or price/discount filters too strict
3. Check logs — `logs/deal-monitor_YYYY-MM-DD.log`

### Duplicate Bot Responses
Multiple bot instances are running. Kill all `dotnet`/`control-bot` processes and start only one.

### Price Shows Wrong
The price regex handles `$1149.99`, `$1,299.00`, `$50`, etc. If a price format isn't captured, check `Extract-PriceInfo` in the script.

### `!scan` Shows Wrong Numbers or Help Text
Fixed in latest version. The scan now uses `-SkipDiscordControl` to prevent the PS script from polling Discord during a bot-triggered scan.

### Bot Shows 401 Unauthorized
The `DISCORD_BOT_TOKEN` environment variable is missing in that terminal session. Set it explicitly before running.

### Deals Already Sent
Use `!clearhistory` in Discord, or delete `history.json` manually.

## Best Practices

✅ **Use watches** for different product categories with their own price limits  
✅ **Start with broader keywords** — "5080" instead of "ASUS ROG STRIX RTX 5080 OC"  
✅ **Use `!scan` to test** — don't wait for the schedule  
✅ **Check logs regularly** — monitor for errors or missed deals  
✅ **Run only one bot instance** — avoid duplicate responses  
✅ **Keep keywords case-insensitive** — `1440p` matches `1440P` automatically  

## License

Free to use and modify for personal use.

---

**Happy deal hunting! 🎯**
