# Deal Monitor - Automated Deal Alerts via Discord

A PowerShell-based deal monitoring system that tracks RSS feeds and deal sources, filters by keywords and criteria, scores deals by "hotness", and sends notifications to Discord.

## Features

✅ **Multi-Source Support** - Monitor multiple RSS feeds and JSON endpoints  
✅ **Smart Filtering** - Filter by keywords, max price, and minimum discount percentage  
✅ **Hotness Scoring** - Automatically scores deals based on discount %, price threshold, and keyword relevance  
✅ **Discord Notifications** - Rich embedded notifications with color-coded urgency  
✅ **Duplicate Prevention** - Tracks sent deals to avoid repeat notifications  
✅ **Comprehensive Logging** - Daily log files for troubleshooting  
✅ **Task Scheduler Ready** - Designed for automated Windows Task Scheduler execution  

## Quick Start

### 1. Prerequisites

- **Windows 10/11** with PowerShell 5.1+
- **Discord Webhook URL** (see setup below)
- **Internet connection** for fetching deals

### 2. Get Your Discord Webhook URL

1. Open Discord and go to your server
2. Right-click the channel where you want notifications → **Edit Channel**
3. Go to **Integrations** → **Webhooks** → **New Webhook**
4. Click **Copy Webhook URL**
5. Save this URL for the next step

### 3. Configure the Script

Easiest option (no JSON editing): update `keywords.txt` (one keyword per line).

```text
750W
power supply
PSU
```

You can also override keywords/filters at runtime:

```powershell
./deal-monitor.ps1 -Keywords "DDR5","48GB" -MaxPrice 240
./deal-monitor.ps1 -ConfigureKeywords   # prompts and writes keywords.txt
```

### Optional: Set Keywords via Discord (Receive Commands)

Discord webhooks are **send-only** (the script can post alerts, but cannot receive messages through a webhook).
To type keywords *in Discord* and have the script pick them up, you need a **Discord bot** that can read messages in a “control” channel.

**How it works:**
- If you use the PowerShell-only approach, the script reads Discord commands **on each run** (scheduled/polling).
- If you want instant replies and instant updates, run the always-on C# bot in [control-bot/README.md](control-bot/README.md).
- You type commands like `!keywords set 750W, PSU, power supply` in a Discord channel.
- On the next run, the script reads that channel via Discord’s API, updates `keywords.txt`, then continues normally.

**Setup (high level):**
- Create a bot in the Discord Developer Portal.
- Invite it to your server with permission to **View Channel** and **Read Message History** (and optionally **Send Messages** if you enable acknowledgements).
- Set an environment variable for the bot token:

```powershell
$env:DISCORD_BOT_TOKEN = "YOUR_BOT_TOKEN"
```

**Commands:**
- `!keywords set kw1, kw2, kw3`
- `!keywords help`
- `!keywords show`
- `!status`
- `!maxprice 200`
- `!mindiscount 15`

Enable it in [config.json](config.json) under `discord_control`.

**Instant mode (recommended for best UX):**
- See [control-bot/README.md](control-bot/README.md) for a small always-on C# Discord bot that updates `keywords.txt` immediately and acks immediately.

Edit [config.json](config.json) and update:

```json
{
  "discord_webhook_url": "YOUR_WEBHOOK_URL_HERE",
  "keywords": [
    "RTX 4070",
    "2TB NVMe",
    "AM5",
    "DDR5"
  ],
  "filters": {
    "max_price": 500,
    "min_discount_percent": 15
  }
}
```

**Configuration Options:**

- **`discord_webhook_url`** - Your Discord webhook URL (required)
- **`keywords`** - Array of terms to watch for (case-insensitive)
- **`filters.max_price`** - Only notify for deals under this price (or `null` for no limit)
- **`filters.min_discount_percent`** - Minimum discount % required (or `null` for no minimum)
- **`sources`** - Array of RSS feeds or JSON endpoints to monitor

### 4. Test Run

Open PowerShell in the `deal-monitor` folder and run:

```powershell
.\deal-monitor.ps1
```

You should see:
- Log messages in the console
- A `logs/` folder with today's log file
- A `history.json` file tracking sent deals
- Discord notifications for matching deals

### 5. Schedule Automatic Runs

**Option A: Using Task Scheduler GUI**

1. Open **Task Scheduler** (search in Start menu)
2. Click **Create Basic Task**
3. Name: "Deal Monitor"
4. Trigger: Daily at your preferred time (e.g., every 2 hours)
5. Action: **Start a program**
   - Program: `powershell.exe`
  - Arguments: `-ExecutionPolicy Bypass -File "E:\IS305\deal-monitor\deal-monitor.ps1"`
  - Start in: `E:\IS305\deal-monitor`
6. Finish and enable the task

**Option B: Using PowerShell Command**

Run this in PowerShell (as Administrator):

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument '-ExecutionPolicy Bypass -File "E:\IS305\deal-monitor\deal-monitor.ps1"' `
  -WorkingDirectory "E:\IS305\deal-monitor"

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 2)

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "DealMonitor" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "Automated PC parts deal monitoring with Discord notifications"
```

**Run every 2 hours:**
```powershell
# Modify the trigger line above to:
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 2)
```

**Run every 30 minutes:**
```powershell
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30)
```

## Usage Examples

### Example 1: GPU Deals Under $600 with 20%+ Discount

```json
{
  "keywords": ["RTX 4070", "RTX 4060", "RX 7800"],
  "filters": {
    "max_price": 600,
    "min_discount_percent": 20
  }
}
```

### Example 2: Any SSD Deal (No Price Limit)

```json
{
  "keywords": ["NVMe", "SSD", "M.2", "2TB", "1TB"],
  "filters": {
    "max_price": null,
    "min_discount_percent": 10
  }
}
```

### Example 3: High-End Components Only

```json
{
  "keywords": [
    "RTX 4090",
    "Ryzen 9 7950X",
    "Intel Core i9-14900K",
    "DDR5 6000MHz",
    "4TB NVMe"
  ],
  "filters": {
    "max_price": 2000,
    "min_discount_percent": 15
  }
}
```

## How Hotness Scoring Works

Each deal gets a "hotness score" (0-100 points):

- **Discount Percentage**: Up to 50 points (50% off = 50 points)
- **Price Threshold Bonus**: 
  - Under $100 = +20 points
  - $100-$299 = +15 points
  - $300-$499 = +10 points
  - $500-$999 = +5 points
- **Keyword Match Strength**: +5 points per matched keyword (max 30)

**Color Coding in Discord:**
- 🔴 **Red** (70+ points) - HOT DEAL
- 🟠 **Orange** (50-69 points) - Great deal
- 🔵 **Blue** (30-49 points) - Good deal
- ⚪ **Gray** (0-29 points) - Decent deal

## Adding More Sources

### Reddit RSS Feeds

```json
{
  "type": "rss",
  "name": "r/buildapcsales",
  "url": "https://www.reddit.com/r/buildapcsales/.rss"
}
```

### Slickdeals RSS

```json
{
  "type": "rss",
  "name": "Slickdeals Popular",
  "url": "https://slickdeals.net/newsearch.php?mode=popdeals&searcharea=deals&searchin=first&rss=1"
}
```

### Custom JSON API

```json
{
  "type": "json",
  "name": "Custom Store API",
  "url": "https://api.example.com/deals"
}
```

**JSON API Expected Format:**
```json
[
  {
    "title": "Product Name",
    "url": "https://...",
    "description": "Deal description",
    "price": 299.99,
    "original_price": 399.99,
    "date": "2026-02-01T12:00:00Z"
  }
]
```

## File Structure

```
deal-monitor/
│
├── deal-monitor.ps1      # Main script
├── config.json           # Configuration file
├── history.json          # Tracks sent deals (auto-created)
├── README.md             # This file
│
└── logs/                 # Daily log files (auto-created)
    ├── deal-monitor_2026-02-01.log
    └── deal-monitor_2026-02-02.log
```

## Troubleshooting

### No Discord Notifications

1. **Check webhook URL** - Test it manually:
   ```powershell
   $webhook = "YOUR_WEBHOOK_URL"
   $body = @{ content = "Test message" } | ConvertTo-Json
   Invoke-RestMethod -Uri $webhook -Method Post -Body $body -ContentType "application/json"
   ```

2. **Check filters** - Your keywords might not be matching or filters are too strict

3. **Check logs** - Look in `logs/deal-monitor_YYYY-MM-DD.log` for errors

### Script Not Running on Schedule

1. **Check Task Scheduler** - Ensure the task is enabled
2. **Verify PowerShell path** - Should be `powershell.exe` (not `pwsh.exe`)
3. **Check execution policy** - Use `-ExecutionPolicy Bypass` in arguments
4. **Verify working directory** - Must be set to the script folder

### Deals Already Sent

The script tracks sent deals in `history.json`. To reset:
- Delete `history.json` or remove specific deal IDs from the file

### RSS Feed Not Working

Some RSS feeds may have different structures. Check the logs for parsing errors. You may need to modify the `Fetch-RSSFeed` function to handle specific feed formats.

## Advanced Configuration

### Multiple Configurations

Run different configs for different purposes:

```powershell
# GPU-specific monitoring
.\deal-monitor.ps1 -ConfigPath ".\config-gpu.json"

# Storage-specific monitoring
.\deal-monitor.ps1 -ConfigPath ".\config-storage.json"
```

### Custom Price Extraction

If a deal source has a specific price format, modify the `Extract-PriceInfo` function in [deal-monitor.ps1](deal-monitor.ps1#L220).

### Rate Limiting

The script waits 2 seconds between Discord notifications by default. Adjust on [line 663](deal-monitor.ps1#L663):

```powershell
Start-Sleep -Seconds 2  # Change to desired delay
```

## Best Practices

✅ **Start with broader keywords** - "RTX 4070" instead of "ASUS RTX 4070 Ti Super OC"  
✅ **Use reasonable filters** - Don't set `min_discount_percent` too high  
✅ **Check logs regularly** - Monitor for errors or missed deals  
✅ **Clean history periodically** - Script auto-trims to last 1000 deals  
✅ **Test before scheduling** - Run manually first to verify configuration  

## License

Free to use and modify for personal use.

## Support

For issues or questions:
1. Check the logs in `logs/` folder
2. Verify your `config.json` is valid JSON
3. Test the Discord webhook manually
4. Review PowerShell execution policy settings

---

**Happy deal hunting! 🎯**
