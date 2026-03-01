# Deal Monitor Control Bot (C#)

An always-on Discord gateway bot that lets you manage watches, keywords, and filters instantly by typing commands in a Discord channel. Supports both `!` text commands and `/` slash commands.

Uses settings from `../config.json` under `discord_control`.

## Prereqs

- Windows + .NET 8 SDK
- Your Discord bot must have **Message Content Intent** enabled in the Developer Portal
- The bot must be invited to your server with permissions: View Channel, Read Message History, Send Messages

## Configuration

In `config.json` (in the parent folder), ensure:

- `discord_control.enabled`: `true`
- `discord_control.channel_id`: your control channel ID
- `discord_control.allowed_user_ids`: (recommended) your user ID(s)
- `discord_control.token_env`: environment variable name holding the bot token (default: `DISCORD_BOT_TOKEN`)

Set the bot token in an environment variable (do NOT store it in config):

PowerShell (current window only):

```powershell
$env:DISCORD_BOT_TOKEN = "YOUR_TOKEN"
```

Persistent (for Task Scheduler / reboot):

```powershell
setx DISCORD_BOT_TOKEN "YOUR_TOKEN" /M
```

## Run

```powershell
# Set working directory to repo root so the bot finds config.json / keywords.txt
$env:DEAL_MONITOR_DIR = "E:\IS305\deal-monitor"
dotnet run --project "E:\IS305\deal-monitor\control-bot\control-bot.csproj"
```

> **Important:** Only run one bot instance at a time — multiple instances cause duplicate Discord responses.
> Kill any existing instance first: `Get-Process -Name "control-bot" | Stop-Process -Force`

## Commands

| Command | Description |
|---------|-------------|
| `!help` | Full command reference |
| `!scan` | Run deal-monitor.ps1 immediately and report results |
| `!clearhistory` | Reset seen-deals history so all deals re-send |
| `!watch add Name \| kw1, kw2 \| max:500 \| discount:15 \| type:SELLING` | Create/update a watch (type: = flair filter) |
| `!watch list` | Show all watches with their filters |
| `!watch remove Name` | Delete a watch |
| `!watch clear` | Remove all watches |
| `!keywords set kw1, kw2` | Replace simple keywords (ignored when watches exist) |
| `!keywords show` | Show current keywords |
| `!maxprice 200` | Set global max price filter |
| `!mindiscount 15` | Set global min discount % filter |
| `!scaninterval 2d` | Set auto-scan interval (supports days + minutes) |
| `!scaninterval 1d 30` | 1 day and 30 minutes |
| `!scaninterval 30` | 30 minutes |
| `!scaninterval off` | Disable auto-scan |
| `!status` | Show current config summary |
| `!ping` | Check bot is alive |

All commands also available as `/` slash commands.

If `discord_control.ack` is true, the bot replies immediately after applying commands.
