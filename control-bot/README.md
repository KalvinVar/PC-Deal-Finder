# Deal Monitor Control Bot (C#)

This is an always-on Discord bot that lets you update `keywords.txt` (and a couple filters in `config.json`) instantly by typing commands in a Discord channel.

It uses the existing settings in `../config.json` under `discord_control`.

## Prereqs

- Windows + .NET 8 SDK
- Your Discord bot must have **Message Content Intent** enabled in the Developer Portal
- The bot must be invited to your server and have access to the control channel

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

From the parent folder (`E:\IS305\deal-monitor`) or set `Start In` to that folder:

```powershell
cd E:\IS305\deal-monitor\control-bot
# dotnet run uses the config/keywords in the parent folder if your working directory is the deal-monitor folder
# Recommended: run with working directory set to E:\IS305\deal-monitor

# Option A: set working directory explicitly for this run
$env:DEAL_MONITOR_DIR = "E:\IS305\deal-monitor"
"C:\Program Files\dotnet\dotnet.exe" run
```

## Commands (in the control channel)

- `!keywords set kw1, kw2, kw3`
- `!keywords show`
- `!keywords help` (or `!help`)
- `!status`
- `!maxprice 200`
- `!mindiscount 15`
- `!ping`

If `discord_control.ack` is true, the bot replies immediately after applying commands.
