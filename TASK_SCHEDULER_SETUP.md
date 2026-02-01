# Task Scheduler Setup Commands

## Quick Setup (Recommended)

Run this in **PowerShell as Administrator** to schedule the deal monitor to run every 2 hours:

```powershell
# Set the script path (update if needed)
$scriptPath = "E:\3rd qart\deal-monitor\deal-monitor.ps1"
$workingDir = "E:\3rd qart\deal-monitor"

# Create the scheduled task action
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$scriptPath`"" `
    -WorkingDirectory $workingDir

# Create the trigger (every 2 hours)
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).Date.AddHours(9) `
    -RepetitionInterval (New-TimeSpan -Hours 2)

# Create settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable

# Register the task
Register-ScheduledTask `
    -TaskName "DealMonitor" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "Automated PC parts deal monitoring with Discord notifications" `
    -Force

Write-Host "✅ Task 'DealMonitor' created successfully!" -ForegroundColor Green
Write-Host "   Runs every 2 hours starting at 9:00 AM daily" -ForegroundColor Cyan
```

## Alternative Schedules

### Every 30 Minutes

```powershell
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 30)
```

### Every Hour

```powershell
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 1)
```

### Every 4 Hours

```powershell
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).Date.AddHours(8) `
    -RepetitionInterval (New-TimeSpan -Hours 4)
```

### Specific Times Daily (e.g., 8 AM, 12 PM, 6 PM)

```powershell
$triggers = @(
    (New-ScheduledTaskTrigger -Daily -At "08:00"),
    (New-ScheduledTaskTrigger -Daily -At "12:00"),
    (New-ScheduledTaskTrigger -Daily -At "18:00")
)

Register-ScheduledTask `
    -TaskName "DealMonitor" `
    -Action $action `
    -Trigger $triggers `
    -Settings $settings `
    -Description "Automated PC parts deal monitoring with Discord notifications" `
    -Force
```

## Management Commands

### View Task Status

```powershell
Get-ScheduledTask -TaskName "DealMonitor" | Select-Object TaskName, State, LastRunTime, NextRunTime
```

### Run Task Immediately (Test)

```powershell
Start-ScheduledTask -TaskName "DealMonitor"
```

### View Last Run Result

```powershell
Get-ScheduledTask -TaskName "DealMonitor" | Get-ScheduledTaskInfo | Select-Object LastRunTime, LastTaskResult
```

### Disable Task

```powershell
Disable-ScheduledTask -TaskName "DealMonitor"
```

### Enable Task

```powershell
Enable-ScheduledTask -TaskName "DealMonitor"
```

### Remove Task

```powershell
Unregister-ScheduledTask -TaskName "DealMonitor" -Confirm:$false
```

## Viewing Task History

1. Open **Task Scheduler** (Win + R, type `taskschd.msc`)
2. Navigate to **Task Scheduler Library**
3. Find **DealMonitor** task
4. Click **History** tab at the bottom
5. Enable history if disabled: **Action** → **Enable All Tasks History**

## Troubleshooting

### Task Shows "Running" But Nothing Happens

Check the task configuration:
```powershell
Get-ScheduledTask -TaskName "DealMonitor" | Select-Object -ExpandProperty Actions
```

Verify:
- **Execute**: Should be `powershell.exe`
- **Arguments**: Should include `-ExecutionPolicy Bypass -File "path\to\deal-monitor.ps1"`
- **WorkingDirectory**: Should be the script's folder

### Task Result Code: 0x1 (Incorrect function)

Usually means PowerShell execution policy is blocking. Solution:

```powershell
# Re-register with explicit bypass
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument '-ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -File "E:\3rd qart\deal-monitor\deal-monitor.ps1"' `
    -WorkingDirectory "E:\3rd qart\deal-monitor"

Set-ScheduledTask -TaskName "DealMonitor" -Action $action
```

### Task Won't Run When Computer is Locked

Ensure these settings are enabled:

```powershell
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RunOnlyIfNetworkAvailable `
    -StartWhenAvailable

Set-ScheduledTask -TaskName "DealMonitor" -Settings $settings
```

### View Task Logs

Check the daily log files in the `logs/` directory:

```powershell
Get-Content "E:\3rd qart\deal-monitor\logs\deal-monitor_$(Get-Date -Format 'yyyy-MM-dd').log" -Tail 50
```

## GUI Setup (Alternative Method)

If you prefer using the Task Scheduler GUI:

1. Open **Task Scheduler** (Win + R, type `taskschd.msc`)
2. Click **Create Task** (not "Create Basic Task")
3. **General Tab:**
   - Name: `DealMonitor`
   - Description: `Automated deal monitoring with Discord notifications`
   - Select: **Run whether user is logged on or not**
   - Check: **Run with highest privileges**

4. **Triggers Tab:**
   - Click **New**
   - Begin the task: **On a schedule**
   - Settings: **One time** with your start time
   - Advanced: **Repeat task every** `2 hours`, for a duration of **Indefinitely**

5. **Actions Tab:**
   - Click **New**
   - Action: **Start a program**
   - Program/script: `powershell.exe`
   - Add arguments: `-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "E:\3rd qart\deal-monitor\deal-monitor.ps1"`
   - Start in: `E:\3rd qart\deal-monitor`

6. **Conditions Tab:**
   - Check: **Start only if the following network connection is available: Any connection**
   - Uncheck: **Stop if the computer switches to battery power**

7. **Settings Tab:**
   - Check: **Allow task to be run on demand**
   - Check: **Run task as soon as possible after a scheduled start is missed**
   - If the running task does not end when requested: **Stop the existing instance**

8. Click **OK** and enter your Windows password if prompted

## Verification

After setup, verify the task works:

```powershell
# 1. Check task exists
Get-ScheduledTask -TaskName "DealMonitor"

# 2. Run it manually
Start-ScheduledTask -TaskName "DealMonitor"

# 3. Wait 30 seconds, then check logs
Start-Sleep -Seconds 30
Get-Content "E:\3rd qart\deal-monitor\logs\deal-monitor_$(Get-Date -Format 'yyyy-MM-dd').log" -Tail 20

# 4. Check history.json was updated
Get-Content "E:\3rd qart\deal-monitor\history.json"
```

---

**Note**: Adjust paths in all commands if your script is in a different location!
