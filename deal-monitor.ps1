<#
.SYNOPSIS
    Automated deal monitoring script with Discord notifications

.DESCRIPTION
    Monitors RSS feeds and deal sources for specific keywords, filters by price/discount,
    scores deals by "hotness", and sends Discord notifications for matches.
    Tracks sent deals to avoid duplicates.

.PARAMETER ConfigPath
    Path to the configuration JSON file (default: config.json)

.EXAMPLE
    .\deal-monitor.ps1
    .\deal-monitor.ps1 -ConfigPath ".\custom-config.json"
#>

param(
    [string]$ConfigPath = ".\config.json",
    [string]$KeywordsFile = ".\keywords.txt",
    [string[]]$Keywords,
    [string[]]$Flairs,
    [Nullable[double]]$MaxPrice,
    [Nullable[int]]$MinDiscountPercent,
    [switch]$ConfigureKeywords,
    [switch]$SkipDiscordControl
)

# ============================================================================
# CONFIGURATION & INITIALIZATION
# ============================================================================

$ErrorActionPreference = "Continue"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogPath = Join-Path $ScriptPath "logs"
$HistoryPath = Join-Path $ScriptPath "history.json"
$ControlStatePath = Join-Path $ScriptPath "control_state.json"
$LogFile = Join-Path $LogPath "deal-monitor_$(Get-Date -Format 'yyyy-MM-dd').log"

# Ensure TLS 1.2 on Windows PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        # ignore
    }
}

# Create directories if they don't exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Log rotation - delete logs older than 30 days
try {
    Get-ChildItem -Path $LogPath -Filter "deal-monitor_*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
        ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
}
catch {
    # Non-critical; ignore
}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage }
    }
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logMessage
}

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

function Load-Configuration {
    param([string]$Path)
    
    try {
        if (-not (Test-Path $Path)) {
            Write-Log "Configuration file not found: $Path" -Level ERROR
            return $null
        }
        
        $config = Get-Content $Path -Raw | ConvertFrom-Json
        Write-Log "Configuration loaded successfully from $Path"
        return $config
    }
    catch {
        Write-Log "Failed to load configuration: $_" -Level ERROR
        return $null
    }
}

function Resolve-PathRelativeToScript {
    param([Parameter(Mandatory=$true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return (Join-Path $ScriptPath $Path)
}

function Load-KeywordsFromFile {
    param([Parameter(Mandatory=$true)][string]$Path)

    try {
        if (-not (Test-Path $Path)) {
            return @()
        }

        $lines = Get-Content -Path $Path -ErrorAction Stop
        $keywords = @()

        foreach ($line in $lines) {
            $trimmed = ($line -as [string]).Trim()
            if (-not $trimmed) { continue }
            if ($trimmed.StartsWith('#')) { continue }
            $keywords += $trimmed
        }

        return @($keywords | Select-Object -Unique)
    }
    catch {
        Write-Log "Failed to load keywords file $Path : $_" -Level WARNING
        return @()
    }
}

function Normalize-Keyword {
    <#
    .SYNOPSIS
        Normalizes a keyword string: collapses extra whitespace and strips leading
        zeros from embedded numbers (e.g. "050W" -> "50W", "01440p" -> "1440p").
        Prevents accidental misses caused by copy-paste formatting differences.
    #>
    param([string]$Keyword)

    # 1. Trim and collapse internal whitespace
    $k = ($Keyword.Trim() -replace '\s+', ' ')
    # 2. Strip leading zeros from numbers embedded in text
    $k = $k -replace '\b0+(\d)', '$1'
    return $k
}

function Ensure-ConfigFilters {
    param([Parameter(Mandatory=$true)]$Config)

    if (-not $Config.filters) {
        $Config | Add-Member -NotePropertyName 'filters' -NotePropertyValue ([pscustomobject]@{}) -Force
    }
}

function Ensure-ConfigDiscordControl {
    param([Parameter(Mandatory=$true)]$Config)

    if (-not $Config.discord_control) {
        $Config | Add-Member -NotePropertyName 'discord_control' -NotePropertyValue ([pscustomobject]@{}) -Force
    }

    if ($null -eq $Config.discord_control.enabled) {
        $Config.discord_control | Add-Member -NotePropertyName 'enabled' -NotePropertyValue $false -Force
    }
    if (-not $Config.discord_control.token_env) {
        $Config.discord_control | Add-Member -NotePropertyName 'token_env' -NotePropertyValue 'DISCORD_BOT_TOKEN' -Force
    }
    if ($null -eq $Config.discord_control.allowed_user_ids) {
        $Config.discord_control | Add-Member -NotePropertyName 'allowed_user_ids' -NotePropertyValue @() -Force
    }
    if ($null -eq $Config.discord_control.ack) {
        $Config.discord_control | Add-Member -NotePropertyName 'ack' -NotePropertyValue $false -Force
    }
}

function Load-ControlState {
    try {
        if (Test-Path $ControlStatePath) {
            $state = Get-Content $ControlStatePath -Raw | ConvertFrom-Json
            return $state
        }
        return [pscustomobject]@{ last_message_id = $null }
    }
    catch {
        return [pscustomobject]@{ last_message_id = $null }
    }
}

function Save-ControlState {
    param([Parameter(Mandatory=$true)]$State)

    try {
        $State | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $ControlStatePath
    }
    catch {
        Write-Log "Failed to save control state: $_" -Level WARNING
    }
}

function Get-DiscordBotToken {
    param([Parameter(Mandatory=$true)]$Config)

    Ensure-ConfigDiscordControl -Config $Config
    $envName = [string]$Config.discord_control.token_env
    if (-not $envName) { $envName = 'DISCORD_BOT_TOKEN' }

    $token = [Environment]::GetEnvironmentVariable($envName)
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $null
    }

    return $token.Trim()
}

function Invoke-DiscordApi {
    param(
        [Parameter(Mandatory=$true)][string]$Method,
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$BotToken,
        [object]$Body
    )

    $headers = @{
        Authorization = "Bot $BotToken"
        "User-Agent"  = "DealMonitor/1.0 (PowerShell; +https://discord.com/developers/docs/intro)"
        Accept        = "application/json"
    }

    if ($null -ne $Body) {
        # IMPORTANT: Windows PowerShell 5.1 may send string bodies as UTF-16.
        # Discord expects UTF-8 JSON; send UTF-8 bytes explicitly.
        $json = $Body | ConvertTo-Json -Depth 10
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        return Invoke-RestMethod -Method $Method -Uri $Url -Headers $headers -TimeoutSec 30 -ContentType 'application/json; charset=utf-8' -Body $bytes
    }

    return Invoke-RestMethod -Method $Method -Uri $Url -Headers $headers -TimeoutSec 30
}

function Test-DiscordBotToken {
    param(
        [Parameter(Mandatory=$true)]$Config
    )

    Ensure-ConfigDiscordControl -Config $Config
    if (-not $Config.discord_control.enabled) {
        return
    }

    $botToken = Get-DiscordBotToken -Config $Config
    if (-not $botToken) {
        return
    }

    try {
        $me = Invoke-DiscordApi -Method 'GET' -Url 'https://discord.com/api/v10/users/@me' -BotToken $botToken
        if ($me -and $me.id) {
            Write-Log "[Discord Control] Bot token OK. Bot user: $($me.username)#$($me.discriminator) (id=$($me.id))" -Level INFO
        }
        else {
            Write-Log "[Discord Control] Bot token validation returned unexpected response" -Level WARNING
        }
    }
    catch {
        $status = $null
        try {
            if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        }
        catch { }

        if ($status) {
            Write-Log "[Discord Control] Bot token validation failed (HTTP $status): $_" -Level WARNING
        }
        else {
            Write-Log "[Discord Control] Bot token validation failed: $_" -Level WARNING
        }
    }
}

function Test-DiscordControlChannelAccess {
    param(
        [Parameter(Mandatory=$true)][string]$ChannelId,
        [Parameter(Mandatory=$true)][string]$BotToken
    )

    try {
        $url = "https://discord.com/api/v10/channels/$ChannelId"
        $channel = Invoke-DiscordApi -Method 'GET' -Url $url -BotToken $BotToken
        if ($channel -and $channel.id) {
            $name = if ($channel.name) { $channel.name } else { '(no name)' }
            Write-Log "[Discord Control] Channel access OK: $name (id=$($channel.id), type=$($channel.type))" -Level INFO
        }
        else {
            Write-Log "[Discord Control] Channel access returned unexpected response" -Level WARNING
        }
    }
    catch {
        $status = $null
        try {
            if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        }
        catch { }

        if ($status) {
            Write-Log "[Discord Control] Channel access failed (HTTP $status): $_" -Level WARNING
        }
        else {
            Write-Log "[Discord Control] Channel access failed: $_" -Level WARNING
        }
    }
}

function Get-DiscordRecentMessages {
    param(
        [Parameter(Mandatory=$true)][string]$ChannelId,
        [Parameter(Mandatory=$true)][string]$BotToken,
        [Nullable[UInt64]]$AfterMessageId
    )

    $baseUrl = "https://discord.com/api/v10/channels/$ChannelId/messages?limit=50"
    if ($AfterMessageId) {
        $baseUrl += "&after=$AfterMessageId"
    }

    try {
        $messages = Invoke-DiscordApi -Method 'GET' -Url $baseUrl -BotToken $BotToken
        return @($messages)
    }
    catch {
        $details = $_
        $status = $null
        try {
            if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        }
        catch { }

        if ($status) {
            Write-Log "Failed to read Discord control channel messages (HTTP $status): $details" -Level WARNING
        }
        else {
            Write-Log "Failed to read Discord control channel messages: $details" -Level WARNING
        }
        return @()
    }
}

function Send-DiscordControlAck {
    param(
        [Parameter(Mandatory=$true)][string]$ChannelId,
        [Parameter(Mandatory=$true)][string]$BotToken,
        [Parameter(Mandatory=$true)][string]$Message
    )

    try {
        $url = "https://discord.com/api/v10/channels/$ChannelId/messages"
        $body = @{ content = $Message }
        [void](Invoke-DiscordApi -Method 'POST' -Url $url -BotToken $BotToken -Body $body)
    }
    catch {
        Write-Log "Failed to send Discord control ack: $_" -Level WARNING
    }
}

function Try-ApplyDiscordControl {
    param(
        [Parameter(Mandatory=$true)]$Config,
        [Parameter(Mandatory=$true)][string]$KeywordsFilePath
    )

    Ensure-ConfigDiscordControl -Config $Config
    if (-not $Config.discord_control.enabled) {
        Write-Log "[Discord Control] Disabled" -Level INFO
        return $null
    }

    $channelId = [string]$Config.discord_control.channel_id
    if ([string]::IsNullOrWhiteSpace($channelId)) {
        Write-Log "Discord control enabled but discord_control.channel_id is missing" -Level WARNING
        return $null
    }

    $allowed = @($Config.discord_control.allowed_user_ids)
    if ($allowed -and ($allowed | Measure-Object).Count -gt 0) {
        Write-Log "[Discord Control] Enabled. Channel: $channelId. Allowed users: $(($allowed | Measure-Object).Count)" -Level INFO
    }
    else {
        Write-Log "[Discord Control] Enabled. Channel: $channelId. Allowed users: (anyone in channel)" -Level INFO
    }

    $botToken = Get-DiscordBotToken -Config $Config
    if (-not $botToken) {
        $envName = [string]$Config.discord_control.token_env
        if (-not $envName) { $envName = 'DISCORD_BOT_TOKEN' }
        Write-Log "Discord control enabled but bot token env var '$envName' is missing. Set it in PowerShell: `$env:$envName = '...token...'" -Level WARNING
        return $null
    }

    Test-DiscordControlChannelAccess -ChannelId $channelId -BotToken $botToken

    $state = Load-ControlState
    $after = $null
    if ($state -and $state.last_message_id) {
        try { $after = [UInt64]$state.last_message_id } catch { $after = $null }
    }

    $messages = Get-DiscordRecentMessages -ChannelId $channelId -BotToken $botToken -AfterMessageId $after
    if (-not $messages -or ($messages | Measure-Object).Count -eq 0) {
        if ($after) {
            Write-Log "[Discord Control] No new control messages after $after" -Level INFO
        }
        else {
            Write-Log "[Discord Control] No control messages found" -Level INFO
        }
        return $null
    }

    $latestId = $after

    $applied = $null
    $responseMessage = $null

    foreach ($m in $messages) {
        if (-not $m) { continue }
        if ($m.author -and $m.author.bot) { continue }

        $mid = $null
        try { $mid = [UInt64]$m.id } catch { $mid = $null }
        if ($mid -and ($null -eq $latestId -or $mid -gt $latestId)) {
            $latestId = $mid
        }

        if ($allowed -and ($allowed | Measure-Object).Count -gt 0) {
            $authorId = [string]$m.author.id
            if (-not ($allowed -contains $authorId)) {
                continue
            }
        }

        $content = [string]$m.content
        if ([string]::IsNullOrWhiteSpace($content)) { continue }
        $trim = $content.Trim()

        # Commands:
        # !keywords set kw1, kw2, kw3
        # !keywords show
        # !keywords help / !help
        # !status
        # !maxprice 200
        # !mindiscount 15
        # !watch add Name | kw1, kw2 | max:500 | discount:15
        # !watch list
        # !watch remove Name
        # !watch clear

        if ($trim -match '^!(?:dealmonitor\s+)?(?:keywords\s+help|help)$') {
            $responseMessage = @(
                ':information_source: **Deal Monitor — Commands**',
                '',
                '**Watches** — configure keywords, price limit, and optional deal type per watch',
                '- !watch add GPU | RTX 5080, 5070 Ti | max:1200 | discount:10 | type:GPU',
                '  name | keywords | max: | discount: | type: (type= optional Reddit flair filter)',
                '- !watch list / !watch remove GPU / !watch clear',
                '',
                '**Scanning**',
                '- !scan  (check for deals now)',
                '- !scaninterval 2d / !scaninterval 30 / !scaninterval 1d 30  (auto-scan interval)',
                '- !scaninterval off',
                '',
                '**Other**',
                '- !clearhistory  !status  !ping',
                '',
                'Tip: type: is optional — without it a watch matches all deal categories.'
            ) -join "`n"
            continue
        }

        if ($trim -match '^!keywords\s+show$') {
            $current = Load-KeywordsFromFile -Path $KeywordsFilePath
            if (-not $current -or ($current | Measure-Object).Count -eq 0) {
                $responseMessage = ":information_source: Current keywords: (none)"
            }
            else {
                $responseMessage = ":information_source: Current keywords: " + ($current -join ', ')
            }
            continue
        }

        if ($trim -match '^!status$') {
            $current = Load-KeywordsFromFile -Path $KeywordsFilePath
            $kwText = if ($current -and ($current | Measure-Object).Count -gt 0) { ($current -join ', ') } else { '(none)' }
            $hasWatches = $Config.watches -and ($Config.watches | Measure-Object).Count -gt 0
            # History count
            $histCount = 0
            $histPath2 = Join-Path $ScriptPath 'history.json'
            if (Test-Path $histPath2) {
                try { $hc = Get-Content $histPath2 -Raw | ConvertFrom-Json; $histCount = if ($hc -is [array]) { $hc.Count } else { 0 } } catch { }
            }
            # Watches
            $watchLines = '(none)'
            if ($hasWatches) {
                $watchLines = @($Config.watches | ForEach-Object {
                    $wn = $_.name; $wk = @($_.keywords) -join ', '
                    $wmp = if ($null -ne $_.max_price) { " max=`$$($_.max_price)" } else { '' }
                    $wmd = if ($null -ne $_.min_discount_percent) { " discount=$($_.min_discount_percent)%" } else { '' }
                    $wfl = if ($_.flairs -and ($_.flairs | Measure-Object).Count -gt 0) { " type=$(@($_.flairs) -join ',')" } else { '' }
                    "$wn [$wk]$wmp$wmd$wfl"
                }) -join ' | '
            }
            # Keywords warning
            $kwNote = if ($hasWatches -and $current -and ($current | Measure-Object).Count -gt 0) { ' [!] ignored - watches take priority' } else { '' }
            # Auto-scan
            $scanMins = if ($Config.scan_interval_minutes -and [int]$Config.scan_interval_minutes -gt 0) { [int]$Config.scan_interval_minutes } else { 0 }
            if ($scanMins -gt 0) {
                $scanD = [math]::Floor($scanMins / 1440); $scanM = $scanMins % 1440
                $scanParts = @()
                if ($scanD -gt 0) { $scanParts += "$scanD day$(if ($scanD -ne 1) {'s'})" }
                if ($scanM -gt 0) { $scanParts += "$scanM min" }
                $scanText = "every $($scanParts -join ' ')"
            } else { $scanText = 'off' }
            $plural = if ($histCount -ne 1) { 's' } else { '' }
            $responseMessage = @(
                ':information_source: **Status**',
                "**Watches:** $watchLines",
                "**Keywords (keywords.txt):** $kwText$kwNote",
                "**History:** $histCount deal$plural seen",
                "**Auto-scan:** $scanText"
            ) -join "`n"
            continue
        }

        # ---- Watch commands ----
        if ($trim -match '^!watch\s+list$') {
            if (-not $Config.watches -or ($Config.watches | Measure-Object).Count -eq 0) {
                $responseMessage = ':information_source: No watches configured. Use `!watch add Name | kw1, kw2 | max:500 | discount:15`'
            }
            else {
                $lines = @(':information_source: **Active watches:**')
                foreach ($w in $Config.watches) {
                    $wName = if ($w.name) { $w.name } else { '(unnamed)' }
                    $wKw = @($w.keywords) -join ', '
                    $wMax = if ($null -ne $w.max_price) { "`$$($w.max_price)" } else { 'any' }
                    $wDisc = if ($null -ne $w.min_discount_percent) { "$($w.min_discount_percent)%" } else { 'any' }
                    $wType = if ($w.flairs -and ($w.flairs | Measure-Object).Count -gt 0) { " type=$(@($w.flairs) -join ',')" } else { '' }
                    $lines += "- **$wName**: keywords=[$wKw] max=$wMax discount=$wDisc$wType"
                }
                $responseMessage = $lines -join "`n"
            }
            continue
        }

        if ($trim -match '^!watch\s+add\s+(.+)$') {
            $raw = $Matches[1]
            $parts = $raw -split '\|'
            if ($parts.Count -lt 2) {
                $responseMessage = ':warning: Format: `!watch add Name | kw1, kw2 | max:500 | discount:15`'
                continue
            }
            $watchName = $parts[0].Trim()
            $watchKeywords = @($parts[1] -split ',' | ForEach-Object { Normalize-Keyword $_.Trim() } | Where-Object { $_ })
            if (-not $watchName -or $watchKeywords.Count -eq 0) {
                $responseMessage = ':warning: Need a name and at least one keyword.'
                continue
            }
            $watchMaxPrice = $null
            $watchMinDiscount = $null
            $watchFlairs = @()
            for ($i = 2; $i -lt $parts.Count; $i++) {
                $seg = $parts[$i].Trim()
                if ($seg -match '^max:\s*(\d+(?:\.\d+)?)$') { $watchMaxPrice = [double]$Matches[1] }
                elseif ($seg -match '^discount:\s*(\d+)$') { $watchMinDiscount = [int]$Matches[1] }
                elseif ($seg -match '^type:\s*(.+)$') { $watchFlairs = @($Matches[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            }
            # Build watch object and save to config.json
            $newWatch = [ordered]@{
                name = $watchName
                keywords = $watchKeywords
            }
            if ($null -ne $watchMaxPrice) { $newWatch['max_price'] = $watchMaxPrice }
            if ($null -ne $watchMinDiscount) { $newWatch['min_discount_percent'] = $watchMinDiscount }
            if ($watchFlairs.Count -gt 0) { $newWatch['flairs'] = $watchFlairs }
            # Read config, add watch, write back
            try {
                $configRaw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                if (-not $configRaw.watches) {
                    $configRaw | Add-Member -NotePropertyName 'watches' -NotePropertyValue @() -Force
                }
                # Remove existing watch with same name
                $existing = @($configRaw.watches | Where-Object { $_.name -ne $watchName })
                $existing += [pscustomobject]$newWatch
                $configRaw.watches = @($existing)
                $Config.watches = @($existing)
                $configRaw | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $ConfigPath
                Write-Log "[Discord Control] Added watch '$watchName': $($watchKeywords -join ', ')" -Level INFO
                if (-not $applied) { $applied = [pscustomobject]@{} }
                $applied | Add-Member -NotePropertyName 'watch_added' -NotePropertyValue $watchName -Force
                $responseMessage = ":white_check_mark: Watch **$watchName** added (keywords: $($watchKeywords -join ', ')$(if ($watchMaxPrice) { ", max: `$$watchMaxPrice" })$(if ($watchMinDiscount) { ", discount: $watchMinDiscount%" })$(if ($watchFlairs.Count -gt 0) { ", type: $($watchFlairs -join ',')" }))"
            }
            catch {
                Write-Log "[Discord Control] Failed to save watch: $($_.Exception.Message)" -Level ERROR
                $responseMessage = ':x: Failed to save watch to config.'
            }
            continue
        }

        if ($trim -match '^!watch\s+remove\s+(.+)$') {
            $watchName = $Matches[1].Trim()
            try {
                $configRaw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                if (-not $configRaw.watches -or ($configRaw.watches | Measure-Object).Count -eq 0) {
                    $responseMessage = ':warning: No watches to remove.'
                    continue
                }
                $before = ($configRaw.watches | Measure-Object).Count
                $remaining = @($configRaw.watches | Where-Object { $_.name -ne $watchName })
                if ($remaining.Count -eq $before) {
                    $responseMessage = ":warning: Watch '$watchName' not found."
                    continue
                }
                $configRaw.watches = @($remaining)
                $Config.watches = @($remaining)
                $configRaw | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $ConfigPath
                Write-Log "[Discord Control] Removed watch '$watchName'" -Level INFO
                $responseMessage = ":white_check_mark: Watch **$watchName** removed. $(($remaining | Measure-Object).Count) watch(es) remaining."
                if (-not $applied) { $applied = [pscustomobject]@{} }
                $applied | Add-Member -NotePropertyName 'watch_removed' -NotePropertyValue $watchName -Force
            }
            catch {
                Write-Log "[Discord Control] Failed to remove watch: $_" -Level ERROR
                $responseMessage = ':x: Failed to update config.'
            }
            continue
        }

        if ($trim -match '^!watch\s+clear$') {
            try {
                $configRaw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                $configRaw | Add-Member -NotePropertyName 'watches' -NotePropertyValue @() -Force
                $Config.watches = @()
                $configRaw | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $ConfigPath
                Write-Log "[Discord Control] Cleared all watches" -Level INFO
                $responseMessage = ':white_check_mark: All watches cleared.'
                if (-not $applied) { $applied = [pscustomobject]@{} }
                $applied | Add-Member -NotePropertyName 'watches_cleared' -NotePropertyValue $true -Force
            }
            catch {
                Write-Log "[Discord Control] Failed to clear watches: $_" -Level ERROR
                $responseMessage = ':x: Failed to update config.'
            }
            continue
        }

        if ($trim -match '^!keywords\s+set\s+(.+)$') {
            $raw = $Matches[1]
            $newKeywords = @($raw -split ',' | ForEach-Object { Normalize-Keyword $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
            if ($newKeywords.Count -gt 0) {
                Set-Content -Path $KeywordsFilePath -Encoding UTF8 -Value ($newKeywords -join "`n")
                $applied = [pscustomobject]@{ keywords = $newKeywords }
                Write-Log "[Discord Control] Updated keywords.txt from command: $($newKeywords -join ', ')" -Level INFO
                $responseMessage = ":white_check_mark: Keywords set: $($newKeywords -join ', ')"
            }
        }
        elseif ($trim -match '^!keywords\s+add\s+(.+)$') {
            $raw = $Matches[1]
            $toAdd = @($raw -split ',' | ForEach-Object { Normalize-Keyword $_.Trim() } | Where-Object { $_ })
            if ($toAdd.Count -gt 0) {
                $existing = @(Load-KeywordsFromFile -Path $KeywordsFilePath)
                $merged = @($existing + $toAdd | Select-Object -Unique)
                $addedKws = @($toAdd | Where-Object { $existing -notcontains $_ })
                Set-Content -Path $KeywordsFilePath -Encoding UTF8 -Value ($merged -join "`n")
                Write-Log "[Discord Control] Added keywords: $($addedKws -join ', ')" -Level INFO
                if ($addedKws.Count -gt 0) {
                    $responseMessage = ":white_check_mark: Added: **$($addedKws -join ', ')**. All keywords: $($merged -join ', ')"
                } else {
                    $responseMessage = ":information_source: Keywords already present - no change. All: $($merged -join ', ')"
                }
                if (-not $applied) { $applied = [pscustomobject]@{} }
                $applied | Add-Member -NotePropertyName 'keywords' -NotePropertyValue $merged -Force
            }
        }
        elseif ($trim -match '^!keywords\s+remove\s+(.+)$') {
            $raw = $Matches[1]
            $toRemove = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($toRemove.Count -gt 0) {
                $existing = @(Load-KeywordsFromFile -Path $KeywordsFilePath)
                $remaining = @($existing | Where-Object { $toRemove -notcontains $_ })
                $removedCount = $existing.Count - $remaining.Count
                Set-Content -Path $KeywordsFilePath -Encoding UTF8 -Value ($remaining -join "`n")
                Write-Log "[Discord Control] Removed $removedCount keyword(s)" -Level INFO
                if ($removedCount -gt 0) {
                    $remainText = if ($remaining.Count -gt 0) { $remaining -join ', ' } else { '(none)' }
                    $responseMessage = ":white_check_mark: Removed $removedCount keyword(s). Remaining: $remainText"
                } else {
                    $existText = if ($existing.Count -gt 0) { $existing -join ', ' } else { '(none)' }
                    $responseMessage = ":information_source: None of those keywords matched. Current: $existText"
                }
            }
        }
        if ($trim -match '^!(?:dealtype|flairs)') {
            $responseMessage = ':information_source: Deal type filtering is now per-watch. Use `!watch add GPU | 5080 | max:1200 | type:GPU` to add a type filter to a watch.'
            continue
        }
        elseif ($trim -match '^!history(?:\s+count)?$') {
            $historyPath = Join-Path $ScriptPath 'history.json'
            if (Test-Path $historyPath) {
                try {
                    $histContent = Get-Content $historyPath -Raw | ConvertFrom-Json
                    $count = if ($histContent -is [array]) { $histContent.Count } else { 0 }
                    $plural = if ($count -ne 1) { 's' } else { '' }
                    $responseMessage = ":information_source: History: **$count** deal$plural tracked. Use ``!clearhistory`` to reset."
                } catch { $responseMessage = ':x: Could not read history file.' }
            } else {
                $responseMessage = ':information_source: No history file found (0 tracked deals).'
            }
        }
        elseif ($trim -match '^!scaninterval\s+(.+)$') {
            $arg = $Matches[1].Trim()
            if ($arg -ieq 'off') {
                try {
                    $configRaw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                    if ($configRaw.PSObject.Properties['scan_interval_minutes']) {
                        $configRaw.PSObject.Properties.Remove('scan_interval_minutes')
                    }
                    $configRaw | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $ConfigPath
                    $Config | Add-Member -NotePropertyName 'scan_interval_minutes' -NotePropertyValue $null -Force
                    $responseMessage = ':white_check_mark: Auto-scan interval removed from config. Update Task Scheduler if needed.'
                    Write-Log '[Discord Control] Removed scan_interval_minutes from config' -Level INFO
                }
                catch { $responseMessage = ':x: Failed to update config.' }
            }
            else {
                # Parse: 2d | 1d 30 | 30
                $parsedMins = 0
                if ($arg -match '(\d+)\s*d') { $parsedMins += [int]$Matches[1] * 1440 }
                $minPart = if ($arg -match 'd') { $arg -replace '^.*d\s*', '' } else { $arg }
                if ($minPart -match '^\d+$') { $parsedMins += [int]$minPart }
                if ($parsedMins -ge 1) {
                    $newInterval = $parsedMins
                    $fmtD = [math]::Floor($newInterval / 1440); $fmtM = $newInterval % 1440
                    $fmtParts = @()
                    if ($fmtD -gt 0) { $fmtParts += "$fmtD day$(if ($fmtD -ne 1) {'s'})" }
                    if ($fmtM -gt 0) { $fmtParts += "$fmtM min" }
                    $fmtStr = $fmtParts -join ' '
                    try {
                        $configRaw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                        $configRaw | Add-Member -NotePropertyName 'scan_interval_minutes' -NotePropertyValue $newInterval -Force
                        $Config | Add-Member -NotePropertyName 'scan_interval_minutes' -NotePropertyValue $newInterval -Force
                        $configRaw | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $ConfigPath
                        $responseMessage = ":white_check_mark: Auto-scan set to every **$fmtStr** ($newInterval min) in config.json. Update Task Scheduler trigger to match."
                        Write-Log "[Discord Control] Set scan_interval_minutes = $newInterval" -Level INFO
                    }
                    catch { $responseMessage = ':x: Failed to update config.' }
                } else {
                    $responseMessage = ':warning: Usage: `!scaninterval 30` / `!scaninterval 2d` / `!scaninterval 1d 30` / `!scaninterval off`'
                }
            }
        }
        elseif ($trim -match '^!maxprice\s+(\d+(?:\.\d+)?)$') {
            $val = [double]$Matches[1]
            Ensure-ConfigFilters -Config $Config
            $Config.filters | Add-Member -NotePropertyName 'max_price' -NotePropertyValue $val -Force
            Write-Log "[Discord Control] Set max_price = $val" -Level INFO
            if (-not $applied) { $applied = [pscustomobject]@{} }
            $applied | Add-Member -NotePropertyName 'max_price' -NotePropertyValue $val -Force
        }
        elseif ($trim -match '^!mindiscount\s+(\d+)$') {
            $val = [int]$Matches[1]
            Ensure-ConfigFilters -Config $Config
            $Config.filters | Add-Member -NotePropertyName 'min_discount_percent' -NotePropertyValue $val -Force
            Write-Log "[Discord Control] Set min_discount_percent = $val" -Level INFO
            if (-not $applied) { $applied = [pscustomobject]@{} }
            $applied | Add-Member -NotePropertyName 'min_discount_percent' -NotePropertyValue $val -Force
        }
    }

    if ($latestId) {
        $state.last_message_id = [string]$latestId
        Save-ControlState -State $state
    }

    if ($Config.discord_control.ack) {
        if ($applied) {
            $msg = ":white_check_mark: Deal Monitor updated from Discord control." 
            if ($applied.keywords) { $msg += " Keywords: $($applied.keywords -join ', ')" }
            if ($applied.max_price) { $msg += " | max_price=$($applied.max_price)" }
            if ($applied.min_discount_percent) { $msg += " | min_discount_percent=$($applied.min_discount_percent)" }
            Send-DiscordControlAck -ChannelId $channelId -BotToken $botToken -Message $msg
        }
        elseif ($responseMessage) {
            Send-DiscordControlAck -ChannelId $channelId -BotToken $botToken -Message $responseMessage
        }
    }

    return $applied
}

# ============================================================================
# HISTORY MANAGEMENT
# ============================================================================

function Load-History {
    try {
        if (Test-Path $HistoryPath) {
            $historyRaw = Get-Content $HistoryPath -Raw
            $history = $historyRaw | ConvertFrom-Json

            $ids = New-Object System.Collections.Generic.List[string]
            $needsRepair = $false

            function Add-IdsFromString {
                param([string]$Text)

                if ([string]::IsNullOrWhiteSpace($Text)) {
                    return
                }

                # Extract any 32-hex tokens (MD5) even if the string contains spaces/newlines.
                foreach ($m in [regex]::Matches($Text.ToLowerInvariant(), '[0-9a-f]{32}')) {
                    $ids.Add($m.Value)
                }
            }

            if ($null -eq $history) {
                # no-op
            }
            elseif ($history -is [array]) {
                foreach ($entry in $history) {
                    $entryString = [string]$entry
                    if ($entryString -notmatch '^[0-9a-f]{32}$') {
                        $needsRepair = $true
                    }
                    Add-IdsFromString -Text $entryString
                }
            }
            else {
                $needsRepair = $true
                Add-IdsFromString -Text ([string]$history)
            }

            # Deduplicate while preserving order
            $seen = New-Object 'System.Collections.Generic.HashSet[string]'
            $historyArray = New-Object System.Collections.Generic.List[string]
            foreach ($id in $ids) {
                if ($seen.Add($id)) {
                    $historyArray.Add($id)
                }
                else {
                    $needsRepair = $true
                }
            }

            Write-Log "Loaded $(($historyArray | Measure-Object).Count) items from history"

            if ($needsRepair) {
                Save-History -History @($historyArray.ToArray())
            }
            return @($historyArray.ToArray())
        }
        else {
            Write-Log "No history file found, starting fresh"
            return @()
        }
    }
    catch {
        Write-Log "Failed to load history: $_" -Level WARNING
        return @()
    }
}

function Save-History {
    param($History)
    
    try {
        # Keep only last 1000 items to prevent file bloat
        $historyArray = if ($History -is [array]) {
            @($History | ForEach-Object { [string]$_ })
        }
        elseif ($null -eq $History) {
            @()
        }
        else {
            @([string]$History)
        }

        # Deduplicate while preserving order
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        $deduped = New-Object System.Collections.Generic.List[string]
        foreach ($id in $historyArray) {
            if (-not [string]::IsNullOrWhiteSpace($id) -and $seen.Add($id)) {
                $deduped.Add($id)
            }
        }

        $trimmedHistory = @($deduped.ToArray() | Select-Object -Last 1000)
        @($trimmedHistory) | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $HistoryPath
        Write-Log "History saved ($(($trimmedHistory | Measure-Object).Count) items)"
    }
    catch {
        Write-Log "Failed to save history: $_" -Level ERROR
    }
}

function Is-DealSent {
    param(
        [string]$DealId,
        [array]$History
    )
    
    return $History -contains $DealId
}

# ============================================================================
# DEAL SOURCE FETCHING
# ============================================================================

function Fetch-RedditJSON {
    param(
        [string]$Subreddit,
        [int]$Limit = 25,
        [string[]]$AllowedFlairs = @()
    )
    
    try {
        $url = "https://www.reddit.com/r/$Subreddit/new.json?limit=$Limit"
        Write-Log "Fetching Reddit JSON: r/$Subreddit"
        
        $headers = @{
            "User-Agent" = "PowerShell:DealMonitor:v1.0 (by /u/dealmonitor)"
        }
        
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 30 -Headers $headers
        
        $deals = @()
        
        foreach ($post in $response.data.children) {
            $data = $post.data
            
            # Flair filtering: skip posts whose flair doesn't match the allowlist
            if ($AllowedFlairs -and $AllowedFlairs.Count -gt 0) {
                $flair = [string]$data.link_flair_text
                $flairMatched = $false
                foreach ($f in $AllowedFlairs) {
                    if ($flair -match [regex]::Escape($f)) {
                        $flairMatched = $true
                        break
                    }
                }
                if (-not $flairMatched) {
                    continue
                }
            }
            
            # Extract title and selftext
            $title = $data.title
            $description = if ($data.selftext) { $data.selftext } else { "" }
            $postUrl = if ($data.url) { $data.url } else { "https://reddit.com$($data.permalink)" }
            $flair = if ($data.link_flair_text) { [System.Net.WebUtility]::HtmlDecode([string]$data.link_flair_text) } else { $null }
            
            $deal = @{
                Title = $title
                Link = $postUrl
                Description = $description
                PubDate = (Get-Date "1970-01-01 00:00:00").AddSeconds($data.created_utc).ToString()
                Source = "Reddit r/$Subreddit"
                Flair = $flair
            }
            
            $deals += $deal
        }
        
        Write-Log "Fetched $(($deals | Measure-Object).Count) deals from Reddit r/$Subreddit (flair filter: $(if ($AllowedFlairs -and $AllowedFlairs.Count -gt 0) { $AllowedFlairs -join ', ' } else { 'none' }))"
        return $deals
    }
    catch {
        Write-Log "Failed to fetch Reddit JSON r/$Subreddit : $_" -Level ERROR
        return @()
    }
}

function Fetch-SlickdealsWeb {
    param([string]$Url, [int]$MaxDeals = 20)
    
    try {
        Write-Log "Fetching Slickdeals web page: $Url"
        
        $headers = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 30 -Headers $headers
        
        $deals = @()
        
        # Parse HTML for deal posts (basic scraping)
        # Looking for deal links in the format /f/XXXXXX
        $dealLinks = $response.Links | Where-Object { $_.href -match '^/f/\d+' } | Select-Object -First $MaxDeals
        
        foreach ($link in $dealLinks) {
            $dealTitle = $link.innerText
            $dealUrl = "https://slickdeals.net" + $link.href
            
            if ($dealTitle -and $dealTitle.Length -gt 5) {
                $deal = @{
                    Title = $dealTitle
                    Link = $dealUrl
                    Description = ""
                    PubDate = (Get-Date).ToString()
                    Source = "Slickdeals Web"
                }
                
                $deals += $deal
            }
        }
        
        Write-Log "Fetched $(($deals | Measure-Object).Count) deals from Slickdeals web scraping"
        return $deals
    }
    catch {
        Write-Log "Failed to fetch Slickdeals web page: $_" -Level ERROR
        return @()
    }
}

function Fetch-RSSFeed {
    param([string]$Url)
    
    try {
        Write-Log "Fetching RSS feed: $Url"
        
        # Add User-Agent header to avoid being blocked by Reddit
        $headers = @{
            "User-Agent" = "PowerShell Deal Monitor/1.0 (Windows)"
        }
        
        $response = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 30 -Headers $headers
        
        $deals = @()
        
        # Handle different RSS feed structures
        if ($response.rss.channel.item) {
            $items = $response.rss.channel.item
        }
        elseif ($response.feed.entry) {
            $items = $response.feed.entry
        }
        elseif ($response.channel.item) {
            $items = $response.channel.item
        }
        else {
            Write-Log "Unknown RSS feed structure for $Url" -Level WARNING
            return @()
        }
        
        foreach ($item in $items) {
            $deal = @{
                Title = if ($item.title) { $item.title } else { $item.summary }
                Link = if ($item.link.'#text') { $item.link.'#text' } elseif ($item.link.href) { $item.link.href } else { $item.link }
                Description = if ($item.description) { $item.description } else { $item.summary }
                PubDate = if ($item.pubDate) { $item.pubDate } else { $item.published }
                Source = $Url
            }
            
            # Debug: Show what was fetched
            Write-Log "  - Fetched: $($deal.Title)"
            
            $deals += $deal
        }
        
        Write-Log "Fetched $(($deals | Measure-Object).Count) deals from RSS feed"
        return $deals
    }
    catch {
        Write-Log "Failed to fetch RSS feed $Url : $_" -Level ERROR
        return @()
    }
}

function Fetch-JSONEndpoint {
    param([string]$Url)
    
    try {
        Write-Log "Fetching JSON endpoint: $Url"
        $response = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 30
        
        # Assuming JSON response is an array of deals
        $deals = @()
        
        foreach ($item in $response) {
            $deal = @{
                Title = $item.title
                Link = $item.url
                Description = $item.description
                Price = $item.price
                OriginalPrice = $item.original_price
                PubDate = $item.date
                Source = $Url
            }
            
            $deals += $deal
        }
        
        Write-Log "Fetched $(($deals | Measure-Object).Count) deals from JSON endpoint"
        return $deals
    }
    catch {
        Write-Log "Failed to fetch JSON endpoint $Url : $_" -Level ERROR
        return @()
    }
}

# ============================================================================
# DEAL PARSING & EXTRACTION
# ============================================================================

function Extract-PriceInfo {
    param([string]$Text)

    $prices = @()

    # Pattern 1: Standard dollar-sign prices  e.g. $299, $1,299.99
    foreach ($m in [regex]::Matches($Text, '\$\s*(\d[\d,]*(?:\.\d{1,2})?)')) {
        $prices += [decimal]($m.Groups[1].Value -replace ',', '')
    }

    # Pattern 2: Hardwareswap-style prices without $ sign
    # Only used when no $-prices found, to avoid double-counting.
    # Requires a payment/shipping word after the number so model numbers
    # like "5080" or "1440p" are never mistaken for prices.
    # Matches: "800 shipped", "800 OBO", "800 or best offer",
    #          "800 local", "800 firm", "800 PayPal", "800 Venmo",
    #          "800 Zelle", "800 Cash"
    if ($prices.Count -eq 0) {
        $hwsPattern = '\b(\d[\d,]*(?:\.\d{1,2})?)\s*(?:shipped|obo|or\s+best\s+offer|local|firm|paypal|venmo|zelle|cash)\b'
        foreach ($m in [regex]::Matches($Text, $hwsPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $prices += [decimal]($m.Groups[1].Value -replace ',', '')
        }
    }

    if ($prices.Count -eq 0) {
        return @{ CurrentPrice = $null; OriginalPrice = $null; DiscountPercent = $null }
    }
    elseif ($prices.Count -eq 1) {
        return @{ CurrentPrice = $prices[0]; OriginalPrice = $null; DiscountPercent = $null }
    }
    else {
        # Assume format: "$299 (was $399)" or "800 shipped (was $1000)" etc.
        $currentPrice = $prices[0]
        $originalPrice = $prices[1]

        if ($originalPrice -gt $currentPrice) {
            $discount = [math]::Round((($originalPrice - $currentPrice) / $originalPrice) * 100, 1)
            return @{ CurrentPrice = $currentPrice; OriginalPrice = $originalPrice; DiscountPercent = $discount }
        }
        else {
            return @{ CurrentPrice = $currentPrice; OriginalPrice = $originalPrice; DiscountPercent = $null }
        }
    }
}

function Extract-DiscountPercent {
    param([string]$Text)
    
    # Extract discount percentage (e.g., "50% off", "-30%", "30% discount")
    $discountPattern = '(\d{1,2})%\s*(?:off|discount|sale)'
    $match = [regex]::Match($Text, $discountPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    if ($match.Success) {
        return [int]$match.Groups[1].Value
    }
    
    return $null
}

# ============================================================================
# FILTERING & SCORING
# ============================================================================

function Test-KeywordMatch {
    param(
        [string]$Text,
        $Keywords
    )
    
    $matchList = New-Object System.Collections.Generic.List[string]
    
    foreach ($keyword in $Keywords) {
        $keywordStr = [string]$keyword
        
        if ($Text -match [regex]::Escape($keywordStr)) {
            $matchList.Add($keywordStr)
        }
    }
    
    return $matchList.ToArray()
}

function Calculate-HotnessScore {
    param(
        [hashtable]$Deal,
        [array]$MatchedKeywords,
        [decimal]$CurrentPrice,
        [decimal]$DiscountPercent
    )
    
    $score = 0
    
    # Discount percentage contributes heavily (0-50 points)
    if ($DiscountPercent) {
        $score += [math]::Min($DiscountPercent, 50)
    }
    
    # Price threshold bonus (lower price = higher score for same discount)
    # Award up to 20 points for deals under $100, scaling down as price increases
    if ($CurrentPrice) {
        if ($CurrentPrice -lt 100) {
            $score += 20
        }
        elseif ($CurrentPrice -lt 300) {
            $score += 15
        }
        elseif ($CurrentPrice -lt 500) {
            $score += 10
        }
        elseif ($CurrentPrice -lt 1000) {
            $score += 5
        }
    }
    
    # Keyword match strength (5 points per matched keyword, max 30)
    $keywordBonus = ($MatchedKeywords | Measure-Object).Count * 5
    $score += [math]::Min($keywordBonus, 30)
    
    return $score
}

function Filter-Deal {
    param(
        [hashtable]$Deal,
        [object]$Config
    )
    
    $fullText = "$($Deal.Title) $($Deal.Description)"

    # Skip r/hardwareswap "Want to Buy" posts.
    # On hardwareswap every post uses [H] = Have and [W] = Want.
    # SELLING post: [H] <product>       [W] <payment method>
    # WTB post:     [H] <payment method> [W] <product>
    # We detect WTB by checking whether the content between [H] and [W]
    # consists entirely of payment/location keywords (PayPal, Cash, Venmo,
    # Zelle, Local, Verified, etc.) with no actual product words.
    if ($Deal.Source -match 'hardwareswap') {
        $hMatch = [regex]::Match($Deal.Title, '(?i)\[H\]\s*(.+?)\s*\[W\]')
        if ($hMatch.Success) {
            $hContent = $hMatch.Groups[1].Value.Trim()
            # Strip out all payment/location tokens and punctuation
            $stripped = $hContent -replace '(?i)\b(?:cash|paypal|venmo|zelle|local|verified|or|and|g&s|gs|f&f|ff)\b', ''
            $stripped = $stripped -replace '[,/&+\s]', ''
            # If nothing meaningful remains, the [H] section was payment-only → WTB post
            if ($stripped.Length -eq 0) {
                Write-Log "Skipping hardwareswap WTB post: $($Deal.Title)"
                return $null
            }
        }
    }

    # Extract price information once (shared by all watches)
    $priceInfo = Extract-PriceInfo -Text $fullText
    $extractedDiscount = Extract-DiscountPercent -Text $fullText
    $currentPrice = if ($Deal.Price) { $Deal.Price } else { $priceInfo.CurrentPrice }
    $originalPrice = if ($Deal.OriginalPrice) { $Deal.OriginalPrice } else { $priceInfo.OriginalPrice }
    $discountPercent = if ($extractedDiscount) { $extractedDiscount } else { $priceInfo.DiscountPercent }
    
    # Build the watches list:  config.watches (multi-watch) or fall back to legacy single-keyword mode
    $watches = @()
    if ($Config.watches -and ($Config.watches | Measure-Object).Count -gt 0) {
        $watches = @($Config.watches)
    }
    else {
        # Legacy mode: build one watch from top-level keywords + filters
        $legacyWatch = [pscustomobject]@{
            name = 'Default'
            keywords = @($Config.keywords)
            max_price = $Config.filters.max_price
            min_discount_percent = $Config.filters.min_discount_percent
        }
        $watches = @($legacyWatch)
    }
    
    # Try each watch — first match wins
    foreach ($watch in $watches) {
        $watchKeywords = @($watch.keywords)
        if (($watchKeywords | Measure-Object).Count -eq 0) { continue }

        $matchedKeywords = Test-KeywordMatch -Text $fullText -Keywords $watchKeywords
        if (($matchedKeywords | Measure-Object).Count -eq 0) { continue }

        # Per-watch deal type filter (optional): check post flair if watch has 'flairs' defined
        if ($watch.flairs -and ($watch.flairs | Measure-Object).Count -gt 0) {
            $postFlair = [string]$Deal.Flair
            $flairMatched = $false
            foreach ($f in $watch.flairs) {
                if ($postFlair -match [regex]::Escape([string]$f)) { $flairMatched = $true; break }
            }
            if (-not $flairMatched) {
                $watchName2 = if ($watch.name) { $watch.name } else { 'unnamed' }
                Write-Log "Deal skipped by watch '$watchName2': flair '$postFlair' not in [$($watch.flairs -join ', ')]"
                continue
            }
        }
        
        # Per-watch price filter (falls back to global if not set)
        $watchMaxPrice = if ($null -ne $watch.max_price) { $watch.max_price } else { $Config.filters.max_price }
        $watchMinDiscount = if ($null -ne $watch.min_discount_percent) { $watch.min_discount_percent } else { $Config.filters.min_discount_percent }
        
        if ($watchMaxPrice -and $currentPrice -and ($currentPrice -gt $watchMaxPrice)) {
            $watchName = if ($watch.name) { $watch.name } else { 'unnamed' }
            Write-Log "Deal filtered out by watch '$watchName': Price $currentPrice exceeds max $watchMaxPrice"
            continue
        }
        
        if ($watchMinDiscount -and $discountPercent -and ($discountPercent -lt $watchMinDiscount)) {
            $watchName = if ($watch.name) { $watch.name } else { 'unnamed' }
            Write-Log "Deal filtered out by watch '$watchName': Discount $discountPercent% below min $watchMinDiscount%"
            continue
        }
        
        # This watch matched — calculate hotness and return the enriched deal
        $hotnessScore = Calculate-HotnessScore -Deal $Deal -MatchedKeywords $matchedKeywords -CurrentPrice $currentPrice -DiscountPercent $discountPercent
        
        $dealIdSeed = if ($Deal.Link) {
            [string]$Deal.Link
        }
        else {
            "$(($Deal.Source))|$(($Deal.Title))|$(($Deal.PubDate))"
        }
        
        $watchName = if ($watch.name) { [string]$watch.name } else { 'Default' }

        return @{
            Title = $Deal.Title
            Link = $Deal.Link
            Description = $Deal.Description
            CurrentPrice = $currentPrice
            OriginalPrice = $originalPrice
            DiscountPercent = $discountPercent
            MatchedKeywords = $matchedKeywords
            HotnessScore = $hotnessScore
            Source = $Deal.Source
            PubDate = $Deal.PubDate
            WatchName = $watchName
            DealId = -join ([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dealIdSeed)) | ForEach-Object { $_.ToString("x2") })
        }
    }
    
    return $null  # No watch matched
}

# ============================================================================
# DISCORD NOTIFICATION
# ============================================================================

function Send-DiscordNotification {
    param(
        [hashtable]$Deal,
        [string]$WebhookUrl
    )
    
    try {
        # Determine embed color based on hotness score
        if ($Deal.HotnessScore -ge 70) {
            $color = 15158332  # Red - HOT DEAL
        }
        elseif ($Deal.HotnessScore -ge 50) {
            $color = 15105570  # Orange - Great deal
        }
        elseif ($Deal.HotnessScore -ge 30) {
            $color = 3447003   # Blue - Good deal
        }
        else {
            $color = 9807270   # Gray - Decent deal
        }
        
        # Build description
        $description = ""
        
        if ($Deal.CurrentPrice) {
            $priceText = "**Price:** $" + $Deal.CurrentPrice
            
            if ($Deal.OriginalPrice) {
                $priceText += " ~~" + "$" + $Deal.OriginalPrice + "~~"
            }
            
            $description += $priceText + "`n"
        }
        
        if ($Deal.DiscountPercent) {
            $description += "**Discount:** " + $Deal.DiscountPercent + "% OFF`n"
        }
        
        $description += "**Hotness:** " + $Deal.HotnessScore + " points`n"
        if ($Deal.WatchName -and $Deal.WatchName -ne 'Default') {
            $description += "**Watch:** " + $Deal.WatchName + "`n"
        }
        $description += "**Keywords:** " + ($Deal.MatchedKeywords -join ', ') + "`n"
        
        if ($Deal.Description -and $Deal.Description.Length -gt 0) {
            $shortDesc = if ($Deal.Description.Length -gt 200) { 
                $Deal.Description.Substring(0, 200) + "..." 
            } else { 
                $Deal.Description 
            }
            $description += "`n" + $shortDesc
        }
        
        # Build embed
        $embed = @{
            title = $Deal.Title
            url = $Deal.Link
            description = $description
            color = $color
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            footer = @{
                text = "Deal Monitor - Score: $($Deal.HotnessScore)$(if ($Deal.WatchName -and $Deal.WatchName -ne 'Default') { " | $($Deal.WatchName)" })"
            }
        }
        
        # Build payload
        $payload = @{
            username = "Deal Monitor"
            avatar_url = "https://cdn-icons-png.flaticon.com/512/3565/3565688.png"
            embeds = @($embed)
        } | ConvertTo-Json -Depth 10
        
        # Send to Discord (UTF-8 bytes to avoid encoding issues on PS 5.1)
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)

        $maxRetries = 3
        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                $response = Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payloadBytes -ContentType 'application/json; charset=utf-8'
                Write-Log "Discord notification sent: $($Deal.Title)" -Level SUCCESS
                return $true
            }
            catch {
                # Handle Discord 429 rate-limit
                $statusCode = $null
                try {
                    if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    }
                }
                catch { }

                if ($statusCode -eq 429 -and $attempt -lt $maxRetries) {
                    # Try to read Retry-After header; default to 5 seconds
                    $retryAfter = 5
                    try {
                        $retryHeader = $_.Exception.Response.Headers | Where-Object { $_.Key -eq 'Retry-After' } | Select-Object -First 1
                        if ($retryHeader) {
                            $retryAfter = [math]::Max([int]$retryHeader.Value[0], 1)
                        }
                    }
                    catch { }
                    Write-Log "Discord rate limited (429). Retrying in ${retryAfter}s (attempt $attempt/$maxRetries)" -Level WARNING
                    Start-Sleep -Seconds $retryAfter
                    continue
                }

                Write-Log "Failed to send Discord notification: $_" -Level ERROR
                return $false
            }
        }

        return $false
    }
    catch {
        Write-Log "Failed to send Discord notification: $_" -Level ERROR
        return $false
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Write-Log "========================================" -Level INFO
    Write-Log "Deal Monitor Started" -Level INFO
    Write-Log "========================================" -Level INFO
    
    # Load configuration
    $config = Load-Configuration -Path $ConfigPath
    if (-not $config) {
        Write-Log "Cannot continue without configuration" -Level ERROR
        exit 1
    }

    # If Discord control is enabled, validate bot token early (without printing it)
    Test-DiscordBotToken -Config $config

    # Optional interactive keyword setup (writes keywords.txt, then exits)
    if ($ConfigureKeywords) {
        $keywordsFilePath = Resolve-PathRelativeToScript -Path $KeywordsFile
        $raw = Read-Host "Enter keywords (comma-separated). Example: RTX 4070, 2TB NVMe, DDR5"
        $newKeywords = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        if (($newKeywords | Measure-Object).Count -eq 0) {
            Write-Log "No keywords provided; not updating $keywordsFilePath" -Level WARNING
            exit 0
        }

        @(
            "# One keyword per line. Blank lines and lines starting with # are ignored.",
            "# Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
            ""
        ) + $newKeywords | Set-Content -Path $keywordsFilePath

        Write-Log "Updated keywords file: $keywordsFilePath" -Level SUCCESS
        Write-Log "Keywords: $($newKeywords -join ', ')" -Level INFO
        exit 0
    }

    # Keywords source priority:
    # 0) Discord control channel (optional) -> updates keywords.txt
    # 1) -Keywords CLI param
    # 2) keywords.txt file
    # 3) config.json keywords
    $keywordsFilePath = Resolve-PathRelativeToScript -Path $KeywordsFile
    if (-not $SkipDiscordControl) {
        [void](Try-ApplyDiscordControl -Config $config -KeywordsFilePath $keywordsFilePath)
    } else {
        Write-Log "Skipping Discord control polling (launched by bot)" -Level INFO
    }
    $fileKeywords = Load-KeywordsFromFile -Path $keywordsFilePath

    if ($PSBoundParameters.ContainsKey('Keywords') -and $Keywords -and $Keywords.Count -gt 0) {
        $config.keywords = @($Keywords)
        Write-Log "Using keywords from CLI: $($config.keywords -join ', ')"
    }
    elseif ($fileKeywords -and ($fileKeywords | Measure-Object).Count -gt 0) {
        $config.keywords = @($fileKeywords)
        Write-Log "Using keywords from file ${keywordsFilePath}: $($config.keywords -join ', ')"
    }
    else {
        $config.keywords = @($config.keywords)
        Write-Log "Using keywords from config.json: $($config.keywords -join ', ')"
    }

    # Optional CLI overrides for filters (so you don't have to edit JSON)
    Ensure-ConfigFilters -Config $config
    if ($PSBoundParameters.ContainsKey('MaxPrice')) {
        $config.filters | Add-Member -NotePropertyName 'max_price' -NotePropertyValue $MaxPrice -Force
        Write-Log "Override: max_price = $MaxPrice"
    }
    if ($PSBoundParameters.ContainsKey('MinDiscountPercent')) {
        $config.filters | Add-Member -NotePropertyName 'min_discount_percent' -NotePropertyValue $MinDiscountPercent -Force
        Write-Log "Override: min_discount_percent = $MinDiscountPercent"
    }
    
    # Load history
    $history = Load-History
    if ($null -eq $history) {
        $history = @()
    }
    elseif ($history -isnot [array]) {
        $history = @([string]$history)
    }
    else {
        $history = @($history | ForEach-Object { [string]$_ })
    }
    
    # Fetch deals from all sources (no global flair pre-filter — each watch handles its own type filter)
    $allDeals = @()

    foreach ($source in $config.sources) {
        if ($source.type -eq "reddit") {
            $deals = Fetch-RedditJSON -Subreddit $source.subreddit -Limit 25
            $allDeals += $deals
        }
        elseif ($source.type -eq "slickdeals-web") {
            $deals = Fetch-SlickdealsWeb -Url $source.url
            $allDeals += $deals
        }
        elseif ($source.type -eq "rss") {
            $deals = Fetch-RSSFeed -Url $source.url
            $allDeals += $deals
        }
        elseif ($source.type -eq "json") {
            $deals = Fetch-JSONEndpoint -Url $source.url
            $allDeals += $deals
        }
    }
    
    Write-Log "Total deals fetched: $(($allDeals | Measure-Object).Count)"
    
    # Filter and score deals
    $filteredDeals = @()
    
    foreach ($deal in $allDeals) {
        $filteredDeal = Filter-Deal -Deal $deal -Config $config
        
        if ($filteredDeal) {
            # Check if already sent
            if (-not (Is-DealSent -DealId $filteredDeal.DealId -History $history)) {
                $filteredDeals += $filteredDeal
            }
            else {
                Write-Log "Skipping already sent deal: $($filteredDeal.Title)"
            }
        }
    }
    
    Write-Log "Filtered deals (new): $(($filteredDeals | Measure-Object).Count)"
    
    # Sort by hotness score (descending)
    $filteredDeals = $filteredDeals | Sort-Object -Property HotnessScore -Descending
    
    # Send Discord notifications
    $sentCount = 0
    
    foreach ($deal in $filteredDeals) {
        $sent = Send-DiscordNotification -Deal $deal -WebhookUrl $config.discord_webhook_url
        
        if ($sent) {
            $history += @($deal.DealId)
            $sentCount++
            
            # Crash-safe: save history after each successful send so
            # we never re-notify if the script dies mid-run
            Save-History -History $history
            
            # Rate limiting - wait 2 seconds between notifications
            if ($sentCount -lt ($filteredDeals | Measure-Object).Count) {
                Start-Sleep -Seconds 2
            }
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "Deal Monitor Completed" -Level SUCCESS
    Write-Log "Sent: $sentCount notifications" -Level SUCCESS
    Write-Log "========================================" -Level INFO
}

# Run main function
try {
    Main
}
catch {
    Write-Log "Fatal error in main execution: $_" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    exit 1
}
