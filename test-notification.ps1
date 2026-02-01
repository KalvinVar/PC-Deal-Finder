# Test Discord Webhook - Sends a sample deal notification

param(
    [string]$WebhookUrl
)

if (-not $WebhookUrl) {
    Write-Host "ERROR: No webhook URL provided." -ForegroundColor Red
    Write-Host "Usage: .\test-notification.ps1 -WebhookUrl 'YOUR_WEBHOOK_URL'" -ForegroundColor Yellow
    exit 1
}

Write-Host "Sending test notification to Discord..." -ForegroundColor Cyan

# Create a sample deal
$testDeal = @{
    Title = "[GPU] NVIDIA RTX 4070 Ti SUPER - GAMING GRAPHICS CARD"
    Link = "https://www.example.com/test-deal"
    CurrentPrice = 599.99
    OriginalPrice = 799.99
    DiscountPercent = 25
    MatchedKeywords = @("RTX 4070", "GPU", "deal")
    HotnessScore = 75
    Description = "This is a TEST notification to verify your Discord webhook is working correctly. The deal monitor script is configured and ready to send real alerts!"
}

# Build description
$description = ""

if ($testDeal.CurrentPrice) {
    $priceText = "**Price:** $" + $testDeal.CurrentPrice
    
    if ($testDeal.OriginalPrice) {
        $priceText += " ~~" + "$" + $testDeal.OriginalPrice + "~~"
    }
    
    $description += $priceText + "`n"
}

if ($testDeal.DiscountPercent) {
    $description += "**Discount:** " + $testDeal.DiscountPercent + "% OFF`n"
}

$description += "**Hotness:** " + $testDeal.HotnessScore + " points`n"
$description += "**Keywords:** " + ($testDeal.MatchedKeywords -join ', ') + "`n"
$description += "`n" + $testDeal.Description

# Build embed (RED color for hot deal)
$embed = @{
    title = $testDeal.Title
    url = $testDeal.Link
    description = $description
    color = 15158332  # Red
    timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    footer = @{
        text = "Deal Monitor TEST - Score: $($testDeal.HotnessScore)"
    }
}

# Build payload
$payload = @{
    username = "Deal Monitor (TEST)"
    avatar_url = "https://cdn-icons-png.flaticon.com/512/3565/3565688.png"
    embeds = @($embed)
} | ConvertTo-Json -Depth 10

try {
    # Send to Discord
    $response = Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType "application/json"
    
    Write-Host "`n✅ SUCCESS! Test notification sent to Discord!" -ForegroundColor Green
    Write-Host "Check your Discord channel for the message." -ForegroundColor Green
    Write-Host "`nThe deal monitor is working correctly and ready to send real alerts!" -ForegroundColor Cyan
}
catch {
    Write-Host "`n❌ ERROR: Failed to send notification" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "`nPlease verify:" -ForegroundColor Yellow
    Write-Host "  1. The webhook URL is correct" -ForegroundColor Yellow
    Write-Host "  2. The webhook hasn't been deleted in Discord" -ForegroundColor Yellow
    Write-Host "  3. You have internet connectivity" -ForegroundColor Yellow
}
