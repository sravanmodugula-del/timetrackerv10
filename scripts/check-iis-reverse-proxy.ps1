param(
   [string]$SiteName = "TimeTracker",
   [string]$AppPoolName = "TimeTrackerAppPool",
   [string]$Domain = "timetracker.fmb.com"
)

Write-Host "IIS Reverse Proxy Status Check" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

# 1. Check IIS Service
Write-Host "`n1. Checking IIS Service..." -ForegroundColor Cyan
$iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
if ($iisService) {
    if ($iisService.Status -eq "Running") {
        Write-Host "✅ IIS Service is running" -ForegroundColor Green
    } else {
        Write-Host "❌ IIS Service is not running: $($iisService.Status)" -ForegroundColor Red
    }
} else {
    Write-Host "❌ IIS Service not found" -ForegroundColor Red
}

# 2. Check Application Pool
Write-Host "`n2. Checking Application Pool..." -ForegroundColor Cyan
try {
    $appPool = Get-WebAppPool -Name $AppPoolName -ErrorAction Stop
    if ($appPool.State -eq "Started") {
        Write-Host "✅ Application Pool '$AppPoolName' is started" -ForegroundColor Green
    } else {
        Write-Host "❌ Application Pool '$AppPoolName' is $($appPool.State)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Application Pool '$AppPoolName' not found" -ForegroundColor Red
}

# 3. Check Website
Write-Host "`n3. Checking Website..." -ForegroundColor Cyan
try {
    $website = Get-Website -Name $SiteName -ErrorAction Stop
    if ($website.State -eq "Started") {
        Write-Host "✅ Website '$SiteName' is started" -ForegroundColor Green
        Write-Host "   Physical Path: $($website.PhysicalPath)" -ForegroundColor Gray
    } else {
        Write-Host "❌ Website '$SiteName' is $($website.State)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Website '$SiteName' not found" -ForegroundColor Red
}

# 4. Check Bindings
Write-Host "`n4. Checking Website Bindings..." -ForegroundColor Cyan
try {
    $bindings = Get-WebBinding -Name $SiteName -ErrorAction Stop
    foreach ($binding in $bindings) {
        Write-Host "✅ $($binding.protocol)://$($binding.bindingInformation)" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Could not retrieve bindings for '$SiteName'" -ForegroundColor Red
}

# 5. Check Port Listeners
Write-Host "`n5. Checking Port Listeners..." -ForegroundColor Cyan
$ports = @(80, 443, 3000)
foreach ($port in $ports) {
    $listening = netstat -ano | findstr ":$port "
    if ($listening) {
        Write-Host "✅ Port $port is being listened on" -ForegroundColor Green
    } else {
        Write-Host "❌ Port $port is not being listened on" -ForegroundColor Red
    }
}

# 6. Test HTTP Connectivity
Write-Host "`n6. Testing HTTP Connectivity..." -ForegroundColor Cyan

# First check if IIS is running
try {
    $iisService = Get-Service -Name "W3SVC" -ErrorAction Stop
    if ($iisService.Status -eq "Running") {
        Write-Host "✅ IIS Service (W3SVC) is running" -ForegroundColor Green
    } else {
        Write-Host "❌ IIS Service (W3SVC) is not running: $($iisService.Status)" -ForegroundColor Red
        Write-Host "   Starting IIS..." -ForegroundColor Yellow
        Start-Service -Name "W3SVC"
    }
} catch {
    Write-Host "❌ IIS Service (W3SVC) not found or accessible: $($_.Exception.Message)" -ForegroundColor Red
}

# Check if Node.js application is running on port 3000
Write-Host "`n   Testing Node.js application (port 3000)..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/api/health" -Method GET -TimeoutSec 10 -ErrorAction Stop
    Write-Host "✅ Node.js application responding on port 3000: $($response.StatusCode)" -ForegroundColor Green

    # Parse health check response
    if ($response.Content) {
        $healthData = $response.Content | ConvertFrom-Json
        Write-Host "   Application Status: $($healthData.status)" -ForegroundColor Gray
        Write-Host "   Environment: $($healthData.environment)" -ForegroundColor Gray
    }
} catch {
    Write-Host "❌ Node.js application not responding on port 3000: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Make sure the application is running with: npm start or pm2 start" -ForegroundColor Yellow
}

# Check IIS reverse proxy (port 80)
Write-Host "`n   Testing IIS reverse proxy (port 80)..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost" -Method HEAD -TimeoutSec 10 -ErrorAction Stop
    Write-Host "✅ IIS reverse proxy responding on port 80: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "❌ IIS reverse proxy not responding on port 80: $($_.Exception.Message)" -ForegroundColor Red

    # Check if TimeTracker site exists in IIS
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $site = Get-Website -Name "TimeTracker" -ErrorAction Stop
        Write-Host "   TimeTracker IIS site status: $($site.State)" -ForegroundColor Yellow

        if ($site.State -ne "Started") {
            Write-Host "   Starting TimeTracker site..." -ForegroundColor Yellow
            Start-Website -Name "TimeTracker"
        }
    } catch {
        Write-Host "   TimeTracker IIS site not found or not configured" -ForegroundColor Red
        Write-Host "   Run: .\create-windows-service.ps1 to configure IIS" -ForegroundColor Yellow
    }
}

# Additional troubleshooting information
Write-Host "`n   Troubleshooting Information:" -ForegroundColor Cyan
Write-Host "   - Node.js app should run on http://127.0.0.1:3000" -ForegroundColor Gray
Write-Host "   - IIS should proxy http://localhost to the Node.js app" -ForegroundColor Gray
Write-Host "   - Check web.config for reverse proxy rules" -ForegroundColor Gray

# Check if processes are running
$nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue
if ($nodeProcesses) {
    Write-Host "   Active Node.js processes: $($nodeProcesses.Count)" -ForegroundColor Green
} else {
    Write-Host "   No Node.js processes found" -ForegroundColor Red
    Write-Host "   Start the application with: npm start" -ForegroundColor Yellow
}

# 7. Test HTTPS Connectivity (if certificate exists)
Write-Host "`n7. Testing HTTPS Connectivity..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "https://localhost" -Method HEAD -TimeoutSec 10 -SkipCertificateCheck -ErrorAction Stop
    Write-Host "✅ HTTPS (port 443) responding: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "❌ HTTPS (port 443) not responding: $($_.Exception.Message)" -ForegroundColor Red
}

# 8. Test Node.js Backend
Write-Host "`n8. Testing Node.js Backend..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000/api/health" -Method GET -TimeoutSec 10 -ErrorAction Stop
    Write-Host "✅ Node.js backend responding: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js backend not responding: $($_.Exception.Message)" -ForegroundColor Red
}

# 9. Check Reverse Proxy Configuration
Write-Host "`n9. Checking Reverse Proxy Configuration..." -ForegroundColor Cyan
$webConfigPath = "C:\TimeTracker\web.config"
if (Test-Path $webConfigPath) {
    $webConfig = Get-Content $webConfigPath -Raw
    if ($webConfig -match "rewrite" -and $webConfig -match "localhost:3000") {
        Write-Host "✅ Reverse proxy rules found in web.config" -ForegroundColor Green
    } else {
        Write-Host "❌ Reverse proxy rules not found or incorrect in web.config" -ForegroundColor Red
    }
} else {
    Write-Host "❌ web.config not found at $webConfigPath" -ForegroundColor Red
}

# 10. Check Recent IIS Logs
Write-Host "`n10. Checking Recent IIS Logs..." -ForegroundColor Cyan
$logPath = "C:\inetpub\logs\LogFiles\W3SVC1"
if (Test-Path $logPath) {
    $latestLog = Get-ChildItem $logPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestLog) {
        $recentEntries = Get-Content $latestLog.FullName | Select-Object -Last 5
        Write-Host "✅ Recent IIS log entries:" -ForegroundColor Green
        $recentEntries | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
    }
} else {
    Write-Host "❌ IIS log directory not found" -ForegroundColor Red
}

Write-Host "`n==============================" -ForegroundColor Green
Write-Host "Status check completed!" -ForegroundColor Green