
# Complete TimeTracker Windows Installation
# Run as Administrator - This script orchestrates the entire installation

param(
    [string]$Domain = "timetracker.fmb.com",
    [string]$InstallPath = "C:\TimeTracker",
    [string]$SqlServer = "localhost",
    [string]$SqlUser = "timetracker",
    [string]$SqlPassword = "iTT!`$Lo7gm`"i'JAg~5Y\",
    [switch]$SkipIIS,
    [switch]$SkipSQL
)

$ErrorActionPreference = "Stop"

Write-Host "TimeTracker Complete Windows Installation" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Enable Windows Features
Write-Host "Step 1: Enabling Windows Features..." -ForegroundColor Green
& "$PSScriptRoot\enable-windows-features.ps1"

# Step 2: Install Node.js
Write-Host "Step 2: Installing Node.js..." -ForegroundColor Green
& "$PSScriptRoot\install-nodejs.ps1"

# Step 3: Setup SQL Server (if not skipped)
if (!$SkipSQL) {
    Write-Host "Step 3: Setting up SQL Server..." -ForegroundColor Green
    # Run SQL script manually or via sqlcmd
    sqlcmd -S $SqlServer -E -i "$PSScriptRoot\setup-sqlserver.sql"
}

# Step 4: Install Application
Write-Host "Step 4: Installing TimeTracker..." -ForegroundColor Green
& "$PSScriptRoot\install-timetracker.ps1" -InstallPath $InstallPath -Domain $Domain -SqlServer $SqlServer -SqlUser $SqlUser -SqlPassword $SqlPassword

# Step 5: Configure IIS (if not skipped)
if (!$SkipIIS) {
    Write-Host "Step 5: Configuring IIS..." -ForegroundColor Green
    & "$PSScriptRoot\configure-iis.ps1" -Domain $Domain -InstallPath $InstallPath
}

# Step 6: Create Windows Service
Write-Host "Step 6: Creating Windows Service..." -ForegroundColor Green
& "$PSScriptRoot\create-windows-service.ps1" -InstallPath $InstallPath

# Step 7: Install SSL Certificate
Write-Host "Step 7: Installing SSL Certificate..." -ForegroundColor Green
& "$PSScriptRoot\install-ssl-certificate.ps1" -Domain $Domain

# Step 8: Database Migration
Write-Host "Step 8: Running Database Migration..." -ForegroundColor Green
& "$PSScriptRoot\migrate-database.ps1" -InstallPath $InstallPath

# Step 9: Setup Logging
Write-Host "Step 9: Setting up Logging..." -ForegroundColor Green
& "$PSScriptRoot\setup-logging.ps1" -InstallPath $InstallPath

# Step 10: Security Hardening
Write-Host "Step 10: Applying Security Hardening..." -ForegroundColor Green
& "$PSScriptRoot\security-hardening.ps1" -InstallPath $InstallPath

# Step 11: Final Testing
Write-Host "Step 11: Running Final Tests..." -ForegroundColor Green

# Test application startup
Set-Location $InstallPath
$testResult = & node -e "console.log('Node.js is working')"
if ($testResult -eq "Node.js is working") {
    Write-Host "✅ Node.js test passed" -ForegroundColor Green
} else {
    Write-Host "❌ Node.js test failed" -ForegroundColor Red
}

# Test database connection
try {
    sqlcmd -S $SqlServer -U $SqlUser -P $SqlPassword -d timetracker -Q "SELECT 1" -h -1
    Write-Host "✅ Database connection test passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Database connection test failed" -ForegroundColor Red
}

# Start the application
pm2 start ecosystem.config.js --env production
Start-Sleep -Seconds 10

# Test HTTP endpoint
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000/health" -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Application health check passed" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Application health check failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "Installation Summary" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
Write-Host "Application URL: https://$Domain" -ForegroundColor White
Write-Host "Installation Path: $InstallPath" -ForegroundColor White
Write-Host "Database: $SqlServer\timetracker" -ForegroundColor White
Write-Host "Default Admin: admin@fmb.com / admin123" -ForegroundColor Yellow
Write-Host ""
Write-Host "Management Commands:" -ForegroundColor Cyan
Write-Host "- View logs: pm2 logs timetracker-pro" -ForegroundColor White
Write-Host "- Restart app: pm2 restart timetracker-pro" -ForegroundColor White
Write-Host "- Check status: pm2 status" -ForegroundColor White
Write-Host ""
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "Please change the default admin password on first login." -ForegroundColor Yellow
