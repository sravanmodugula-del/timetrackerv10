
# TimeTracker Production Setup Verification Script

param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$Domain = "timetracker.fmb.com"
)

$ErrorActionPreference = "Continue"

Write-Host "TimeTracker Production Setup Verification" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

$errors = 0
$warnings = 0

# Check installation path
Write-Host "`n1. Checking installation path..." -ForegroundColor Cyan
if (Test-Path $InstallPath) {
    Write-Host "✅ Installation path exists: $InstallPath" -ForegroundColor Green
} else {
    Write-Host "❌ Installation path not found: $InstallPath" -ForegroundColor Red
    $errors++
}

# Check required files
Write-Host "`n2. Checking required files..." -ForegroundColor Cyan
$requiredFiles = @(
    ".env",
    "ecosystem.config.js",
    "dist\index.js",
    "public\index.html",
    "node_modules\.prisma\client\index.js"
)

foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $InstallPath $file
    if (Test-Path $fullPath) {
        Write-Host "✅ $file" -ForegroundColor Green
    } else {
        Write-Host "❌ $file - MISSING" -ForegroundColor Red
        $errors++
    }
}

# Check environment variables
Write-Host "`n3. Checking environment configuration..." -ForegroundColor Cyan
$envPath = Join-Path $InstallPath ".env"
if (Test-Path $envPath) {
    $envContent = Get-Content $envPath
    
    if ($envContent -match "NODE_ENV=production") {
        Write-Host "✅ NODE_ENV set to production" -ForegroundColor Green
    } else {
        Write-Host "❌ NODE_ENV not set to production" -ForegroundColor Red
        $errors++
    }
    
    if ($envContent -match "DATABASE_URL.*HUB-SQL1TST-LIS") {
        Write-Host "✅ Database URL configured for HUB-SQL1TST-LIS" -ForegroundColor Green
    } else {
        Write-Host "❌ Database URL not configured correctly" -ForegroundColor Red
        $errors++
    }
    
    if ($envContent -match "SESSION_SECRET") {
        Write-Host "✅ SESSION_SECRET configured" -ForegroundColor Green
    } else {
        Write-Host "❌ SESSION_SECRET not configured" -ForegroundColor Red
        $errors++
    }
}

# Check Node.js
Write-Host "`n4. Checking Node.js..." -ForegroundColor Cyan
try {
    $nodeVersion = node --version
    Write-Host "✅ Node.js version: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js not installed or not in PATH" -ForegroundColor Red
    $errors++
}

# Check PM2
Write-Host "`n5. Checking PM2..." -ForegroundColor Cyan
try {
    $pm2Version = pm2 --version
    Write-Host "✅ PM2 version: $pm2Version" -ForegroundColor Green
} catch {
    Write-Host "❌ PM2 not installed" -ForegroundColor Red
    $errors++
}

# Check SQL Server connection
Write-Host "`n6. Testing SQL Server connection..." -ForegroundColor Cyan
try {
    $result = sqlcmd -S "HUB-SQL1TST-LIS" -d "timetracker" -U "timetracker" -P "iTT!`$Lo7gm`"i'JAg~5Y\" -Q "SELECT 1 as test" -h -1
    if ($result -eq "1") {
        Write-Host "✅ SQL Server connection successful" -ForegroundColor Green
    } else {
        Write-Host "⚠️ SQL Server connection test returned unexpected result" -ForegroundColor Yellow
        $warnings++
    }
} catch {
    Write-Host "❌ SQL Server connection failed" -ForegroundColor Red
    $errors++
}

# Check IIS
Write-Host "`n7. Checking IIS..." -ForegroundColor Cyan
$iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
if ($iisService -and $iisService.Status -eq "Running") {
    Write-Host "✅ IIS is running" -ForegroundColor Green
} else {
    Write-Host "❌ IIS is not running" -ForegroundColor Red
    $errors++
}

# Summary
Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "VERIFICATION SUMMARY" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

if ($errors -eq 0) {
    Write-Host "✅ PRODUCTION READY" -ForegroundColor Green
    if ($warnings -gt 0) {
        Write-Host "⚠️ $warnings warnings found - review recommended" -ForegroundColor Yellow
    }
    Write-Host "`n🚀 Your TimeTracker application is ready for production!" -ForegroundColor Green
    Write-Host "Access URL: https://$Domain" -ForegroundColor Cyan
} else {
    Write-Host "❌ NOT READY FOR PRODUCTION" -ForegroundColor Red
    Write-Host "   $errors critical errors found" -ForegroundColor Red
    Write-Host "   $warnings warnings found" -ForegroundColor Yellow
    Write-Host "`n🔧 Fix all errors before deploying to production" -ForegroundColor Yellow
    exit 1
}
