param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$SiteName = "TimeTracker",
    [string]$AppPoolName = "TimeTrackerAppPool",
    [switch]$SkipBackup = $false
)

$ErrorActionPreference = "Stop"

Write-Host "Starting TimeTracker Production Deployment with IISNode..." -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green

# Import required modules
Import-Module WebAdministration

# Create backup if not skipped
if (!$SkipBackup) {
    Write-Host "Creating backup..." -ForegroundColor Yellow
    $BackupPath = "C:\TimeTracker\Backups\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    New-Item -ItemType Directory -Force -Path $BackupPath

    # Backup application files
    Copy-Item -Path "$InstallPath\*" -Destination $BackupPath -Recurse -Exclude @("Backups", "Logs", "node_modules")
    Write-Host "Backup created at: $BackupPath" -ForegroundColor Green
}

# Stop IIS site and app pool
Write-Host "Stopping IIS services..." -ForegroundColor Yellow
try {
    Stop-IISSite -Name $SiteName -ErrorAction SilentlyContinue
    Stop-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
    Write-Host "IIS services stopped" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not stop IIS services: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Wait for processes to fully stop
Start-Sleep -Seconds 5

# Set working directory
Set-Location $InstallPath

# Clean up old build artifacts
Write-Host "Cleaning up old build artifacts..." -ForegroundColor Yellow
if (Test-Path "dist") {
    Remove-Item -Path "dist" -Recurse -Force
}

# Install/update dependencies
Write-Host "Installing production dependencies..." -ForegroundColor Yellow
npm ci --only=production

# Generate Prisma client
Write-Host "Generating Prisma client..." -ForegroundColor Yellow
npx prisma generate

# Build the application
Write-Host "Building application..." -ForegroundColor Yellow
npm run build

# Run database migrations
Write-Host "Running database migrations..." -ForegroundColor Yellow
try {
    npx prisma db push --force-reset
    Write-Host "Database migrations completed" -ForegroundColor Green
} catch {
    Write-Host "Warning: Database migration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "You may need to run migrations manually" -ForegroundColor Yellow
}

# Verify build
Write-Host "Verifying build..." -ForegroundColor Yellow
if (Test-Path "dist\index.js") {
    Write-Host "Build verification successful" -ForegroundColor Green
} else {
    Write-Host "ERROR: Build verification failed - dist/index.js not found" -ForegroundColor Red
    exit 1
}

# Update IISNode configuration
Write-Host "Updating IISNode configuration..." -ForegroundColor Yellow

# Ensure web.config is properly configured
$webConfigPath = "$InstallPath\web.config"
if (!(Test-Path $webConfigPath)) {
    Write-Host "ERROR: web.config not found. IISNode requires web.config." -ForegroundColor Red
    exit 1
}

# Ensure iisnode.yml exists with production settings
$iisNodeConfig = @"
node_env: production
loggingEnabled: true
logDirectory: $InstallPath\Logs
nodeProcessCountPerApplication: 2
maxConcurrentRequestsPerProcess: 1024
maxNamedPipeConnectionRetry: 100
namedPipeConnectionRetryDelay: 250
asyncCompletionThreadCount: 8
initialRequestBufferSize: 4096
maxRequestBufferSize: 65536
watchedFiles: web.config;*.js;dist\*.js
debuggingEnabled: false
debugHeaderEnabled: false
gracefulShutdownTimeout: 60000
enableXFF: true
promoteServerVars: LOGON_USER,AUTH_USER,AUTH_TYPE
"@

$iisNodeConfig | Out-File -FilePath "$InstallPath\iisnode.yml" -Encoding utf8

# Set proper file permissions
Write-Host "Setting file permissions..." -ForegroundColor Yellow
$acl = Get-Acl $InstallPath

# Ensure IIS_IUSRS has proper permissions
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)

# Ensure logs directory has write permissions
$logsPath = "$InstallPath\Logs"
if (!(Test-Path $logsPath)) {
    New-Item -ItemType Directory -Force -Path $logsPath
}

$logsAcl = Get-Acl $logsPath
$logsAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$logsAcl.SetAccessRule($logsAccessRule)
Set-Acl $logsPath $logsAcl

Set-Acl $InstallPath $acl
Write-Host "File permissions updated" -ForegroundColor Green

# Recycle application pool to clear any cached modules
Write-Host "Recycling application pool..." -ForegroundColor Yellow
try {
    Restart-WebAppPool -Name $AppPoolName
    Write-Host "Application pool recycled" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not recycle application pool: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Start IIS services
Write-Host "Starting IIS services..." -ForegroundColor Yellow
try {
    Start-WebAppPool -Name $AppPoolName
    Start-IISSite -Name $SiteName

    # Wait for startup
    Start-Sleep -Seconds 10

    $appPoolState = (Get-IISAppPool -Name $AppPoolName).State
    $siteState = (Get-IISSite -Name $SiteName).State

    Write-Host "Application Pool: $AppPoolName ($appPoolState)" -ForegroundColor White
    Write-Host "Website: $SiteName ($siteState)" -ForegroundColor White

    if ($appPoolState -eq "Started" -and $siteState -eq "Started") {
        Write-Host "IIS services started successfully" -ForegroundColor Green
    } else {
        Write-Host "WARNING: IIS services may not have started properly" -ForegroundColor Yellow
    }
} catch {
    Write-Host "ERROR: Could not start IIS services: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test the application
Write-Host "Testing application..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost/" -TimeoutSec 30 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "Application test successful (HTTP 200)" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Application test returned HTTP $($response.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "WARNING: Could not test application: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Check IIS logs and application logs for details" -ForegroundColor Yellow
}

# Display post-deployment information
Write-Host "" -ForegroundColor White
Write-Host "TimeTracker deployment completed successfully!" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "Application Status:" -ForegroundColor White
Write-Host "  Install Path: $InstallPath" -ForegroundColor Gray
Write-Host "  IIS Site: $SiteName" -ForegroundColor Gray
Write-Host "  App Pool: $AppPoolName" -ForegroundColor Gray
Write-Host "  Logs: $InstallPath\Logs" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Management Commands:" -ForegroundColor White
Write-Host "  .\manage-timetracker.ps1 status" -ForegroundColor Gray
Write-Host "  inetmgr.exe (IIS Manager)" -ForegroundColor Gray
Write-Host "  eventvwr.msc (Event Viewer)" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Test the application in a browser" -ForegroundColor White
Write-Host "2. Configure SSL certificate if needed" -ForegroundColor White
Write-Host "3. Update DNS if deploying to production domain" -ForegroundColor White
Write-Host "4. Monitor application logs for any issues" -ForegroundColor White