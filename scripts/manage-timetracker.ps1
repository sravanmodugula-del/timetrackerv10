
# TimeTracker Pro Management Script
# Manages the TimeTracker application and services on Windows Server

param(
    [string]$Action = "status",
    [string]$InstallPath = "C:\TimeTracker",
    [string]$ServiceName = "TimeTracker",
    [string]$AppPoolName = "TimeTrackerAppPool",
    [string]$SiteName = "TimeTracker"
)

$ErrorActionPreference = "Stop"

function Show-Usage {
    Write-Host "TimeTracker Pro Management Script" -ForegroundColor Cyan
    Write-Host "Usage: .\manage-timetracker.ps1 [ACTION]" -ForegroundColor White
    Write-Host ""
    Write-Host "Available Actions:" -ForegroundColor Yellow
    Write-Host "  start     - Start all TimeTracker services"
    Write-Host "  stop      - Stop all TimeTracker services"
    Write-Host "  restart   - Restart all TimeTracker services"
    Write-Host "  status    - Show status of all services"
    Write-Host "  logs      - Show recent application logs"
    Write-Host "  health    - Check application health"
    Write-Host "  backup    - Create backup of application and database"
}

function Start-TimeTracker {
    Write-Host "Starting TimeTracker services..." -ForegroundColor Green
    
    try {
        # Ensure we're in the correct directory
        Set-Location $InstallPath
        
        # Step 1: Verify Prisma Client exists
        Write-Host "Checking Prisma Client..." -ForegroundColor Yellow
        if (!(Test-Path "node_modules\.prisma\client")) {
            Write-Host "⚠️ Prisma Client not found. Generating..." -ForegroundColor Yellow
            npx prisma generate
            if ($LASTEXITCODE -ne 0) {
                Write-Host "❌ Failed to generate Prisma Client" -ForegroundColor Red
                return
            }
        }
        
        # Step 2: Test database connection
        Write-Host "Testing database connection..." -ForegroundColor Yellow
        try {
            node -e "
                const { PrismaClient } = require('@prisma/client');
                const prisma = new PrismaClient();
                prisma.\$connect()
                    .then(() => { console.log('Database OK'); process.exit(0); })
                    .catch(err => { console.log('Database Error:', err.message); process.exit(1); });
            "
            if ($LASTEXITCODE -ne 0) {
                Write-Host "❌ Database connection failed" -ForegroundColor Red
                Write-Host "Check your DATABASE_URL in .env file" -ForegroundColor Yellow
                return
            }
            Write-Host "✅ Database connection verified" -ForegroundColor Green
        } catch {
            Write-Host "❌ Database test failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Step 3: Build application if needed
        Write-Host "Checking application build..." -ForegroundColor Yellow
        if (!(Test-Path "dist\index.js")) {
            Write-Host "⚠️ Application not built. Building..." -ForegroundColor Yellow
            npm run build
            if ($LASTEXITCODE -ne 0) {
                Write-Host "❌ Build failed" -ForegroundColor Red
                return
            }
        }
        
        # Step 4: Kill any existing Node processes on port 3000
        Write-Host "Checking for existing processes..." -ForegroundColor Yellow
        $existingProcesses = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
        if ($existingProcesses) {
            $pids = $existingProcesses | ForEach-Object { (Get-Process -Id $_.OwningProcess).Id } | Sort-Object -Unique
            foreach ($pid in $pids) {
                Write-Host "Stopping existing process PID: $pid" -ForegroundColor Yellow
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 2
        }
        
        # Step 5: Start PM2 process (preferred method)
        if (Get-Command pm2 -ErrorAction SilentlyContinue) {
            Write-Host "Starting with PM2..." -ForegroundColor Yellow
            
            # Stop any existing PM2 processes
            pm2 stop timetracker 2>$null
            pm2 delete timetracker 2>$null
            
            # Start with PM2
            pm2 start ecosystem.config.js --env production
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ PM2 application started" -ForegroundColor Green
                
                # Wait for application to start
                Start-Sleep -Seconds 5
                
                # Test if application is responding
                try {
                    $response = Invoke-WebRequest -Uri "http://localhost:3000/api/health" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
                    if ($response.StatusCode -eq 200) {
                        Write-Host "✅ Application is responding on port 3000" -ForegroundColor Green
                    } else {
                        Write-Host "⚠️ Application started but not responding properly" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "⚠️ Application may still be starting up..." -ForegroundColor Yellow
                }
            } else {
                Write-Host "❌ PM2 start failed" -ForegroundColor Red
                pm2 logs timetracker --lines 20
                return
            }
        }
        # Step 6: Start with Node directly as fallback
        else {
            Write-Host "PM2 not available, starting with Node.js directly..." -ForegroundColor Yellow
            
            # Start application in background
            $env:NODE_ENV = "production"
            Start-Process -FilePath "node" -ArgumentList "dist/index.js" -WorkingDirectory $InstallPath -WindowStyle Hidden
            
            Start-Sleep -Seconds 5
            Write-Host "✅ Node.js application started" -ForegroundColor Green
        }
        
        # Step 7: Start IIS components if they exist
        if (Get-Module -ListAvailable -Name WebAdministration) {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            
            # Start IIS Application Pool
            if (Get-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue) {
                Start-WebAppPool -Name $AppPoolName
                Write-Host "✅ IIS Application Pool '$AppPoolName' started" -ForegroundColor Green
            }
            
            # Start IIS Website
            if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
                Start-Website -Name $SiteName
                Write-Host "✅ IIS Website '$SiteName' started" -ForegroundColor Green
            }
        }
        
        # Step 8: Start Windows Service if it exists
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Start-Service -Name $ServiceName
            Write-Host "✅ Windows Service '$ServiceName' started" -ForegroundColor Green
        }
        
        Write-Host "" -ForegroundColor White
        Write-Host "TimeTracker startup completed!" -ForegroundColor Green
        Write-Host "Check status with: .\manage-timetracker.ps1 status" -ForegroundColor Gray
        Write-Host "View logs with: .\manage-timetracker.ps1 logs" -ForegroundColor Gray
        
    }
    catch {
        Write-Host "❌ Error starting TimeTracker: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Run '.\manage-timetracker.ps1 logs' for more details" -ForegroundColor Yellow
        exit 1
    }
}

function Stop-TimeTracker {
    Write-Host "Stopping TimeTracker services..." -ForegroundColor Yellow
    
    try {
        # Stop PM2 process
        if (Get-Command pm2 -ErrorAction SilentlyContinue) {
            pm2 stop timetracker 2>$null
            Write-Host "✅ PM2 application stopped" -ForegroundColor Yellow
        }
        
        # Stop Windows Service
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force
            Write-Host "✅ Windows Service '$ServiceName' stopped" -ForegroundColor Yellow
        }
        
        # Stop IIS Website
        if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
            Stop-Website -Name $SiteName
            Write-Host "✅ Website '$SiteName' stopped" -ForegroundColor Yellow
        }
        
        # Stop IIS Application Pool
        if (Get-IISAppPool -Name $AppPoolName -ErrorAction SilentlyContinue) {
            Stop-WebAppPool -Name $AppPoolName
            Write-Host "✅ Application Pool '$AppPoolName' stopped" -ForegroundColor Yellow
        }
        
        Write-Host "TimeTracker stopped successfully!" -ForegroundColor Yellow
    }
    catch {
        Write-Host "❌ Error stopping TimeTracker: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

function Restart-TimeTracker {
    Write-Host "Restarting TimeTracker..." -ForegroundColor Blue
    Stop-TimeTracker
    Start-Sleep -Seconds 5
    Start-TimeTracker
}

function Get-TimeTrackerStatus {
    Write-Host "TimeTracker Service Status" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    
    # Check critical prerequisites
    Write-Host "`nPrerequisites:" -ForegroundColor Yellow
    
    # Check if in correct directory
    if (Test-Path "$InstallPath\package.json") {
        Write-Host "✅ Installation directory: $InstallPath" -ForegroundColor Green
    } else {
        Write-Host "❌ Installation directory: Not found at $InstallPath" -ForegroundColor Red
    }
    
    # Check Prisma Client
    if (Test-Path "$InstallPath\node_modules\.prisma\client") {
        Write-Host "✅ Prisma Client: Generated" -ForegroundColor Green
    } else {
        Write-Host "❌ Prisma Client: Not generated (run: npx prisma generate)" -ForegroundColor Red
    }
    
    # Check build
    if (Test-Path "$InstallPath\dist\index.js") {
        Write-Host "✅ Application Build: Complete" -ForegroundColor Green
    } else {
        Write-Host "❌ Application Build: Missing (run: npm run build)" -ForegroundColor Red
    }
    
    # Check environment file
    if (Test-Path "$InstallPath\.env") {
        Write-Host "✅ Environment File: Found" -ForegroundColor Green
    } else {
        Write-Host "❌ Environment File: Missing" -ForegroundColor Red
    }
    
    Write-Host "`nPort Status:" -ForegroundColor Yellow
    
    # Check port 3000
    $port3000 = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
    if ($port3000) {
        $process = Get-Process -Id $port3000.OwningProcess -ErrorAction SilentlyContinue
        Write-Host "✅ Port 3000: In use by $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Green
    } else {
        Write-Host "❌ Port 3000: Not listening" -ForegroundColor Red
    }
    
    # Check port 80
    $port80 = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
    if ($port80) {
        Write-Host "✅ Port 80: In use (IIS)" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Port 80: Not listening" -ForegroundColor Yellow
    }
    
    Write-Host "`nApplication Status:" -ForegroundColor Yellow
    
    # Check PM2 Process
    if (Get-Command pm2 -ErrorAction SilentlyContinue) {
        try {
            $pm2List = pm2 jlist | ConvertFrom-Json
            $pm2Status = $pm2List | Where-Object { $_.name -eq 'timetracker' }
            if ($pm2Status) {
                $status = if ($pm2Status.pm2_env.status -eq 'online') { "✅ Running" } else { "❌ Stopped/Error" }
                $memory = [math]::Round($pm2Status.monit.memory / 1MB, 1)
                $cpu = $pm2Status.monit.cpu
                Write-Host "PM2 Process (timetracker): $status (Memory: ${memory}MB, CPU: ${cpu}%)" -ForegroundColor White
                
                if ($pm2Status.pm2_env.status -ne 'online') {
                    Write-Host "  Last restart: $($pm2Status.pm2_env.pm_uptime)" -ForegroundColor Gray
                    Write-Host "  Restart count: $($pm2Status.pm2_env.restart_time)" -ForegroundColor Gray
                }
            } else {
                Write-Host "PM2 Process (timetracker): ❌ Not Found" -ForegroundColor Red
            }
        } catch {
            Write-Host "PM2 Process: ❌ Error checking status" -ForegroundColor Red
        }
    } else {
        Write-Host "PM2: ❌ Not installed" -ForegroundColor Red
    }
    
    # Check Node processes
    $nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue
    if ($nodeProcesses) {
        Write-Host "Node.js Processes: ✅ $($nodeProcesses.Count) running" -ForegroundColor Green
        foreach ($proc in $nodeProcesses) {
            $memory = [math]::Round($proc.WorkingSet / 1MB, 1)
            Write-Host "  PID: $($proc.Id) - Memory: ${memory}MB" -ForegroundColor Gray
        }
    } else {
        Write-Host "Node.js Processes: ❌ None running" -ForegroundColor Red
    }
    
    Write-Host "`nIIS Status:" -ForegroundColor Yellow
    
    # Check IIS components
    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        # Check IIS Application Pool
        $appPool = Get-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
        if ($appPool) {
            $status = if ($appPool.State -eq 'Started') { "✅ Running" } else { "❌ Stopped" }
            Write-Host "Application Pool ($AppPoolName): $status" -ForegroundColor White
        } else {
            Write-Host "Application Pool ($AppPoolName): ❌ Not Found" -ForegroundColor Red
        }
        
        # Check IIS Website
        $website = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
        if ($website) {
            $status = if ($website.State -eq 'Started') { "✅ Running" } else { "❌ Stopped" }
            Write-Host "IIS Website ($SiteName): $status" -ForegroundColor White
        } else {
            Write-Host "IIS Website ($SiteName): ❌ Not Found" -ForegroundColor Red
        }
    } else {
        Write-Host "IIS: ⚠️ WebAdministration module not available" -ForegroundColor Yellow
    }
    
    # Check Windows Service
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        $status = if ($service.Status -eq 'Running') { "✅ Running" } else { "❌ Stopped" }
        Write-Host "Windows Service ($ServiceName): $status" -ForegroundColor White
    } else {
        Write-Host "Windows Service ($ServiceName): ❌ Not Found" -ForegroundColor Red
    }
    
    Write-Host "`nConnectivity Test:" -ForegroundColor Yellow
    
    # Test local HTTP endpoint
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000/api/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "✅ HTTP Health Check: OK (Status: $($response.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "❌ HTTP Health Check: Failed - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    
    if (!(Test-Path "$InstallPath\node_modules\.prisma\client")) {
        Write-Host "  1. Generate Prisma Client: npx prisma generate" -ForegroundColor White
    }
    if (!(Test-Path "$InstallPath\dist\index.js")) {
        Write-Host "  2. Build application: npm run build" -ForegroundColor White
    }
    if (!$port3000) {
        Write-Host "  3. Start application: .\manage-timetracker.ps1 start" -ForegroundColor White
    }
    
    Write-Host "" -ForegroundColor White
}

function Show-Logs {
    Write-Host "Recent TimeTracker Logs" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    
    # PM2 logs
    if (Get-Command pm2 -ErrorAction SilentlyContinue) {
        Write-Host "`nPM2 Logs (last 20 lines):" -ForegroundColor Yellow
        pm2 logs timetracker --lines 20 --nostream
    }
    
    # Windows Event Log
    $events = Get-EventLog -LogName Application -Source "TimeTracker" -Newest 10 -ErrorAction SilentlyContinue
    if ($events) {
        Write-Host "`nWindows Event Log (last 10 entries):" -ForegroundColor Yellow
        $events | Format-Table TimeGenerated, EntryType, Message -Wrap
    }
    
    # Application log files
    $logFiles = @(
        "$InstallPath\logs\app.log",
        "$InstallPath\logs\error.log",
        "C:\inetpub\logs\LogFiles\W3SVC1\*.log"
    )
    
    foreach ($logPattern in $logFiles) {
        $files = Get-ChildItem -Path $logPattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($files) {
            Write-Host "`nLog file: $($files.FullName)" -ForegroundColor Yellow
            Get-Content $files.FullName -Tail 10
        }
    }
}

function Test-Health {
    Write-Host "TimeTracker Health Check" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    
    # Test local endpoint
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000/health" -UseBasicParsing -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Local HTTP endpoint: Healthy" -ForegroundColor Green
        } else {
            Write-Host "⚠ Local HTTP endpoint: Responding but status $($response.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ Local HTTP endpoint: Not responding" -ForegroundColor Red
    }
    
    # Test HTTPS endpoint (if configured)
    try {
        $response = Invoke-WebRequest -Uri "https://timetracker.fmb.com/health" -UseBasicParsing -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ HTTPS endpoint: Healthy" -ForegroundColor Green
        } else {
            Write-Host "⚠ HTTPS endpoint: Responding but status $($response.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ HTTPS endpoint: Not responding" -ForegroundColor Red
    }
    
    # Test database connection
    try {
        Set-Location $InstallPath
        $dbTest = node -e "
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
prisma.\$connect().then(() => {
  console.log('Database connection: OK');
  return prisma.\$disconnect();
}).catch(err => {
  console.log('Database connection: FAILED - ' + err.message);
});
"
        if ($dbTest -like "*OK*") {
            Write-Host "✅ Database connection: Healthy" -ForegroundColor Green
        } else {
            Write-Host "❌ Database connection: Failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Database connection: Test failed" -ForegroundColor Red
    }
}

function Backup-TimeTracker {
    Write-Host "Creating TimeTracker Backup..." -ForegroundColor Cyan
    
    $BackupDate = Get-Date -Format "yyyyMMdd_HHmmss"
    $BackupPath = "C:\Backups\TimeTracker\$BackupDate"
    
    try {
        # Create backup directory
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        
        # Backup database
        Write-Host "Backing up database..." -ForegroundColor Yellow
        sqlcmd -S "localhost" -E -Q "BACKUP DATABASE timetracker TO DISK = '$BackupPath\timetracker.bak' WITH COMPRESSION"
        
        # Backup application files
        Write-Host "Backing up application files..." -ForegroundColor Yellow
        Compress-Archive -Path $InstallPath -DestinationPath "$BackupPath\application.zip" -Force
        
        # Backup IIS configuration
        Write-Host "Backing up IIS configuration..." -ForegroundColor Yellow
        & "$env:windir\system32\inetsrv\appcmd.exe" list config > "$BackupPath\iis-config.txt"
        
        Write-Host "✅ Backup completed: $BackupPath" -ForegroundColor Green
    } catch {
        Write-Host "❌ Backup failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Main script logic
switch ($Action.ToLower()) {
    "start" { Start-TimeTracker }
    "stop" { Stop-TimeTracker }
    "restart" { Restart-TimeTracker }
    "status" { Get-TimeTrackerStatus }
    "logs" { Show-Logs }
    "health" { Test-Health }
    "backup" { Backup-TimeTracker }
    "help" { Show-Usage }
    default {
        Write-Host "Unknown action: $Action" -ForegroundColor Red
        Show-Usage
        exit 1
    }
}
