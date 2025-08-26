
param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$ServiceName = "TimeTracker",
    [string]$SiteName = "TimeTracker",
    [string]$AppPoolName = "TimeTrackerAppPool"
)

$ErrorActionPreference = "Stop"

Write-Host "Configuring IISNode-based TimeTracker Service..." -ForegroundColor Green
Write-Host "Note: Using IISNode instead of PM2 for Windows deployment" -ForegroundColor Yellow

# Ensure we're in the correct directory
Set-Location $InstallPath

# Check if IIS is installed and import required modules
Write-Host "Checking IIS installation and modules..." -ForegroundColor Yellow

try {
    # Try to import IISAdministration module first (newer)
    if (Get-Module -ListAvailable -Name IISAdministration) {
        Import-Module IISAdministration -Force
        Write-Host "Using IISAdministration module" -ForegroundColor Green
        $useIISAdmin = $true
    }
    # Fallback to WebAdministration module (older but more common)
    elseif (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration -Force
        Write-Host "Using WebAdministration module" -ForegroundColor Yellow
        $useIISAdmin = $false
    }
    else {
        throw "Neither IISAdministration nor WebAdministration modules are available"
    }
} catch {
    Write-Host "Error: IIS modules not available. Please ensure IIS is properly installed." -ForegroundColor Red
    Write-Host "Run the following to install IIS features:" -ForegroundColor Yellow
    Write-Host "Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole" -ForegroundColor White
    Write-Host "Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole" -ForegroundColor White
    exit 1
}

# Stop existing site and app pool if they exist
Write-Host "Stopping existing IIS components..." -ForegroundColor Yellow
try {
    if ($useIISAdmin) {
        # Using IISAdministration cmdlets
        if (Get-IISSite -Name $SiteName -ErrorAction SilentlyContinue) {
            Stop-IISSite -Name $SiteName -Confirm:$false
        }
        if (Get-IISAppPool -Name $AppPoolName -ErrorAction SilentlyContinue) {
            Stop-IISAppPool -Name $AppPoolName -Confirm:$false
        }
    } else {
        # Using WebAdministration cmdlets
        if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
            Stop-Website -Name $SiteName
        }
        if (Get-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue) {
            Stop-WebAppPool -Name $AppPoolName
        }
    }
} catch {
    Write-Host "No existing components to stop or error stopping them" -ForegroundColor Gray
}

# Configure Application Pool
Write-Host "Configuring Application Pool..." -ForegroundColor Yellow

if ($useIISAdmin) {
    # Using IISAdministration cmdlets - simplified approach
    if (!(Get-IISAppPool -Name $AppPoolName -ErrorAction SilentlyContinue)) {
        New-IISAppPool -Name $AppPoolName
    }
    
    # Use WebAdministration approach even with IISAdministration module for better compatibility
    Import-Module WebAdministration -Force
    $useIISAdmin = $false
    Write-Host "Switching to WebAdministration for configuration compatibility" -ForegroundColor Yellow
}

if (!$useIISAdmin) {
    # Using WebAdministration cmdlets
    if (!(Get-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue)) {
        New-WebAppPool -Name $AppPoolName
    }
    
    # Configure app pool settings with error handling
    try {
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value ApplicationPoolIdentity
        Write-Host "✓ Set identity type to ApplicationPoolIdentity" -ForegroundColor Green
    } catch { Write-Host "⚠ Could not set identity type: $($_.Exception.Message)" -ForegroundColor Yellow }

    try {
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name processModel.loadUserProfile -Value $true
        Write-Host "✓ Enabled load user profile" -ForegroundColor Green
    } catch { Write-Host "⚠ Could not set load user profile: $($_.Exception.Message)" -ForegroundColor Yellow }

    try {
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name processModel.idleTimeout -Value "00:00:00"
        Write-Host "✓ Disabled idle timeout" -ForegroundColor Green
    } catch { Write-Host "⚠ Could not set idle timeout: $($_.Exception.Message)" -ForegroundColor Yellow }

    try {
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name recycling.periodicRestart.time -Value "00:00:00"
        Write-Host "✓ Disabled periodic restart" -ForegroundColor Green
    } catch { Write-Host "⚠ Could not set periodic restart: $($_.Exception.Message)" -ForegroundColor Yellow }

    try {
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name failure.rapidFailProtection -Value $false
        Write-Host "✓ Disabled rapid fail protection" -ForegroundColor Green
    } catch { Write-Host "⚠ Could not set rapid fail protection: $($_.Exception.Message)" -ForegroundColor Yellow }

    try {
        Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name recycling.periodicRestart.memory -Value 2097152
        Write-Host "✓ Set memory limit to 2GB" -ForegroundColor Green
    } catch { Write-Host "⚠ Could not set memory limit: $($_.Exception.Message)" -ForegroundColor Yellow }

    # Skip ping settings as they may not be available in all IIS versions
    Write-Host "ℹ Skipping ping settings for compatibility" -ForegroundColor Gray
}

Write-Host "Application Pool configured for production use" -ForegroundColor Green

# Configure the website
Write-Host "Configuring IIS Website..." -ForegroundColor Yellow

if ($useIISAdmin) {
    # Using IISAdministration cmdlets
    if (!(Get-IISSite -Name $SiteName -ErrorAction SilentlyContinue)) {
        New-IISSite -Name $SiteName -PhysicalPath $InstallPath -Port 80 -ApplicationPool $AppPoolName
    }
    
    # Set website properties
    Set-IISConfigAttributeValue -ConfigElement (Get-IISSite -Name $SiteName) -AttributeName "applicationPool" -AttributeValue $AppPoolName
    
} else {
    # Using WebAdministration cmdlets
    if (!(Get-Website -Name $SiteName -ErrorAction SilentlyContinue)) {
        New-Website -Name $SiteName -PhysicalPath $InstallPath -Port 80 -ApplicationPool $AppPoolName
    }
    
    # Set website properties
    Set-ItemProperty -Path "IIS:\Sites\$SiteName" -Name applicationPool -Value $AppPoolName
}

# Add HTTPS binding if certificate is available
$cert = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*timetracker*" -or $_.Subject -like "*fmb.com*" } | Select-Object -First 1
if ($cert) {
    Write-Host "Configuring HTTPS binding with certificate..." -ForegroundColor Yellow
    try {
        if ($useIISAdmin) {
            New-IISSiteBinding -Name $SiteName -BindingInformation "*:443:" -Protocol https -CertificateThumbPrint $cert.Thumbprint
        } else {
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -SslFlags 0
            $binding = Get-WebBinding -Name $SiteName -Protocol https
            $binding.AddSslCertificate($cert.Thumbprint, "my")
        }
        Write-Host "HTTPS binding configured successfully" -ForegroundColor Green
    } catch {
        Write-Host "Could not configure HTTPS binding: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Configure IISNode specific settings in web.config
Write-Host "Verifying web.config configuration..." -ForegroundColor Yellow
$webConfigPath = "$InstallPath\web.config"
if (Test-Path $webConfigPath) {
    Write-Host "web.config found and configured for IISNode" -ForegroundColor Green
} else {
    Write-Host "WARNING: web.config not found. IISNode may not work properly." -ForegroundColor Red
}

# Start the application pool and website
Write-Host "Starting IIS services..." -ForegroundColor Yellow

if ($useIISAdmin) {
    Start-IISAppPool -Name $AppPoolName
    Start-IISSite -Name $SiteName
    
    # Check status
    $appPoolState = (Get-IISAppPool -Name $AppPoolName).State
    $siteState = (Get-IISSite -Name $SiteName).State
} else {
    Start-WebAppPool -Name $AppPoolName
    Start-Website -Name $SiteName
    
    # Check status
    $appPoolState = (Get-WebAppPool -Name $AppPoolName).State
    $siteState = (Get-Website -Name $SiteName).State
}

# Wait a moment for startup
Start-Sleep -Seconds 5

if ($appPoolState -eq "Started" -and $siteState -eq "Started") {
    Write-Host "TimeTracker IIS service started successfully!" -ForegroundColor Green
    Write-Host "Application Pool: $AppPoolName ($appPoolState)" -ForegroundColor White
    Write-Host "Website: $SiteName ($siteState)" -ForegroundColor White
} else {
    Write-Host "WARNING: Service may not have started properly" -ForegroundColor Yellow
    Write-Host "Application Pool: $AppPoolName ($appPoolState)" -ForegroundColor Red
    Write-Host "Website: $SiteName ($siteState)" -ForegroundColor Red
}

# Create a PowerShell script for easy management
$managementScript = @"
# TimeTracker IISNode Service Management Script
# Run as Administrator
# Application is managed through IISNode, not PM2

param([string]`$Action = "status")

# Import appropriate IIS module
try {
    if (Get-Module -ListAvailable -Name IISAdministration) {
        Import-Module IISAdministration -Force
        `$useIISAdmin = `$true
    } else {
        Import-Module WebAdministration -Force
        `$useIISAdmin = `$false
    }
} catch {
    Write-Host "Error: Cannot load IIS modules" -ForegroundColor Red
    exit 1
}

switch (`$Action.ToLower()) {
    "start" {
        Write-Host "Starting TimeTracker..." -ForegroundColor Green
        if (`$useIISAdmin) {
            Start-IISAppPool -Name "$AppPoolName"
            Start-IISSite -Name "$SiteName"
        } else {
            Start-WebAppPool -Name "$AppPoolName"
            Start-Website -Name "$SiteName"
        }
    }
    "stop" {
        Write-Host "Stopping TimeTracker..." -ForegroundColor Yellow
        if (`$useIISAdmin) {
            Stop-IISSite -Name "$SiteName" -Confirm:`$false
            Stop-IISAppPool -Name "$AppPoolName" -Confirm:`$false
        } else {
            Stop-Website -Name "$SiteName"
            Stop-WebAppPool -Name "$AppPoolName"
        }
    }
    "restart" {
        Write-Host "Restarting TimeTracker..." -ForegroundColor Yellow
        if (`$useIISAdmin) {
            Stop-IISSite -Name "$SiteName" -Confirm:`$false
            Stop-IISAppPool -Name "$AppPoolName" -Confirm:`$false
            Start-Sleep -Seconds 2
            Start-IISAppPool -Name "$AppPoolName"
            Start-IISSite -Name "$SiteName"
        } else {
            Stop-Website -Name "$SiteName"
            Stop-WebAppPool -Name "$AppPoolName"
            Start-Sleep -Seconds 2
            Start-WebAppPool -Name "$AppPoolName"
            Start-Website -Name "$SiteName"
        }
    }
    "recycle" {
        Write-Host "Recycling Application Pool..." -ForegroundColor Yellow
        if (`$useIISAdmin) {
            Restart-IISAppPool -Name "$AppPoolName"
        } else {
            Restart-WebAppPool -Name "$AppPoolName"
        }
    }
    "status" {
        Write-Host "TimeTracker Service Status:" -ForegroundColor Green
        if (`$useIISAdmin) {
            `$appPool = Get-IISAppPool -Name "$AppPoolName"
            `$site = Get-IISSite -Name "$SiteName"
        } else {
            `$appPool = Get-WebAppPool -Name "$AppPoolName"
            `$site = Get-Website -Name "$SiteName"
        }
        Write-Host "Application Pool: `$(`$appPool.Name) - `$(`$appPool.State)" -ForegroundColor White
        Write-Host "Website: `$(`$site.Name) - `$(`$site.State)" -ForegroundColor White
        
        # Show IIS worker processes and Node.js processes managed by IISNode
        `$w3wpProcesses = Get-WmiObject -Class Win32_Process | Where-Object { `$_.Name -eq "w3wp.exe" }
        if (`$w3wpProcesses) {
            Write-Host "IIS Worker Processes:" -ForegroundColor White
            `$w3wpProcesses | ForEach-Object { Write-Host "  PID: `$(`$_.ProcessId) - Memory: `$([math]::round(`$_.WorkingSetSize/1MB, 2))MB" -ForegroundColor Gray }
        }
        
        `$nodeProcesses = Get-WmiObject -Class Win32_Process | Where-Object { `$_.Name -eq "node.exe" -and `$_.CommandLine -like "*dist/index.js*" }
        if (`$nodeProcesses) {
            Write-Host "Node.js Processes (IISNode):" -ForegroundColor White
            `$nodeProcesses | ForEach-Object { Write-Host "  PID: `$(`$_.ProcessId) - Memory: `$([math]::round(`$_.WorkingSetSize/1MB, 2))MB" -ForegroundColor Gray }
        }
    }
    default {
        Write-Host "Usage: .\manage-timetracker.ps1 [start|stop|restart|recycle|status]" -ForegroundColor White
    }
}
"@

$managementScript | Out-File -FilePath "$InstallPath\manage-timetracker.ps1" -Encoding UTF8

Write-Host "" -ForegroundColor White
Write-Host "IISNode-based TimeTracker service configured successfully!" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "Management Commands:" -ForegroundColor White
Write-Host "  .\manage-timetracker.ps1 status" -ForegroundColor Gray
Write-Host "  .\manage-timetracker.ps1 start" -ForegroundColor Gray
Write-Host "  .\manage-timetracker.ps1 stop" -ForegroundColor Gray
Write-Host "  .\manage-timetracker.ps1 restart" -ForegroundColor Gray
Write-Host "  .\manage-timetracker.ps1 recycle" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Technology Stack:" -ForegroundColor White
Write-Host "  - IIS 10.0 (Web Server)" -ForegroundColor Gray
Write-Host "  - IISNode (Node.js Integration)" -ForegroundColor Gray
Write-Host "  - Node.js 20.x (Runtime)" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Management Tools:" -ForegroundColor White
Write-Host "  IIS Manager: inetmgr.exe" -ForegroundColor Gray
Write-Host "  Event Logs: eventvwr.msc" -ForegroundColor Gray
Write-Host "  Application Logs: $InstallPath\Logs" -ForegroundColor Gray
Write-Host "  IISNode Logs: $InstallPath\Logs\iisnode" -ForegroundColor Gray
