
# Security Hardening for TimeTracker Pro Windows Deployment
# Run as Administrator

param(
    [string]$InstallPath = "C:\TimeTrackerPro",
    [string]$ServiceUser = "TimeTrackerService"
)

Write-Host "Applying security hardening measures..." -ForegroundColor Green

# Create dedicated service user
if (!(Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue)) {
    $securePassword = ConvertTo-SecureString -String ([System.Web.Security.Membership]::GeneratePassword(16, 4)) -AsPlainText -Force
    New-LocalUser -Name $ServiceUser -Password $securePassword -Description "TimeTracker Pro Service Account" -AccountNeverExpires -PasswordNeverExpires
    
    # Add to Log on as a service right
    $tempPath = "$env:TEMP\ntrights.exe"
    # Download ntrights.exe from Windows Resource Kit or use secedit
    
    Write-Host "Created service user: $ServiceUser" -ForegroundColor Green
}

# Configure file permissions
$acl = Get-Acl $InstallPath

# Remove inherited permissions
$acl.SetAccessRuleProtection($true, $false)

# Add specific permissions
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$serviceRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ServiceUser, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$iisRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")

$acl.SetAccessRule($adminRule)
$acl.SetAccessRule($serviceRule)
$acl.SetAccessRule($iisRule)

Set-Acl $InstallPath $acl

Write-Host "File permissions configured securely" -ForegroundColor Green

# Configure Windows Firewall
New-NetFirewallRule -DisplayName "TimeTracker Pro HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "TimeTracker Pro HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
New-NetFirewallRule -DisplayName "TimeTracker Pro App" -Direction Inbound -Protocol TCP -LocalPort 3000 -Action Allow

Write-Host "Windows Firewall rules configured" -ForegroundColor Green

# Disable unnecessary services (optional)
$servicesToDisable = @("Telnet", "RemoteRegistry", "SNMP")
foreach ($service in $servicesToDisable) {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Stop-Service -Name $service -Force
        Set-Service -Name $service -StartupType Disabled
        Write-Host "Disabled service: $service" -ForegroundColor Yellow
    }
}

# Configure audit policies
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable

Write-Host "Audit policies configured" -ForegroundColor Green

# Create backup script
$backupScript = @"
# Automated Backup Script for TimeTracker Pro
param(
    [string]$BackupPath = "C:\Backups\TimeTrackerPro"
)

$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFolder = "$BackupPath\$Date"

if (!(Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Force -Path $BackupPath
}

# Backup application files
Compress-Archive -Path "$InstallPath\*" -DestinationPath "$BackupFolder\Application_$Date.zip"

# Backup database
$sqlCmd = "sqlcmd -S localhost -E -Q `"BACKUP DATABASE TimeTrackerPro TO DISK = '$BackupFolder\Database_$Date.bak'`""
Invoke-Expression $sqlCmd

Write-EventLog -LogName "TimeTrackerPro" -Source "TimeTrackerPro" -EventID 1003 -EntryType Information -Message "Backup completed: $BackupFolder"

# Clean old backups (keep 7 days)
Get-ChildItem -Path $BackupPath -Directory | Where-Object {
    $_.CreationTime -lt (Get-Date).AddDays(-7)
} | Remove-Item -Recurse -Force
"@

$backupScript | Out-File -FilePath "$InstallPath\scripts\backup.ps1" -Encoding utf8

Write-Host "Security hardening completed!" -ForegroundColor Green
