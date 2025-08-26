
# Setup Windows Event Logging for TimeTracker Pro
# Run as Administrator

param(
    [string]$LogName = "TimeTrackerPro",
    [string]$InstallPath = "C:\TimeTrackerPro"
)

Write-Host "Setting up Windows Event Logging..." -ForegroundColor Green

# Create custom event log
if (!(Get-EventLog -LogName $LogName -ErrorAction SilentlyContinue)) {
    New-EventLog -LogName $LogName -Source "TimeTrackerPro"
    Write-Host "Created event log: $LogName" -ForegroundColor Green
}

# Create log rotation script
$logRotationScript = @"
# Log Rotation Script for TimeTracker Pro
param([int]$DaysToKeep = 30)

$LogPath = "$InstallPath\logs"
$CutoffDate = (Get-Date).AddDays(-$DaysToKeep)

Get-ChildItem -Path $LogPath -Filter "*.log" | Where-Object {
    $_.LastWriteTime -lt $CutoffDate
} | Remove-Item -Force

Write-EventLog -LogName "TimeTrackerPro" -Source "TimeTrackerPro" -EventID 1001 -EntryType Information -Message "Log rotation completed. Removed logs older than $DaysToKeep days."
"@

$logRotationScript | Out-File -FilePath "$InstallPath\scripts\rotate-logs.ps1" -Encoding utf8

# Schedule log rotation task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$InstallPath\scripts\rotate-logs.ps1`""
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "TimeTrackerPro-LogRotation" -Action $action -Trigger $trigger -Principal $principal -Description "Rotate TimeTracker Pro log files"

Write-Host "Log rotation scheduled for 2:00 AM daily" -ForegroundColor Green

# Create performance monitoring script
$monitoringScript = @"
# Performance Monitoring for TimeTracker Pro
$ProcessName = "node"
$ServiceName = "TimeTrackerPro"

$process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Where-Object { $_.MainModule.FileName -like "*TimeTrackerPro*" }

if ($process) {
    $cpuUsage = $process.CPU
    $memoryUsage = $process.WorkingSet / 1MB
    
    if ($memoryUsage -gt 1024) {  # Alert if memory usage > 1GB
        Write-EventLog -LogName "TimeTrackerPro" -Source "TimeTrackerPro" -EventID 2001 -EntryType Warning -Message "High memory usage detected: $([math]::Round($memoryUsage, 2)) MB"
    }
    
    Write-EventLog -LogName "TimeTrackerPro" -Source "TimeTrackerPro" -EventID 1002 -EntryType Information -Message "Performance check: CPU: $cpuUsage, Memory: $([math]::Round($memoryUsage, 2)) MB"
} else {
    Write-EventLog -LogName "TimeTrackerPro" -Source "TimeTrackerPro" -EventID 3001 -EntryType Error -Message "TimeTracker Pro process not found"
}
"@

$monitoringScript | Out-File -FilePath "$InstallPath\scripts\monitor-performance.ps1" -Encoding utf8

Write-Host "Windows Event Logging configured successfully!" -ForegroundColor Green
