
param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$TaskName = "TimeTracker-Startup"
)

# Create startup script
@"
@echo off
cd /d $InstallPath
set NODE_ENV=production
set PORT=3000
set DATABASE_URL=sqlserver://HUB-SQL1TST-LIS:1433;database=timetracker;user=timetracker;password=iTT!`$Lo7gm`"i'JAg~5Y\;encrypt=true;trustServerCertificate=true
node dist/index.js >> logs/app.log 2>&1
"@ | Out-File -FilePath "$InstallPath\start-timetracker.bat" -Encoding ASCII

# Create scheduled task that runs at startup
$action = New-ScheduledTaskAction -Execute "$InstallPath\start-timetracker.bat"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal

Write-Host "Scheduled task '$TaskName' created successfully!" -ForegroundColor Green
