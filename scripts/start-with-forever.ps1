
param(
    [string]$InstallPath = "C:\TimeTracker"
)

Set-Location $InstallPath

# Start with Forever
forever start -l "$InstallPath\logs\forever.log" -o "$InstallPath\logs\out.log" -e "$InstallPath\logs\err.log" --pidFile="$InstallPath\timetracker.pid" dist/index.js

Write-Host "TimeTracker started with Forever" -ForegroundColor Green
Write-Host "Commands:" -ForegroundColor White
Write-Host "  forever list" -ForegroundColor Gray
Write-Host "  forever restart $InstallPath/timetracker.pid" -ForegroundColor Gray
Write-Host "  forever stop $InstallPath/timetracker.pid" -ForegroundColor Gray
