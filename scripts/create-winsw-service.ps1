
param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$ServiceName = "TimeTracker"
)

Write-Host "Creating TimeTracker service with WinSW..." -ForegroundColor Green

# Download WinSW if not present
$winswPath = "$InstallPath\winsw.exe"
if (!(Test-Path $winswPath)) {
    $winswUrl = "https://github.com/winsw/winsw/releases/download/v3.0.0-alpha.11/WinSW-x64.exe"
    Invoke-WebRequest -Uri $winswUrl -OutFile $winswPath
}

# Create service configuration XML
@"
<service>
  <id>$ServiceName</id>
  <name>$ServiceName</name>
  <description>TimeTracker Application Server</description>
  <executable>node</executable>
  <arguments>dist/index.js</arguments>
  <workingdirectory>$InstallPath</workingdirectory>
  <env name="NODE_ENV" value="production"/>
  <env name="PORT" value="3000"/>
  <env name="DATABASE_URL" value="sqlserver://HUB-SQL1TST-LIS:1433;database=timetracker;user=timetracker;password=iTT!`$Lo7gm`"i'JAg~5Y\;encrypt=true;trustServerCertificate=true"/>
  <logmode>rotate</logmode>
  <logpath>$InstallPath\logs</logpath>
  <startmode>Automatic</startmode>
  <stopparentprocessfirst>true</stopparentprocessfirst>
</service>
"@ | Out-File -FilePath "$InstallPath\$ServiceName.xml" -Encoding UTF8

# Install the service
& $winswPath install "$InstallPath\$ServiceName.xml"

Write-Host "WinSW service installed successfully!" -ForegroundColor Green
