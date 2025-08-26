# TimeTracker Windows Installation Script with IISNode
# Run as Administrator in PowerShell

param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$Domain = "timetracker.fmb.com",
    [string]$SqlServer = "HUB-SQL1TST-LIS",
    [string]$SqlUser = "timetracker",
    [string]$SqlPassword = "iTT!`$Lo7gm`"i'JAg~5Y\"
)

$ErrorActionPreference = "Stop"

Write-Host "Starting TimeTracker Installation with IISNode..." -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green

# Verify Node.js is installed
Write-Host "Verifying Node.js installation..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version
    if ($nodeVersion -match "v20\.") {
        Write-Host "✅ Node.js 20.x detected: $nodeVersion" -ForegroundColor Green
    } elseif ($nodeVersion) {
        Write-Host "⚠️ Node.js detected but not version 20.x: $nodeVersion" -ForegroundColor Yellow
        Write-Host "TimeTracker is optimized for Node.js 20.x. Consider upgrading." -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Node.js not found. Please install Node.js 20.x first:" -ForegroundColor Red
    Write-Host "  Run: .\install-nodejs.ps1" -ForegroundColor Yellow
    exit 1
}

# Create installation directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Force -Path $InstallPath
    Write-Host "Created installation directory: $InstallPath" -ForegroundColor Yellow
}

Set-Location $InstallPath

# Create logs directory
New-Item -ItemType Directory -Force -Path "$InstallPath\Logs"

# Install IISNode
Write-Host "Installing IISNode..." -ForegroundColor Yellow
$iisNodeUrl = "https://github.com/Azure/iisnode/releases/download/v0.2.26/iisnode-full-v0.2.26-x64.msi"
$iisNodeMsi = "$env:TEMP\iisnode.msi"

try {
    Invoke-WebRequest -Uri $iisNodeUrl -OutFile $iisNodeMsi
    Start-Process msiexec.exe -ArgumentList "/i $iisNodeMsi /quiet" -Wait
    Write-Host "IISNode installed successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to install IISNode: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Install application dependencies
Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
npm install --production

# Install additional Windows-specific packages for IISNode
npm install mssql tedious

# Generate Prisma Client
Write-Host "Generating Prisma Client..." -ForegroundColor Yellow
npx prisma generate

# Build the application
Write-Host "Building application..." -ForegroundColor Yellow
npm run build

# Create environment file for IISNode
Write-Host "Creating environment configuration..." -ForegroundColor Yellow
$envContent = @"
NODE_ENV=production
PORT=3000
SQL_SERVER=$SqlServer
SQL_USER=$SqlUser
SQL_PASSWORD=$SqlPassword
SQL_DATABASE=timetracker
DATABASE_URL=sqlserver://${SqlServer}:1433;database=timetracker;user=${SqlUser};password=${SqlPassword};encrypt=true;trustServerCertificate=true
SESSION_SECRET=$(([System.Web.Security.Membership]::GeneratePassword(32, 8)))
APP_URL=https://$Domain
ALLOWED_ORIGINS=https://$Domain
TZ=America/Los_Angeles
WEBSITE_NODE_DEFAULT_VERSION=20.11.0
"@

$envContent | Out-File -FilePath "$InstallPath\.env" -Encoding utf8
Write-Host "Environment file created" -ForegroundColor Green

# Create iisnode.yml configuration file
Write-Host "Creating IISNode configuration..." -ForegroundColor Yellow
$iisNodeConfig = @"
node_env: production
loggingEnabled: true
logDirectory: C:\TimeTracker\Logs
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
"@

$iisNodeConfig | Out-File -FilePath "$InstallPath\iisnode.yml" -Encoding utf8

# Set proper file permissions for IIS
Write-Host "Configuring file permissions..." -ForegroundColor Yellow
$acl = Get-Acl $InstallPath

# Give IIS_IUSRS read and execute permissions
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)

# Give IUSR read permissions
$accessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("IUSR", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule2)

# Give Administrators full control
$accessRule3 = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule3)

Set-Acl $InstallPath $acl

# Set special permissions for logs directory
$logsAcl = Get-Acl "$InstallPath\Logs"
$logsAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$logsAcl.SetAccessRule($logsAccessRule)
Set-Acl "$InstallPath\Logs" $logsAcl

Write-Host "File permissions configured for IIS" -ForegroundColor Green

# Create IIS application pool
Write-Host "Creating IIS Application Pool..." -ForegroundColor Yellow
Import-Module WebAdministration

$appPoolName = "TimeTrackerAppPool"
if (Get-IISAppPool -Name $appPoolName -ErrorAction SilentlyContinue) {
    Remove-IISAppPool -Name $appPoolName -Confirm:$false
}

New-IISAppPool -Name $appPoolName
Set-IISAppPool -Name $appPoolName -ProcessModel.identityType ApplicationPoolIdentity
Set-IISAppPool -Name $appPoolName -ProcessModel.loadUserProfile $true
Set-IISAppPool -Name $appPoolName -ProcessModel.setProfileEnvironment $true
Set-IISAppPool -Name $appPoolName -Recycling.periodicRestart.time "00:00:00"
Set-IISAppPool -Name $appPoolName -Failure.rapidFailProtection $false

Write-Host "IIS Application Pool created: $appPoolName" -ForegroundColor Green

# Create IIS Website
Write-Host "Creating IIS Website..." -ForegroundColor Yellow
$siteName = "TimeTracker"
if (Get-IISSite -Name $siteName -ErrorAction SilentlyContinue) {
    Remove-IISSite -Name $siteName -Confirm:$false
}

New-IISSite -Name $siteName -PhysicalPath $InstallPath -Port 80 -ApplicationPool $appPoolName
Start-IISSite -Name $siteName

# Application will be managed by IISNode through IIS
Write-Host "Application configured for IISNode management..." -ForegroundColor Yellow

Write-Host "TimeTracker installation with IISNode completed!" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Configure SSL certificate for HTTPS" -ForegroundColor White
Write-Host "2. Update DNS to point $Domain to this server" -ForegroundColor White
Write-Host "3. Test the application at http://$Domain" -ForegroundColor White
Write-Host "4. Configure SAML authentication if needed" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "Application files: $InstallPath" -ForegroundColor Gray
Write-Host "Application logs: $InstallPath\Logs" -ForegroundColor Gray
Write-Host "IIS Manager: inetmgr.exe" -ForegroundColor Gray