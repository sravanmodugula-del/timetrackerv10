
param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$SiteName = "TimeTracker",
    [string]$AppPoolName = "TimeTrackerAppPool"
)

Write-Host "Configuring IISNode for TimeTracker..." -ForegroundColor Green

# Ensure IISNode is installed
$iisNodePath = "${env:ProgramFiles}\iisnode"
if (!(Test-Path $iisNodePath)) {
    Write-Host "Installing IISNode..." -ForegroundColor Yellow
    
    # Download and install IISNode
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
    
    Remove-Item $iisNodeMsi -Force -ErrorAction SilentlyContinue
}

# Import IIS module
Import-Module WebAdministration

# Create application pool if it doesn't exist
if (!(Get-IISAppPool -Name $AppPoolName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating application pool: $AppPoolName" -ForegroundColor Yellow
    New-IISAppPool -Name $AppPoolName
}

# Configure application pool for Node.js
Write-Host "Configuring application pool for Node.js..." -ForegroundColor Yellow
Set-IISAppPool -Name $AppPoolName -ProcessModel.identityType ApplicationPoolIdentity
Set-IISAppPool -Name $AppPoolName -ProcessModel.loadUserProfile $true
Set-IISAppPool -Name $AppPoolName -ProcessModel.setProfileEnvironment $true
Set-IISAppPool -Name $AppPoolName -ProcessModel.idleTimeout "00:00:00"
Set-IISAppPool -Name $AppPoolName -Recycling.periodicRestart.time "00:00:00"
Set-IISAppPool -Name $AppPoolName -Failure.rapidFailProtection $false

# Configure managed runtime version to "No Managed Code"
Set-IISAppPool -Name $AppPoolName -ManagedRuntimeVersion ""

# Create website if it doesn't exist
if (!(Get-IISSite -Name $SiteName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating website: $SiteName" -ForegroundColor Yellow
    New-IISSite -Name $SiteName -PhysicalPath $InstallPath -Port 80 -ApplicationPool $AppPoolName
}

# Ensure the website uses the correct application pool
Set-IISSite -Name $SiteName -ApplicationPool $AppPoolName

# Configure IISNode handler mapping
Write-Host "Configuring IISNode handler..." -ForegroundColor Yellow
$config = Get-IISConfiguration -SectionPath "system.webServer/handlers" -SiteName $SiteName

# Remove existing iisnode handler if it exists
$handlersCollection = Get-IISConfigCollection -ConfigElement $config
$existingHandler = Get-IISConfigCollectionElement -ConfigCollection $handlersCollection -ConfigAttribute @{"name"="iisnode"}
if ($existingHandler) {
    Remove-IISConfigCollectionElement -ConfigCollection $handlersCollection -ConfigElement $existingHandler
}

# Add IISNode handler
$newHandler = New-IISConfigCollectionElement -ConfigCollection $handlersCollection -ConfigAttribute @{"name"="iisnode"}
Set-IISConfigAttributeValue -ConfigElement $newHandler -AttributeName "path" -AttributeValue "dist/index.js"
Set-IISConfigAttributeValue -ConfigElement $newHandler -AttributeName "verb" -AttributeValue "*"
Set-IISConfigAttributeValue -ConfigElement $newHandler -AttributeName "modules" -AttributeValue "iisnode"

# Configure URL rewrite rules
Write-Host "Configuring URL rewrite rules..." -ForegroundColor Yellow

# Enable URL Rewrite module
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect -All -NoRestart

# Create web.config if it doesn't exist (it should exist from our earlier update)
$webConfigPath = "$InstallPath\web.config"
if (!(Test-Path $webConfigPath)) {
    Write-Host "Creating web.config..." -ForegroundColor Yellow
    
    $webConfigContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="iisnode" path="dist/index.js" verb="*" modules="iisnode" />
        </handlers>
        <rewrite>
            <rules>
                <rule name="NodeInspector" patternSyntax="ECMAScript" stopProcessing="true">
                    <match url="^dist/index.js\/debug[\/]?" />
                </rule>
                <rule name="StaticContent" stopProcessing="false">
                    <match url="^(css|js|images|fonts|assets)/.*" />
                    <action type="Rewrite" url="public/{R:0}" />
                </rule>
                <rule name="DynamicContent" stopProcessing="true">
                    <conditions>
                        <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="True" />
                    </conditions>
                    <action type="Rewrite" url="dist/index.js" />
                </rule>
            </rules>
        </rewrite>
        <iisnode 
            node_env="production"
            nodeProcessCountPerApplication="2"
            maxConcurrentRequestsPerProcess="1024"
            loggingEnabled="true"
            logDirectory="C:\TimeTracker\Logs"
            debuggingEnabled="false"
            gracefulShutdownTimeout="60000"
            enableXFF="true"
        />
        <security>
            <requestFiltering>
                <hiddenSegments>
                    <add segment="node_modules" />
                    <add segment=".env" />
                </hiddenSegments>
            </requestFiltering>
        </security>
        <httpErrors existingResponse="PassThrough" />
    </system.webServer>
</configuration>
'@
    
    $webConfigContent | Out-File -FilePath $webConfigPath -Encoding UTF8
}

# Set proper permissions for IISNode
Write-Host "Setting permissions for IISNode..." -ForegroundColor Yellow

# Get the application pool identity
$appPoolSid = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-82")).Translate([System.Security.Principal.NTAccount])
$appPoolIdentity = "IIS AppPool\$AppPoolName"

# Set permissions on the application directory
$acl = Get-Acl $InstallPath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($appPoolIdentity, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)

# Give IIS_IUSRS read and execute permissions
$iisUsersRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($iisUsersRule)

Set-Acl $InstallPath $acl

# Set special permissions for logs directory
$logsPath = "$InstallPath\Logs"
if (!(Test-Path $logsPath)) {
    New-Item -ItemType Directory -Force -Path $logsPath
}

$logsAcl = Get-Acl $logsPath
$logsAppPoolRule = New-Object System.Security.AccessControl.FileSystemAccessRule($appPoolIdentity, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$logsAcl.SetAccessRule($logsAppPoolRule)
$logsIisRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$logsAcl.SetAccessRule($logsIisRule)
Set-Acl $logsPath $logsAcl

# Create iisnode.yml configuration file
Write-Host "Creating iisnode.yml configuration..." -ForegroundColor Yellow
$iisNodeConfigPath = "$InstallPath\iisnode.yml"
if (!(Test-Path $iisNodeConfigPath)) {
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
    
    $iisNodeConfig | Out-File -FilePath $iisNodeConfigPath -Encoding UTF8
}

# Restart application pool to apply changes
Write-Host "Restarting application pool..." -ForegroundColor Yellow
Restart-WebAppPool -Name $AppPoolName

# Start the website
Write-Host "Starting website..." -ForegroundColor Yellow
Start-IISSite -Name $SiteName

Write-Host "IISNode configuration completed successfully!" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "Configuration Summary:" -ForegroundColor White
Write-Host "  Application Pool: $AppPoolName" -ForegroundColor Gray
Write-Host "  Website: $SiteName" -ForegroundColor Gray
Write-Host "  Physical Path: $InstallPath" -ForegroundColor Gray
Write-Host "  Entry Point: dist/index.js" -ForegroundColor Gray
Write-Host "  Logs: $InstallPath\Logs" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Test the application by navigating to http://localhost" -ForegroundColor Yellow
