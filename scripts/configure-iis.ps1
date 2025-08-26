
# Configure IIS for TimeTracker
# Run as Administrator

param(
    [string]$SiteName = "TimeTracker",
    [string]$Domain = "timetracker.fmb.com",
    [string]$InstallPath = "C:\TimeTracker",
    [int]$Port = 80,
    [int]$SslPort = 443
)

Import-Module WebAdministration

Write-Host "Configuring IIS for TimeTracker..." -ForegroundColor Green

# Remove default site if it exists
if (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue) {
    Remove-Website -Name "Default Web Site"
    Write-Host "Removed default website" -ForegroundColor Yellow
}

# Create application pool
$appPoolName = "$SiteName-AppPool"
if (!(Test-Path "IIS:\AppPools\$appPoolName")) {
    New-WebAppPool -Name $appPoolName
    Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name processModel.identityType -Value NetworkService
    Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name managedRuntimeVersion -Value ""
    Write-Host "Created application pool: $appPoolName" -ForegroundColor Green
}

# Create website
if (!(Get-Website -Name $SiteName -ErrorAction SilentlyContinue)) {
    New-Website -Name $SiteName -Port $Port -PhysicalPath "$InstallPath\public" -ApplicationPool $appPoolName
    Write-Host "Created website: $SiteName" -ForegroundColor Green
}

# Configure bindings
if ($Domain -ne "localhost") {
    New-WebBinding -Name $SiteName -Protocol http -Port $Port -HostHeader $Domain
    if ($SslPort -eq 443) {
        New-WebBinding -Name $SiteName -Protocol https -Port $SslPort -HostHeader $Domain
    }
    Write-Host "Configured bindings for domain: $Domain" -ForegroundColor Green
}

# Install URL Rewrite module (download required)
Write-Host "Please install URL Rewrite module from: https://www.iis.net/downloads/microsoft/url-rewrite" -ForegroundColor Yellow

# Create web.config for reverse proxy
$webConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <defaultDocument>
            <files>
                <clear />
                <add value="index.html" />
            </files>
        </defaultDocument>
        <rewrite>
            <rules>
                <rule name="ReverseProxyInboundRule1" stopProcessing="true">
                    <match url="(.*)" />
                    <conditions>
                        <add input="{CACHE_URL}" pattern="^(https?)://" />
                    </conditions>
                    <action type="Rewrite" url="{C:1}://localhost:3000/{R:1}" />
                </rule>
            </rules>
        </rewrite>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="52428800" />
            </requestFiltering>
        </security>
        <httpProtocol>
            <customHeaders>
                <add name="X-Frame-Options" value="SAMEORIGIN" />
                <add name="X-Content-Type-Options" value="nosniff" />
                <add name="X-XSS-Protection" value="1; mode=block" />
                <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@

$webConfigContent | Out-File -FilePath "$InstallPath\public\web.config" -Encoding utf8

Write-Host "IIS configuration completed!" -ForegroundColor Green
