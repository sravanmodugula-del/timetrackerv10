
# Install SSL Certificate for TimeTracker
# Run as Administrator

param(
    [string]$Domain = "timetracker.fmb.com",
    [string]$CertPath = "",
    [string]$CertPassword = "",
    [string]$SiteName = "TimeTracker"
)

Import-Module WebAdministration

Write-Host "Installing SSL Certificate for TimeTracker..." -ForegroundColor Green

if ($CertPath -and (Test-Path $CertPath)) {
    # Install certificate from file
    $securePassword = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
    $cert = Import-PfxCertificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\My -Password $securePassword
    
    # Check if HTTPS binding already exists, if not create it
    $existingBinding = Get-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $Domain -ErrorAction SilentlyContinue
    if (!$existingBinding) {
        New-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $Domain
        Write-Host "Created new HTTPS binding for $Domain" -ForegroundColor Green
    } else {
        Write-Host "HTTPS binding already exists for $Domain" -ForegroundColor Yellow
    }
    
    $binding = Get-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $Domain
    $binding.AddSslCertificate($cert.Thumbprint, "my")
    
    Write-Host "SSL certificate installed and bound to site" -ForegroundColor Green
} else {
    # Create self-signed certificate for development
    $cert = New-SelfSignedCertificate -DnsName $Domain -CertStoreLocation Cert:\LocalMachine\My -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(2)
    
    # Check if HTTPS binding already exists, if not create it
    $existingBinding = Get-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $Domain -ErrorAction SilentlyContinue
    if (!$existingBinding) {
        New-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $Domain
        Write-Host "Created new HTTPS binding for $Domain" -ForegroundColor Green
    } else {
        Write-Host "HTTPS binding already exists for $Domain" -ForegroundColor Yellow
    }
    
    $binding = Get-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $Domain
    $binding.AddSslCertificate($cert.Thumbprint, "my")
    
    Write-Host "Self-signed certificate created and installed" -ForegroundColor Yellow
    Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
}

# Configure HTTPS redirect
$httpsRedirectRule = @"
<rule name="Redirect to HTTPS" stopProcessing="true">
    <match url=".*" />
    <conditions>
        <add input="{HTTPS}" pattern="off" ignoreCase="true" />
    </conditions>
    <action type="Redirect" url="https://{HTTP_HOST}/{R:0}" redirectType="Permanent" />
</rule>
"@

Write-Host "SSL configuration completed!" -ForegroundColor Green
Write-Host "Access your application at: https://$Domain" -ForegroundColor Cyan
