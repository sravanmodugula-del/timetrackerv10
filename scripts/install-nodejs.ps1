
# Install Node.js 20.x LTS on Windows
# Run as Administrator

Write-Host "Checking for existing Node.js installation..." -ForegroundColor Yellow

# Check if Node.js is already installed
try {
    $existingVersion = node --version 2>$null
    if ($existingVersion) {
        Write-Host "Node.js is already installed: $existingVersion" -ForegroundColor Green
        
        # Check if it's version 20.x
        if ($existingVersion -match "v20\.") {
            Write-Host "✅ Node.js 20.x is already installed. Skipping installation." -ForegroundColor Green
            $skipInstall = $true
        } else {
            Write-Host "⚠️ Different Node.js version detected. Proceeding with Node.js 20.x installation..." -ForegroundColor Yellow
            $skipInstall = $false
        }
    } else {
        $skipInstall = $false
    }
} catch {
    Write-Host "Node.js not found. Proceeding with installation..." -ForegroundColor Yellow
    $skipInstall = $false
}

# Install Node.js only if needed
if (-not $skipInstall) {
    Write-Host "Installing Node.js 20.x LTS..." -ForegroundColor Green
    
    # Download and install Node.js
    $nodeUrl = "https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi"
    $nodeInstaller = "$env:TEMP\nodejs-installer.msi"

    try {
        Invoke-WebRequest -Uri $nodeUrl -OutFile $nodeInstaller
        Start-Process msiexec.exe -Wait -ArgumentList "/i $nodeInstaller /quiet /norestart"
        Write-Host "Node.js 20.x LTS installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to install Node.js: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    
    # Clean up installer
    if (Test-Path $nodeInstaller) {
        Remove-Item $nodeInstaller -Force
    }
}

# Add Node.js to PATH if not already there
$nodePath = "C:\Program Files\nodejs"
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$nodePath*") {
    Write-Host "Adding Node.js to system PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$nodePath", "Machine")
}

# Refresh environment variables
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")

# Verify installation
Write-Host "Verifying Node.js installation..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version
    $npmVersion = npm --version
    Write-Host "✅ Node.js version: $nodeVersion" -ForegroundColor Green
    Write-Host "✅ NPM version: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js verification failed. Installation may be incomplete." -ForegroundColor Red
    exit 1
}

# Note: PM2 not needed with IISNode - IIS handles process management
Write-Host "✅ Using IISNode for process management (PM2 not required)" -ForegroundColor Green

Write-Host "Node.js setup completed successfully!" -ForegroundColor Green
