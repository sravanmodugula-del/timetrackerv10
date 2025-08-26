
# Database Setup Script for TimeTracker on Windows
# Run this after application installation
# Note: Database schema migration is handled by DBA

param(
    [string]$InstallPath = "C:\TimeTracker",
    [string]$SqlServer = "HUB-SQL1TST-LIS",
    [string]$SqlUser = "timetracker",
    [string]$SqlPassword = "iTT!`$Lo7gm`"i'JAg~5Y\"
)

$ErrorActionPreference = "Stop"

Write-Host "Starting TimeTracker database setup..." -ForegroundColor Green

# Set working directory
Set-Location $InstallPath

# Set database URL environment variable
$env:DATABASE_URL = "sqlserver://${SqlServer}:1433;database=timetracker;user=${SqlUser};password=${SqlPassword};encrypt=true;trustServerCertificate=true"

Write-Host "Testing database connection..." -ForegroundColor Yellow
try {
    # Test connection first
    sqlcmd -S $SqlServer -U $SqlUser -P $SqlPassword -d timetracker -Q "SELECT 1" -t 30
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Database connection successful" -ForegroundColor Green
    } else {
        Write-Host "❌ Database connection failed. Please check connection settings." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Database connection error: $_" -ForegroundColor Red
    exit 1
}

# Generate Prisma client (REQUIRED - App will not work without this)
Write-Host "Generating Prisma client..." -ForegroundColor Yellow
npx prisma generate

# Verify Prisma Client generation
if (Test-Path "node_modules\.prisma\client") {
    Write-Host "✅ Prisma Client generated successfully" -ForegroundColor Green
} else {
    Write-Host "❌ Prisma Client generation failed" -ForegroundColor Red
    exit 1
}

# Test Prisma connection to database
Write-Host "Testing Prisma database connection..." -ForegroundColor Yellow
node scripts/test-sql-connection.js

Write-Host "Database setup completed!" -ForegroundColor Green

# Create initial admin user
Write-Host "Creating initial admin user..." -ForegroundColor Yellow

$createAdminScript = @"
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

async function createAdminUser() {
    const prisma = new PrismaClient();
    
    try {
        // Check if admin user already exists
        const existingAdmin = await prisma.user.findUnique({
            where: { email: 'admin@fmb.com' }
        });
        
        if (existingAdmin) {
            console.log('Admin user already exists: admin@fmb.com');
            return;
        }
        
        const hashedPassword = await bcrypt.hash('admin123', 10);
        
        const adminUser = await prisma.user.create({
            data: {
                email: 'admin@fmb.com',
                firstName: 'System',
                lastName: 'Administrator',
                role: 'admin',
                passwordHash: hashedPassword,
                isActive: true
            }
        });
        
        console.log('✅ Admin user created:', adminUser.email);
    } catch (error) {
        if (error.code === 'P2002') {
            console.log('Admin user already exists: admin@fmb.com');
        } else {
            console.error('❌ Error creating admin user:', error.message);
        }
    } finally {
        await prisma.\$disconnect();
    }
}

createAdminUser();
"@

$createAdminScript | Out-File -FilePath "$InstallPath\create-admin.js" -Encoding utf8
node create-admin.js
Remove-Item "$InstallPath\create-admin.js"

Write-Host "✅ Database setup completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "- Database connection: Verified" -ForegroundColor White
Write-Host "- Prisma client: Generated" -ForegroundColor White
Write-Host "- Admin user: admin@fmb.com / admin123" -ForegroundColor Yellow
Write-Host ""
Write-Host "⚠️  Please change the default admin password after first login!" -ForegroundColor Red
