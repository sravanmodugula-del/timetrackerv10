#!/bin/bash

# TimeTracker Pro On-Premises Installation Script
# Supports Ubuntu 20.04+, CentOS 8+, RHEL 8+

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VER"
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    
    case $OS in
        *"Ubuntu"*|*"Debian"*)
            sudo apt update && sudo apt upgrade -y
            sudo apt install -y curl wget git build-essential software-properties-common
            ;;
        *"CentOS"*|*"Red Hat"*)
            sudo dnf update -y
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y curl wget git
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    log_success "System packages updated"
}

# Install Node.js 20
install_nodejs() {
    log_info "Installing Node.js 20..."
    
    # Install Node.js using NodeSource repository
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    
    case $OS in
        *"Ubuntu"*|*"Debian"*)
            sudo apt-get install -y nodejs
            ;;
        *"CentOS"*|*"Red Hat"*)
            sudo dnf install -y nodejs npm
            ;;
    esac
    
    # Verify installation
    NODE_VERSION=$(node --version)
    NPM_VERSION=$(npm --version)
    log_success "Node.js installed: $NODE_VERSION"
    log_success "NPM installed: $NPM_VERSION"
    
    # Install PM2 globally
    sudo npm install -g pm2
    log_success "PM2 process manager installed"
}

# Install PostgreSQL
install_postgresql() {
    log_info "Installing PostgreSQL..."
    
    case $OS in
        *"Ubuntu"*|*"Debian"*)
            sudo apt install -y postgresql postgresql-contrib
            ;;
        *"CentOS"*|*"Red Hat"*)
            sudo dnf install -y postgresql postgresql-server postgresql-contrib
            sudo postgresql-setup --initdb
            ;;
    esac
    
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    
    log_success "PostgreSQL installed and started"
}

# Setup PostgreSQL database
setup_database() {
    log_info "Setting up TimeTracker database..."
    
    # Generate secure database password
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    # Create database and user
    sudo -u postgres psql << EOF
CREATE DATABASE timetracker;
CREATE USER timetracker_user WITH ENCRYPTED PASSWORD '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE timetracker TO timetracker_user;
ALTER USER timetracker_user CREATEDB;
\q
EOF
    
    # Save database credentials
    echo "# Database credentials (generated during installation)" > .env.db
    echo "DATABASE_URL=postgresql://timetracker_user:$DB_PASSWORD@localhost:5432/timetracker" >> .env.db
    chmod 600 .env.db
    
    log_success "Database created with user 'timetracker_user'"
    log_info "Database credentials saved to .env.db"
}

# Install Nginx
install_nginx() {
    log_info "Installing Nginx..."
    
    case $OS in
        *"Ubuntu"*|*"Debian"*)
            sudo apt install -y nginx
            ;;
        *"CentOS"*|*"Red Hat"*)
            sudo dnf install -y nginx
            ;;
    esac
    
    sudo systemctl enable nginx
    sudo systemctl start nginx
    
    log_success "Nginx installed and started"
}

# Setup application
setup_application() {
    log_info "Setting up TimeTracker application..."
    
    # Install dependencies
    npm ci --only=production
    
    # Build application
    npm run build
    
    # Create log directory
    sudo mkdir -p /var/log/timetracker
    sudo chown $USER:$USER /var/log/timetracker
    
    # Create PM2 ecosystem file
    cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'timetracker',
    script: 'server/index.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: '/var/log/timetracker/err.log',
    out_file: '/var/log/timetracker/out.log',
    log_file: '/var/log/timetracker/combined.log',
    time: true,
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024'
  }]
};
EOF
    
    log_success "Application configured"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    case $OS in
        *"Ubuntu"*|*"Debian"*)
            sudo ufw --force enable
            sudo ufw allow ssh
            sudo ufw allow 'Nginx Full'
            ;;
        *"CentOS"*|*"Red Hat"*)
            sudo firewall-cmd --permanent --add-service=http
            sudo firewall-cmd --permanent --add-service=https
            sudo firewall-cmd --permanent --add-port=22/tcp
            sudo firewall-cmd --reload
            ;;
    esac
    
    log_success "Firewall configured"
}

# Generate secure session secret
generate_session_secret() {
    SESSION_SECRET=$(openssl rand -base64 32)
    echo "# Generated session secret" > .env.session
    echo "SESSION_SECRET=$SESSION_SECRET" >> .env.session
    chmod 600 .env.session
    
    log_success "Secure session secret generated and saved to .env.session"
}

# Create environment file
create_env_file() {
    log_info "Creating production environment file..."
    
    # Copy template and merge credentials
    cp .env.onprem.template .env
    
    # Add generated credentials
    echo "" >> .env
    echo "# Generated during installation" >> .env
    cat .env.db >> .env
    cat .env.session >> .env
    
    # Clean up temporary files
    rm .env.db .env.session
    
    chmod 600 .env
    
    log_warn "IMPORTANT: Edit .env file to configure your domain and other settings!"
}

# Setup SSL (Let's Encrypt)
setup_ssl() {
    read -p "Do you want to setup SSL with Let's Encrypt? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter your domain name: " DOMAIN
        
        case $OS in
            *"Ubuntu"*|*"Debian"*)
                sudo apt install -y certbot python3-certbot-nginx
                ;;
            *"CentOS"*|*"Red Hat"*)
                sudo dnf install -y certbot python3-certbot-nginx
                ;;
        esac
        
        sudo certbot --nginx -d $DOMAIN
        
        # Setup auto-renewal
        echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
        
        log_success "SSL certificate installed for $DOMAIN"
    else
        log_info "Skipping SSL setup"
    fi
}

# Start services
start_services() {
    log_info "Starting TimeTracker services..."
    
    # Start application with PM2
    pm2 start ecosystem.config.js --env production
    
    # Setup PM2 startup script
    pm2 startup
    pm2 save
    
    # Start Nginx
    sudo systemctl restart nginx
    
    log_success "All services started"
}

# Main installation function
main() {
    log_info "Starting TimeTracker On-Premises Installation"
    log_info "=============================================="
    
    check_root
    detect_os
    update_system
    install_nodejs
    install_postgresql
    setup_database
    install_nginx
    configure_firewall
    setup_application
    generate_session_secret
    create_env_file
    setup_ssl
    start_services
    
    log_success "TimeTracker installation completed!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Edit .env file with your domain and settings"
    log_info "2. Configure Nginx virtual host for your domain"
    log_info "3. Run database migrations: npm run db:push"
    log_info "4. Access your application at http://your-domain"
    log_info ""
    log_info "Application logs: /var/log/timetracker/"
    log_info "PM2 management: pm2 status, pm2 logs, pm2 restart timetracker"
}

# Run main function
main "$@"