#!/bin/bash

###############################################################################
# Servnix - Dependency Installation Script
# Installs all required dependencies for Servnix
# Usage: ./scripts/install-dependencies.sh
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Start
clear
print_header "Servnix - Dependency Installation"

echo ""
print_info "Detecting Operating System..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
        print_info "Detected: Ubuntu/Debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
        print_info "Detected: RedHat/CentOS"
    else
        DISTRO="unknown"
        print_warn "Unknown Linux distribution"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_info "Detected: macOS"
else
    print_error "Unsupported OS: $OSTYPE"
    exit 1
fi

echo ""
print_header "Installing Dependencies"

# Update package managers
if [ "$DISTRO" = "debian" ]; then
    print_info "Updating apt repository..."
    sudo apt-get update -qq
    
    # Node.js
    print_info "Installing Node.js v18+..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash - > /dev/null 2>&1
    sudo apt-get install -y nodejs > /dev/null 2>&1
    print_success "Node.js installed: $(node -v)"
    
    # Python
    print_info "Installing Python 3..."
    sudo apt-get install -y python3 python3-pip > /dev/null 2>&1
    print_success "Python installed: $(python3 -V 2>&1)"
    
    # Docker
    print_info "Installing Docker..."
    sudo apt-get install -y docker.io docker-compose > /dev/null 2>&1
    sudo usermod -aG docker $USER > /dev/null 2>&1
    print_success "Docker installed"
    
    # Security tools
    print_info "Installing security tools..."
    sudo apt-get install -y curl wget jq openssl git > /dev/null 2>&1
    print_success "Security tools installed"

    # Servnix-Firewall-Basis + Brute-Force-Schutz
    print_info "Installing nftables + fail2ban (Servnix-Firewall & Brute-Force-Schutz)..."
    sudo apt-get install -y nftables fail2ban > /dev/null 2>&1
    sudo systemctl enable fail2ban > /dev/null 2>&1 || true
    sudo systemctl start fail2ban > /dev/null 2>&1 || true
    print_success "nftables + fail2ban installiert"

elif [ "$DISTRO" = "redhat" ]; then
    print_info "Installing Node.js v18+..."
    curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash - > /dev/null 2>&1
    sudo yum install -y nodejs > /dev/null 2>&1
    print_success "Node.js installed: $(node -v)"
    
    # Python
    print_info "Installing Python 3..."
    sudo yum install -y python3 python3-pip > /dev/null 2>&1
    print_success "Python installed: $(python3 -V 2>&1)"
    
    # Docker
    print_info "Installing Docker..."
    sudo yum install -y docker docker-compose > /dev/null 2>&1
    sudo systemctl start docker > /dev/null 2>&1
    sudo usermod -aG docker $USER > /dev/null 2>&1
    print_success "Docker installed"
    
    # Security tools
    print_info "Installing security tools..."
    sudo yum install -y curl wget jq openssl git > /dev/null 2>&1
    print_success "Security tools installed"

    # Servnix-Firewall-Basis + Brute-Force-Schutz
    print_info "Installing nftables + fail2ban (Servnix-Firewall & Brute-Force-Schutz)..."
    sudo yum install -y nftables fail2ban > /dev/null 2>&1
    sudo systemctl enable fail2ban > /dev/null 2>&1 || true
    sudo systemctl start fail2ban > /dev/null 2>&1 || true
    print_success "nftables + fail2ban installiert"

elif [ "$OS" = "macos" ]; then
    print_info "Installing via Homebrew..."
    
    # Check Homebrew
    if ! command -v brew &> /dev/null; then
        print_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Node.js
    print_info "Installing Node.js..."
    brew install node > /dev/null 2>&1
    print_success "Node.js installed: $(node -v)"
    
    # Python
    print_info "Installing Python..."
    brew install python@3.11 > /dev/null 2>&1
    print_success "Python installed: $(python3 -V 2>&1)"
    
    # Docker
    print_info "Installing Docker..."
    brew install --cask docker > /dev/null 2>&1
    print_success "Docker installed"
    
    # Security tools
    print_info "Installing security tools..."
    brew install curl wget jq openssl git > /dev/null 2>&1
    print_success "Security tools installed"
fi

echo ""
print_header "Installing Node.js Dependencies"

# Install npm packages
print_info "Installing npm packages..."
npm install > /dev/null 2>&1
print_success "npm packages installed"

# Install global npm tools
print_info "Installing global npm tools..."
npm install -g npm-check-updates snyk eslint > /dev/null 2>&1
print_success "Global npm tools installed"

echo ""
print_header "Installing Python Dependencies"

# Install Python packages
print_info "Installing Python packages..."
pip3 install --upgrade pip > /dev/null 2>&1
pip3 install -r requirements.txt > /dev/null 2>&1
print_success "Python packages installed"

echo ""
print_header "Final Checks"

# Make scripts executable
print_info "Making scripts executable..."
chmod +x scripts/*.sh
print_success "Scripts are executable"

# GitHub CLI
if command -v gh &> /dev/null; then
    print_success "GitHub CLI already installed"
else
    print_warn "GitHub CLI not found (optional, but recommended)"
    echo "  Install with: brew install gh (macOS) or apt-get install gh (Linux)"
fi

echo ""
print_header "Installation Complete!"

echo ""
echo -e "${GREEN}✅ All dependencies installed successfully!${NC}"
echo ""
echo "Next steps:"
echo "1. Run validation: ./scripts/validate-system.sh"
echo "2. Configure .env: cp .env.example .env && nano .env"
echo "3. Run security scan: ./scripts/security-scan.sh"
echo ""
echo "For help, see: docs/INSTALLATION.md"
