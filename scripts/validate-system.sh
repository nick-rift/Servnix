#!/bin/bash

###############################################################################
# Servnix - System Validation Script
# Validates all prerequisites before installation
# Usage: ./scripts/validate-system.sh
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNING=0

# Helper functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_check() {
    echo -e "${YELLOW}→${NC} $1"
}

print_pass() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED++))
}

print_fail() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED++))
}

print_warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
    ((WARNING++))
}

# Start validation
clear
print_header "Servnix System Validation"

echo ""
print_header "1. Runtime Requirements"

# Check Node.js
print_check "Checking Node.js..."
if command -v node &> /dev/null; then
    NODE_VERSION=$(node -v)
    NODE_MAJOR=$(echo $NODE_VERSION | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_MAJOR" -ge 18 ]; then
        print_pass "Node.js $NODE_VERSION installed"
    else
        print_fail "Node.js $NODE_VERSION installed (requires v18+)"
    fi
else
    print_fail "Node.js not installed"
fi

# Check npm
print_check "Checking npm..."
if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm -v)
    print_pass "npm $NPM_VERSION installed"
else
    print_fail "npm not installed"
fi

# Check Python
print_check "Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -V 2>&1 | awk '{print $2}')
    print_pass "Python $PYTHON_VERSION installed"
else
    print_fail "Python 3 not installed"
fi

# Check Docker
print_check "Checking Docker..."
if command -v docker &> /dev/null; then
    if docker ps &> /dev/null; then
        DOCKER_VERSION=$(docker -v | cut -d',' -f1)
        print_pass "Docker running ($DOCKER_VERSION)"
    else
        print_warn "Docker installed but not running (sudo docker ps failed)"
    fi
else
    print_fail "Docker not installed"
fi

# Check Git
print_check "Checking Git..."
if command -v git &> /dev/null; then
    GIT_VERSION=$(git --version)
    print_pass "$GIT_VERSION"
else
    print_fail "Git not installed"
fi

# Check GitHub CLI
print_check "Checking GitHub CLI..."
if command -v gh &> /dev/null; then
    GH_VERSION=$(gh --version | head -1)
    print_pass "$GH_VERSION"
else
    print_warn "GitHub CLI not installed (optional but recommended)"
fi

echo ""
print_header "2. Required Permissions"

# Check sudo
print_check "Checking sudo permissions..."
if sudo -n true 2>/dev/null; then
    print_pass "Sudo access available without password"
else
    print_warn "Sudo password required (you may need to enter password during setup)"
fi

# Check write permissions
print_check "Checking directory write permissions..."
if [ -w . ]; then
    print_pass "Write permission in current directory"
else
    print_fail "No write permission in current directory"
fi

echo ""
print_header "3. Security Tools"

# Check openssl
print_check "Checking OpenSSL..."
if command -v openssl &> /dev/null; then
    OPENSSL_VERSION=$(openssl version | cut -d' ' -f1-2)
    print_pass "$OPENSSL_VERSION"
else
    print_warn "OpenSSL not found (may be needed for SSL audits)"
fi

# Check curl
print_check "Checking curl..."
if command -v curl &> /dev/null; then
    print_pass "curl installed"
else
    print_fail "curl not installed (required)"
fi

# Check wget
print_check "Checking wget..."
if command -v wget &> /dev/null; then
    print_pass "wget installed"
else
    print_warn "wget not installed (optional)"
fi

# Check jq
print_check "Checking jq..."
if command -v jq &> /dev/null; then
    print_pass "jq installed"
else
    print_warn "jq not installed (useful for JSON parsing)"
fi

echo ""
print_header "4. Network Connectivity"

# Check internet connection
print_check "Checking internet connection..."
if curl -s https://github.com > /dev/null 2>&1; then
    print_pass "Internet connection available"
else
    print_fail "Cannot reach github.com (check your internet connection)"
fi

# Check GitHub API access
print_check "Checking GitHub API access..."
if curl -s -H "Accept: application/vnd.github.v3+json" https://api.github.com > /dev/null 2>&1; then
    print_pass "GitHub API accessible"
else
    print_fail "GitHub API not accessible"
fi

echo ""
print_header "5. Configuration Files"

# Check .env
print_check "Checking .env file..."
if [ -f .env ]; then
    print_pass ".env file exists"
else
    if [ -f .env.example ]; then
        print_warn ".env not found (but .env.example exists)"
    else
        print_fail ".env and .env.example not found"
    fi
fi

# Check package.json
print_check "Checking package.json..."
if [ -f package.json ]; then
    print_pass "package.json found"
else
    print_fail "package.json not found"
fi

# Check requirements.txt
print_check "Checking requirements.txt..."
if [ -f requirements.txt ]; then
    print_pass "requirements.txt found"
else
    print_warn "requirements.txt not found (Python dependencies)"
fi

echo ""
print_header "6. Disk Space"

# Check available disk space
print_check "Checking available disk space..."
AVAILABLE_SPACE=$(df . | awk 'NR==2 {print $4}')
if [ "$AVAILABLE_SPACE" -gt 1000000 ]; then
    AVAILABLE_GB=$((AVAILABLE_SPACE / 1024 / 1024))
    print_pass "Sufficient disk space available (~${AVAILABLE_GB}GB)"
else
    print_warn "Low disk space available (less than 1GB)"
fi

echo ""
print_header "Summary"

echo ""
echo -e "Checks Passed:  ${GREEN}$PASSED${NC}"
echo -e "Checks Failed:  ${RED}$FAILED${NC}"
echo -e "Warnings:       ${YELLOW}$WARNING${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ All critical checks passed!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [ $WARNING -gt 0 ]; then
        echo ""
        echo "⚠️  Warning: There are $WARNING optional checks that failed."
        echo "These are not critical but may limit certain features."
    fi
    
    echo ""
    echo "Next steps:"
    echo "1. Review and configure .env file"
    echo "2. Run: npm install && pip install -r requirements.txt"
    echo "3. Run: ./scripts/security-scan.sh"
    exit 0
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}❌ $FAILED critical checks failed!${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Please install missing requirements and try again."
    exit 1
fi
