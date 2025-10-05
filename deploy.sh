#!/bin/bash

# Root CA Certificate Management System - Deployment Script
# This script sets up the application for production use

set -e

echo "=== Root CA Certificate Management System Deployment ==="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Get the current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
print_status "Working directory: $SCRIPT_DIR"

# Check if Root CA files exist
print_status "Checking Root CA files..."
if [[ ! -f "/etc/mycerts/rootCA.crt" ]]; then
    print_error "Root CA certificate not found at /etc/mycerts/rootCA.crt"
    exit 1
fi

if [[ ! -f "/etc/mycerts/rootCA.key" ]]; then
    print_error "Root CA private key not found at /etc/mycerts/rootCA.key"
    exit 1
fi

print_status "Root CA files found ✓"

# Install Python dependencies
print_status "Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install -r "$SCRIPT_DIR/requirements.txt"
else
    print_error "pip3 not found. Please install Python3 and pip3"
    exit 1
fi

# Create necessary directories
print_status "Creating directories..."
mkdir -p /tmp/csr_uploads
mkdir -p /tmp/cert_processing
mkdir -p /var/log/rootca

# Set proper permissions
chmod 755 /tmp/csr_uploads
chmod 755 /tmp/cert_processing
chmod 755 /var/log/rootca

print_status "Directories created ✓"

# Install systemd service
print_status "Installing systemd service..."
if [[ -f "$SCRIPT_DIR/rootca.service" ]]; then
    cp "$SCRIPT_DIR/rootca.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable rootca.service
    print_status "Systemd service installed ✓"
else
    print_warning "Service file not found, skipping systemd installation"
fi

# Check OpenSSL installation
print_status "Checking OpenSSL installation..."
if command -v openssl &> /dev/null; then
    print_status "OpenSSL found: $(openssl version)"
else
    print_error "OpenSSL not found. Please install OpenSSL"
    exit 1
fi

# Test the application
print_status "Testing application configuration..."
cd "$SCRIPT_DIR"
if python3 -c "import flask, werkzeug; print('Dependencies OK')" 2>/dev/null; then
    print_status "Python dependencies test passed ✓"
else
    print_error "Python dependencies test failed"
    exit 1
fi

# Create a test configuration check
print_status "Running configuration check..."
if python3 -c "
import os
import sys
sys.path.insert(0, '.')
try:
    from app import ROOT_CA_CERT_PATH, ROOT_CA_KEY_PATH
    if os.path.exists(ROOT_CA_CERT_PATH) and os.path.exists(ROOT_CA_KEY_PATH):
        print('Configuration OK')
    else:
        print('Configuration Error')
        sys.exit(1)
except Exception as e:
    print(f'Configuration Error: {e}')
    sys.exit(1)
" 2>/dev/null; then
    print_status "Configuration check passed ✓"
else
    print_error "Configuration check failed"
    exit 1
fi

# Set up log rotation
print_status "Setting up log rotation..."
cat > /etc/logrotate.d/rootca << EOF
/var/log/rootca/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

print_status "Log rotation configured ✓"

# Final setup instructions
echo ""
print_status "=== Deployment Complete ==="
echo ""
print_status "To start the service:"
echo "  systemctl start rootca"
echo ""
print_status "To check service status:"
echo "  systemctl status rootca"
echo ""
print_status "To view logs:"
echo "  journalctl -u rootca -f"
echo ""
print_status "To access the web interface:"
echo "  http://your-server-ip:5000"
echo ""
print_status "Default Login Credentials:"
echo "  Admin User: admin / admin123"
echo "  Operator User: operator / operator123"
echo ""
print_warning "Important Security Notes:"
echo "  1. Change the Flask secret key in app.py"
echo "  2. Change default user passwords in app.py"
echo "  3. Configure firewall rules for port 5000"
echo "  4. Consider using HTTPS in production"
echo "  5. Review sudo permissions for OpenSSL operations"
echo "  6. Root CA private key is password protected (P@ssw0rd)"
echo ""
print_status "New Features Added:"
echo "  ✓ User authentication and login system"
echo "  ✓ Password-protected Root CA private key support"
echo "  ✓ Enhanced error handling and logging"
echo "  ✓ Admin panel for user management"
echo "  ✓ Session management with timeout"
echo "  ✓ CSRF protection enabled"
echo ""
print_status "Deployment completed successfully! ✓"

