#!/bin/bash

# Root CA Certificate Management System - Startup Script

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_status "Starting Root CA Certificate Management System..."
print_status "Working directory: $SCRIPT_DIR"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. Consider using a non-root user for production."
fi

# Check if Root CA files exist
if [[ ! -f "/etc/mycerts/rootCA.crt" ]]; then
    print_error "Root CA certificate not found at /etc/mycerts/rootCA.crt"
    exit 1
fi

if [[ ! -f "/etc/mycerts/rootCA.key" ]]; then
    print_error "Root CA private key not found at /etc/mycerts/rootCA.key"
    exit 1
fi

print_status "Root CA files found ✓"

# Create necessary directories
mkdir -p /tmp/csr_uploads /tmp/cert_processing /var/log/rootca
chmod 755 /tmp/csr_uploads /tmp/cert_processing /var/log/rootca

print_status "Directories created ✓"

# Check Python dependencies
if ! python3 -c "import flask, werkzeug" 2>/dev/null; then
    print_error "Required Python packages not found. Please run: pip3 install -r requirements.txt"
    exit 1
fi

print_status "Python dependencies found ✓"

# Change to the application directory
cd "$SCRIPT_DIR"

# Start the application
print_status "Starting Flask application..."
print_status "Web interface will be available at: http://localhost:5000"
print_status "Press Ctrl+C to stop the application"

python3 app.py

