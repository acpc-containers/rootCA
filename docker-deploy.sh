#!/bin/bash

# Root CA Certificate Management System - Docker Deployment Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_info() {
    echo -e "${BLUE}[DOCKER]${NC} $1"
}

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
print_status "Working directory: $SCRIPT_DIR"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

print_status "Docker and Docker Compose are available ✓"

# Check if Root CA files exist
print_status "Checking Root CA files..."
if [[ ! -f "/etc/mycerts/rootCA.crt" ]]; then
    print_error "Root CA certificate not found at /etc/mycerts/rootCA.crt"
    print_warning "Please ensure your Root CA certificate is available at /etc/mycerts/rootCA.crt"
    print_info "You can copy it there or modify the docker-compose.yml volume mounts"
    exit 1
fi

if [[ ! -f "/etc/mycerts/rootCA.key" ]]; then
    print_error "Root CA private key not found at /etc/mycerts/rootCA.key"
    print_warning "Please ensure your Root CA private key is available at /etc/mycerts/rootCA.key"
    print_info "You can copy it there or modify the docker-compose.yml volume mounts"
    exit 1
fi

print_status "Root CA files found ✓"

# Create necessary directories
print_status "Creating directories..."
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/data/csr_uploads"
mkdir -p "$SCRIPT_DIR/data/cert_processing"

chmod 755 "$SCRIPT_DIR/logs"
chmod 755 "$SCRIPT_DIR/data/csr_uploads"
chmod 755 "$SCRIPT_DIR/data/cert_processing"

print_status "Directories created ✓"

# Build Docker image
print_status "Building Docker image..."
print_info "This may take a few minutes on first build..."
docker-compose build

if [ $? -eq 0 ]; then
    print_status "Docker image built successfully ✓"
else
    print_error "Failed to build Docker image"
    exit 1
fi

# Stop existing containers
print_status "Stopping existing containers..."
docker-compose down 2>/dev/null || true

# Start the application
print_status "Starting Root CA Certificate Management application..."
docker-compose up -d

if [ $? -eq 0 ]; then
    print_status "Application started successfully ✓"
else
    print_error "Failed to start application"
    exit 1
fi

# Wait for application to be ready
print_status "Waiting for application to be ready..."
sleep 10

# Check if application is running
print_status "Checking application status..."
if docker-compose ps | grep -q "Up"; then
    print_status "Application is running ✓"
else
    print_error "Application failed to start"
    print_info "Check logs with: docker-compose logs"
    exit 1
fi

# Display status
echo ""
print_status "=== Deployment Complete ==="
echo ""
print_status "Application Status:"
docker-compose ps
echo ""
print_status "Access Information:"
echo "  Web Interface: http://localhost:5000"
echo "  Default Login: admin / admin123"
echo "  Operator Login: operator / operator123"
echo ""
print_status "Management Commands:"
echo "  View logs: docker-compose logs -f"
echo "  Stop app: docker-compose down"
echo "  Restart app: docker-compose restart"
echo "  Update app: docker-compose up -d --build"
echo ""
print_warning "Security Notes:"
echo "  1. Change default passwords after first login"
echo "  2. Update Flask secret key in app.py"
echo "  3. Configure firewall for port 5000"
echo "  4. Consider using HTTPS in production"
echo ""
print_status "Docker deployment completed successfully! ✓"
