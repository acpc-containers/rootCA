# Docker Deployment Guide

This guide explains how to deploy the Root CA Certificate Management System using Docker.

## Prerequisites

- Docker Engine 20.10 or later
- Docker Compose 2.0 or later
- Root CA certificate and private key files

## Quick Start

1. **Prepare Root CA Files**
   ```bash
   # Ensure your Root CA files are available
   sudo cp /path/to/your/rootCA.crt /etc/mycerts/
   sudo cp /path/to/your/rootCA.key /etc/mycerts/
   sudo chmod 644 /etc/mycerts/rootCA.crt
   sudo chmod 600 /etc/mycerts/rootCA.key
   ```

2. **Deploy with Docker Compose**
   ```bash
   # Clone or download the application files
   cd /path/to/rootca
   
   # Run the deployment script
   ./docker-deploy.sh
   ```

3. **Access the Application**
   - Open your browser to `http://localhost:5000`
   - Login with default credentials:
     - Admin: `admin` / `admin123`
     - Operator: `operator` / `operator123`

## Manual Docker Deployment

### Build the Image

```bash
# Build the Docker image
docker-compose build

# Or build manually
docker build -t rootca-app .
```

### Run with Docker Compose

```bash
# Start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

### Run with Docker (Manual)

```bash
# Create necessary directories
mkdir -p logs data/csr_uploads data/cert_processing

# Run the container
docker run -d \
  --name rootca-app \
  -p 5000:5000 \
  -v /etc/mycerts/rootCA.crt:/etc/mycerts/rootCA.crt:ro \
  -v /etc/mycerts/rootCA.key:/etc/mycerts/rootCA.key:ro \
  -v $(pwd)/logs:/var/log/rootca \
  -v $(pwd)/data/csr_uploads:/tmp/csr_uploads \
  -v $(pwd)/data/cert_processing:/tmp/cert_processing \
  rootca-app
```

## Configuration

### Environment Variables

The following environment variables can be set in the `docker-compose.yml`:

```yaml
environment:
  - FLASK_ENV=production
  - PYTHONPATH=/app
```

### Volume Mounts

The application requires the following volume mounts:

1. **Root CA Files** (Required)
   ```yaml
   - /etc/mycerts/rootCA.crt:/etc/mycerts/rootCA.crt:ro
   - /etc/mycerts/rootCA.key:/etc/mycerts/rootCA.key:ro
   ```

2. **Data Persistence** (Optional but recommended)
   ```yaml
   - ./logs:/var/log/rootca
   - ./data/csr_uploads:/tmp/csr_uploads
   - ./data/cert_processing:/tmp/cert_processing
   ```

### Port Configuration

Default port mapping:
```yaml
ports:
  - "5000:5000"  # Host:Container
```

To use a different host port:
```yaml
ports:
  - "8080:5000"  # Access via http://localhost:8080
```

## Management Commands

### Viewing Logs

```bash
# View all logs
docker-compose logs

# Follow logs in real-time
docker-compose logs -f

# View logs for specific service
docker-compose logs rootca-app
```

### Updating the Application

```bash
# Pull latest changes and rebuild
docker-compose up -d --build

# Or rebuild manually
docker-compose build --no-cache
docker-compose up -d
```

### Backup and Restore

```bash
# Backup data
tar -czf rootca-backup-$(date +%Y%m%d).tar.gz data/ logs/

# Restore data
tar -xzf rootca-backup-YYYYMMDD.tar.gz
```

## Health Checks

The application includes built-in health checks:

```bash
# Check container health
docker-compose ps

# Manual health check
curl http://localhost:5000/status
```

## Security Considerations

### Container Security

1. **Run as non-root user**: The application runs as `appuser`
2. **Read-only Root CA files**: Certificate files are mounted read-only
3. **Minimal base image**: Uses Python slim image
4. **No unnecessary packages**: Only required dependencies installed

### Network Security

1. **Internal networking**: Uses Docker bridge network
2. **Port exposure**: Only port 5000 exposed
3. **No privileged mode**: Container runs without elevated privileges

### Data Security

1. **Volume permissions**: Proper file permissions set
2. **Data isolation**: Application data in separate volumes
3. **Log rotation**: Logs can be managed externally

## Troubleshooting

### Common Issues

1. **Permission Denied on Root CA Files**
   ```bash
   # Fix file permissions
   sudo chmod 644 /etc/mycerts/rootCA.crt
   sudo chmod 600 /etc/mycerts/rootCA.key
   ```

2. **Container Won't Start**
   ```bash
   # Check logs for errors
   docker-compose logs rootca-app
   
   # Check if Root CA files exist
   ls -la /etc/mycerts/
   ```

3. **Port Already in Use**
   ```bash
   # Check what's using port 5000
   sudo netstat -tlnp | grep :5000
   
   # Change port in docker-compose.yml
   ports:
     - "8080:5000"
   ```

4. **Health Check Failures**
   ```bash
   # Check container health
   docker inspect rootca-app | grep -A 10 Health
   
   # Manual health check
   docker exec rootca-app /app/healthcheck.sh
   ```

### Debug Mode

To run in debug mode:

```bash
# Override command for debugging
docker run -it --rm \
  -p 5000:5000 \
  -v /etc/mycerts/rootCA.crt:/etc/mycerts/rootCA.crt:ro \
  -v /etc/mycerts/rootCA.key:/etc/mycerts/rootCA.key:ro \
  --entrypoint /bin/bash \
  rootca-app
```

## Production Deployment

For production deployment, consider:

1. **Use a reverse proxy** (nginx, Traefik)
2. **Enable HTTPS** with proper SSL certificates
3. **Set up log aggregation** (ELK stack, Fluentd)
4. **Use secrets management** for sensitive data
5. **Implement monitoring** (Prometheus, Grafana)
6. **Set up automated backups**

### Example Production docker-compose.yml

```yaml
version: '3.8'

services:
  rootca-app:
    build: .
    restart: unless-stopped
    environment:
      - FLASK_ENV=production
    volumes:
      - /etc/mycerts/rootCA.crt:/etc/mycerts/rootCA.crt:ro
      - /etc/mycerts/rootCA.key:/etc/mycerts/rootCA.key:ro
      - ./logs:/var/log/rootca
      - ./data:/tmp
    networks:
      - backend
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - rootca-app
    networks:
      - frontend
      - backend

networks:
  frontend:
  backend:
    internal: true
```

## Support

For issues and questions:
1. Check the logs: `docker-compose logs`
2. Verify Root CA files are accessible
3. Check file permissions
4. Review the main README.md for additional troubleshooting
