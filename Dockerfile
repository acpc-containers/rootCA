# Root CA Certificate Management System - Dockerfile
# Multi-stage build for production deployment

# Stage 1: Build stage
FROM python:3.10-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --user -r /tmp/requirements.txt

# Stage 2: Runtime stage
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:$PATH"

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    sudo \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user
RUN useradd -m -s /bin/bash appuser && \
    echo "appuser ALL=(ALL) NOPASSWD: /usr/bin/openssl x509 -req -in * -CA /etc/mycerts/rootCA.crt -CAkey /etc/mycerts/rootCA.key -CAcreateserial -out * -days * -sha256 -extfile *" >> /etc/sudoers

# Create necessary directories
RUN mkdir -p /var/log/rootca \
    /tmp/csr_uploads \
    /tmp/cert_processing \
    /etc/mycerts \
    && chmod 755 /var/log/rootca \
    && chmod 755 /tmp/csr_uploads \
    && chmod 755 /tmp/cert_processing \
    && chmod 755 /etc/mycerts

# Copy Python packages from builder stage
COPY --from=builder /root/.local /root/.local

# Set working directory
WORKDIR /app

# Copy application files
COPY app.py config.py manage_users.py requirements.txt ./
COPY templates/ ./templates/
COPY sample.csr ./

# Create startup script
RUN echo '#!/bin/bash\n\
echo "=== Root CA Certificate Management System ==="\n\
echo "Checking Root CA files..."\n\
if [ ! -f "/etc/mycerts/rootCA.crt" ]; then\n\
    echo "WARNING: Root CA certificate not found at /etc/mycerts/rootCA.crt"\n\
    echo "Please mount your Root CA certificate file to /etc/mycerts/rootCA.crt"\n\
fi\n\
if [ ! -f "/etc/mycerts/rootCA.key" ]; then\n\
    echo "WARNING: Root CA private key not found at /etc/mycerts/rootCA.key"\n\
    echo "Please mount your Root CA private key file to /etc/mycerts/rootCA.key"\n\
fi\n\
echo "Starting application..."\n\
python3 app.py' > /app/start.sh && \
    chmod +x /app/start.sh

# Create health check script
RUN echo '#!/bin/bash\n\
curl -f http://localhost:5000/status || exit 1' > /app/healthcheck.sh && \
    chmod +x /app/healthcheck.sh

# Set permissions
RUN chown -R appuser:appuser /app /var/log/rootca /tmp/csr_uploads /tmp/cert_processing

# Switch to application user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/healthcheck.sh

# Default command
CMD ["/app/start.sh"]
