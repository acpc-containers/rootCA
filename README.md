# Root CA Certificate Management System

A web-based application for managing SSL certificate requests and generation using a Root Certificate Authority (CA) on Ubuntu 22.04.

## Features

- **User Authentication**: Secure login system with role-based access control
- **Web-based Interface**: Modern, responsive web interface for certificate requests
- **CSR Upload**: Secure upload of Certificate Signing Request files (.csr, .pem)
- **Automatic SAN Generation**: Automatically extracts domain from FQHN and generates Subject Alternative Name extensions
- **Certificate Signing**: Signs certificates using OpenSSL with password-protected Root CA private key
- **Archive Creation**: Packages signed certificate and Root CA certificate into a downloadable ZIP file
- **Concurrent Access Support**: Thread-safe file operations with proper locking mechanisms
- **Automatic Cleanup**: Temporary files are automatically cleaned up after processing
- **Real-time Status**: System health monitoring and status indicators
- **Admin Panel**: User management and system administration interface
- **Session Management**: Secure session handling with automatic timeout
- **Error Handling**: Comprehensive error handling and logging throughout the application
- **CSRF Protection**: Cross-Site Request Forgery protection enabled

## Prerequisites

- Ubuntu 22.04 or compatible Linux distribution
- OpenSSL installed and configured
- Python 3.8 or higher
- Root CA certificate and private key files
- sudo privileges for OpenSSL operations

## Installation

### Option 1: Docker Deployment (Recommended)

1. **Prerequisites**:
   - Docker Engine 20.10+
   - Docker Compose 2.0+
   - Root CA certificate and private key files

2. **Quick Docker Deployment**:
   ```bash
   # Navigate to the project directory
   cd /home/compiler/cursorai/rootca
   
   # Ensure Root CA files are available
   sudo cp /path/to/your/rootCA.crt /etc/mycerts/
   sudo cp /path/to/your/rootCA.key /etc/mycerts/
   sudo chmod 644 /etc/mycerts/rootCA.crt
   sudo chmod 600 /etc/mycerts/rootCA.key
   
   # Deploy with Docker
   ./docker-deploy.sh
   ```

3. **Access the application**: `http://localhost:5000`

### Option 2: Manual Installation

1. **Clone or download the application files**:
   ```bash
   # Ensure you're in the project directory
   cd /home/compiler/cursorai/rootca
   ```

2. **Install Python dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Verify Root CA files exist**:
   ```bash
   ls -la /etc/mycerts/rootCA.crt /etc/mycerts/rootCA.key
   ```

4. **Create necessary directories**:
   ```bash
   sudo mkdir -p /tmp/csr_uploads /tmp/cert_processing
   sudo chmod 755 /tmp/csr_uploads /tmp/cert_processing
   sudo mkdir -p /var/log/rootca
   sudo chmod 755 /var/log/rootca
   ```

5. **Configure sudoers for OpenSSL operations** (optional but recommended):
   ```bash
   sudo visudo
   # Add the following line (replace 'username' with your actual username):
   username ALL=(ALL) NOPASSWD: /usr/bin/openssl x509 -req -in * -CA /etc/mycerts/rootCA.crt -CAkey /etc/mycerts/rootCA.key -CAcreateserial -out * -days * -sha256 -extfile *
   ```

## Configuration

### Root CA Configuration

The application expects the following files to exist:
- **Root CA Certificate**: `/etc/mycerts/rootCA.crt` (X.509 format)
- **Root CA Private Key**: `/etc/mycerts/rootCA.key` (Password protected with `P@ssw0rd`)

### Application Configuration

Key configuration parameters in `app.py`:
- `ROOT_CA_CERT_PATH`: Path to Root CA certificate
- `ROOT_CA_KEY_PATH`: Path to Root CA private key
- `UPLOAD_FOLDER`: Directory for uploaded CSR files
- `PROCESSING_FOLDER`: Directory for certificate processing
- `MAX_CONTENT_LENGTH`: Maximum file upload size (16MB)

## Usage

### Starting the Application

1. **Run the application**:
   ```bash
   python3 app.py
   ```

2. **Access the web interface**:
   Open your browser and navigate to `http://your-server-ip:5000`

3. **Login with default credentials**:
   - **Admin User**: `admin` / `admin123`
   - **Operator User**: `operator` / `operator123`

### Requesting a Certificate

1. **Enter FQHN**: Input the Fully Qualified Host Name (e.g., `cahttp.egypt.aast.edu`)
2. **Upload CSR**: Drag and drop or browse for your Certificate Signing Request file
3. **Generate Certificate**: Click "Generate Certificate" to start the process
4. **Download Archive**: Once processed, download the ZIP archive containing:
   - `server.crt` - Your signed certificate
   - `rootCA.crt` - The Root CA certificate

### Certificate Generation Process

The application performs the following steps automatically:

1. **Domain Extraction**: Extracts domain from FQHN (e.g., `egypt.aast.edu` from `cahttp.egypt.aast.edu`)
2. **SAN Extension Generation**: Creates extension file with Subject Alternative Names:
   ```
   subjectAltName=DNS:egypt.aast.edu,DNS:cahttp.egypt.aast.edu
   ```
3. **Certificate Signing**: Executes OpenSSL command:
   ```bash
   sudo openssl x509 -req -in /tmp/user1.csr -CA /etc/mycerts/rootCA.crt -CAkey /etc/mycerts/rootCA.key -CAcreateserial -out /tmp/server.crt -days 365 -sha256 -extfile /tmp/san.ext
   ```
4. **Archive Creation**: Packages certificate and Root CA into ZIP file
5. **Cleanup**: Removes temporary files after download

## API Endpoints

- `GET /`: Main certificate request form
- `POST /upload`: Handle file upload and certificate generation
- `GET /download/<session_id>`: Download certificate archive
- `GET /cleanup/<session_id>`: Clean up session files
- `GET /status`: System health check

## Security Considerations

- **File Validation**: Only .csr and .pem files are accepted
- **Size Limits**: Maximum file size of 16MB
- **Secure Filenames**: Uploaded files use secure filename generation
- **Session Management**: Unique session IDs prevent file conflicts
- **Automatic Cleanup**: Temporary files are automatically removed
- **Concurrent Access**: Thread-safe operations with file locking

## Logging

Application logs are written to:
- **File**: `/var/log/rootca/app.log`
- **Console**: Standard output

Log levels include INFO, WARNING, and ERROR for monitoring and debugging.

## Troubleshooting

### Common Issues

1. **Permission Denied for OpenSSL**:
   ```bash
   # Check if user has sudo access for OpenSSL
   sudo -l | grep openssl
   ```

2. **Root CA Files Not Found**:
   ```bash
   # Verify files exist and are readable
   ls -la /etc/mycerts/rootCA.*
   ```

3. **Directory Permissions**:
   ```bash
   # Ensure processing directories are writable
   ls -ld /tmp/csr_uploads /tmp/cert_processing
   ```

4. **Port Already in Use**:
   ```bash
   # Check if port 5000 is available
   sudo netstat -tlnp | grep :5000
   ```

### System Status Check

Visit `/status` endpoint to check system health:
```bash
curl http://localhost:5000/status
```

## Docker Deployment

The application includes comprehensive Docker support for easy deployment and scaling.

### Quick Docker Start

```bash
# Deploy with one command
./docker-deploy.sh
```

### Manual Docker Commands

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop application
docker-compose down
```

### Docker Features

- **Multi-stage build** for optimized image size
- **Health checks** for container monitoring
- **Volume mounts** for data persistence
- **Non-root user** for security
- **Read-only Root CA files** for security
- **Automatic startup** and restart policies

For detailed Docker deployment instructions, see [DOCKER.md](DOCKER.md).

## Production Deployment

For production deployment, consider:

1. **Docker Deployment** (Recommended):
   ```bash
   # Use Docker Compose with production configuration
   docker-compose -f docker-compose.prod.yml up -d
   ```

2. **Use a Production WSGI Server** (Manual deployment):
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

3. **Set up Reverse Proxy** (nginx):
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

4. **Enable HTTPS**: Use your Root CA to generate certificates for the web application

5. **Environment Variables**: Use environment variables for sensitive configuration

6. **Systemd Service**: Create a systemd service for automatic startup

## License

This project is provided as-is for educational and internal use purposes.

## Support

For issues and questions, check the application logs at `/var/log/rootca/app.log` and ensure all prerequisites are properly configured.

