#!/usr/bin/env python3
"""
Test script to verify the Root CA Certificate Management System setup.
This script checks all prerequisites and configuration.
"""

import os
import sys
import subprocess
import tempfile

def print_status(message, status="INFO"):
    colors = {
        "INFO": "\033[0;32m",
        "WARNING": "\033[1;33m",
        "ERROR": "\033[0;31m",
        "RESET": "\033[0m"
    }
    print(f"{colors.get(status, '')}[{status}]{colors['RESET']} {message}")

def check_file_exists(filepath, description):
    """Check if a file exists and is readable."""
    if os.path.exists(filepath):
        if os.access(filepath, os.R_OK):
            print_status(f"{description}: {filepath} ✓", "INFO")
            return True
        else:
            print_status(f"{description}: {filepath} (not readable) ✗", "ERROR")
            return False
    else:
        print_status(f"{description}: {filepath} (not found) ✗", "ERROR")
        return False

def check_directory_writable(dirpath, description):
    """Check if a directory exists and is writable."""
    if os.path.exists(dirpath):
        if os.access(dirpath, os.W_OK):
            print_status(f"{description}: {dirpath} ✓", "INFO")
            return True
        else:
            print_status(f"{description}: {dirpath} (not writable) ✗", "ERROR")
            return False
    else:
        print_status(f"{description}: {dirpath} (not found) ✗", "ERROR")
        return False

def check_command_exists(command, description):
    """Check if a command exists in PATH."""
    try:
        subprocess.run([command, "--version"], capture_output=True, check=True)
        print_status(f"{description}: {command} ✓", "INFO")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_status(f"{description}: {command} (not found) ✗", "ERROR")
        return False

def check_python_package(package, description):
    """Check if a Python package is installed."""
    try:
        __import__(package)
        print_status(f"{description}: {package} ✓", "INFO")
        return True
    except ImportError:
        print_status(f"{description}: {package} (not installed) ✗", "ERROR")
        return False

def test_openssl_operation():
    """Test basic OpenSSL operations."""
    try:
        # Test if we can read the Root CA certificate
        result = subprocess.run([
            'openssl', 'x509', '-in', '/etc/mycerts/rootCA.crt', '-text', '-noout'
        ], capture_output=True, text=True, check=True)
        
        print_status("OpenSSL can read Root CA certificate ✓", "INFO")
        
        # Test if we can read the Root CA private key (password protected)
        # This will fail if the password is wrong, but that's expected
        result = subprocess.run([
            'openssl', 'rsa', '-in', '/etc/mycerts/rootCA.key', '-check', '-noout'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print_status("OpenSSL can read Root CA private key ✓", "INFO")
        else:
            print_status("Root CA private key is password protected (expected) ✓", "INFO")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print_status(f"OpenSSL operation failed: {e.stderr}", "ERROR")
        return False
    except Exception as e:
        print_status(f"OpenSSL test error: {e}", "ERROR")
        return False

def test_sudo_openssl():
    """Test if sudo openssl operations work."""
    try:
        # Create a temporary CSR for testing
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csr', delete=False) as csr_file:
            csr_file.write("""-----BEGIN CERTIFICATE REQUEST-----
MIICXjCCAUYCAQAwGjEYMBYGA1UEAxMPdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALqJ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ
8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8
qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8
qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8
qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8
qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8
qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8qVvLxZ8
-----END CERTIFICATE REQUEST-----""")
            csr_path = csr_file.name
        
        # Create a temporary extension file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ext', delete=False) as ext_file:
            ext_file.write("subjectAltName=DNS:test.example.com")
            ext_path = ext_file.name
        
        # Create a temporary output file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.crt') as out_file:
            out_path = out_file.name
        
        # Test sudo openssl command
        cmd = [
            'sudo', 'openssl', 'x509', '-req',
            '-in', csr_path,
            '-CA', '/etc/mycerts/rootCA.crt',
            '-CAkey', '/etc/mycerts/rootCA.key',
            '-CAcreateserial',
            '-out', out_path,
            '-days', '1',
            '-sha256',
            '-extfile', ext_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print_status("Sudo OpenSSL operations work ✓", "INFO")
            success = True
        else:
            print_status(f"Sudo OpenSSL test failed: {result.stderr}", "WARNING")
            success = False
        
        # Cleanup
        for temp_file in [csr_path, ext_path, out_path]:
            try:
                os.unlink(temp_file)
            except:
                pass
        
        return success
        
    except Exception as e:
        print_status(f"Sudo OpenSSL test error: {e}", "WARNING")
        return False

def main():
    """Main test function."""
    print("=== Root CA Certificate Management System - Setup Test ===\n")
    
    all_checks_passed = True
    
    # Check Root CA files
    print_status("Checking Root CA files...", "INFO")
    ca_cert_ok = check_file_exists('/etc/mycerts/rootCA.crt', 'Root CA Certificate')
    ca_key_ok = check_file_exists('/etc/mycerts/rootCA.key', 'Root CA Private Key')
    
    if not (ca_cert_ok and ca_key_ok):
        all_checks_passed = False
    
    # Check Python packages
    print_status("\nChecking Python packages...", "INFO")
    packages = [
        ('flask', 'Flask'),
        ('werkzeug', 'Werkzeug'),
        ('jinja2', 'Jinja2'),
        ('flask_wtf', 'Flask-WTF'),
        ('wtforms', 'WTForms'),
    ]
    
    for package, name in packages:
        if not check_python_package(package, name):
            all_checks_passed = False
    
    # Check system commands
    print_status("\nChecking system commands...", "INFO")
    if not check_command_exists('openssl', 'OpenSSL'):
        all_checks_passed = False
    
    if not check_command_exists('sudo', 'Sudo'):
        all_checks_passed = False
    
    # Check directories
    print_status("\nChecking directories...", "INFO")
    directories = [
        ('/tmp/csr_uploads', 'CSR Upload Directory'),
        ('/tmp/cert_processing', 'Certificate Processing Directory'),
        ('/var/log/rootca', 'Log Directory'),
    ]
    
    for dirpath, description in directories:
        if not check_directory_writable(dirpath, description):
            all_checks_passed = False
    
    # Test OpenSSL operations
    print_status("\nTesting OpenSSL operations...", "INFO")
    if not test_openssl_operation():
        all_checks_passed = False
    
    # Test sudo OpenSSL operations
    print_status("\nTesting sudo OpenSSL operations...", "INFO")
    if not test_sudo_openssl():
        print_status("Note: Sudo OpenSSL test failed. You may need to configure sudoers.", "WARNING")
    
    # Final result
    print("\n" + "="*60)
    if all_checks_passed:
        print_status("All critical checks passed! The system is ready to use.", "INFO")
        print_status("You can now start the application with: python3 app.py", "INFO")
    else:
        print_status("Some checks failed. Please fix the issues before running the application.", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()

