#!/usr/bin/env python3
"""
User Management Script for Root CA Certificate Management System

This script allows administrators to manage user accounts and passwords.
"""

import hashlib
import json
import os
import sys
from getpass import getpass

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    """Load users from the application file."""
    try:
        with open('app.py', 'r') as f:
            content = f.read()
        
        # Extract USERS dictionary from app.py
        start = content.find('USERS = {')
        if start == -1:
            print("Error: Could not find USERS dictionary in app.py")
            return {}
        
        # Find the end of the USERS dictionary
        brace_count = 0
        end = start
        for i, char in enumerate(content[start:], start):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break
        
        users_dict_str = content[start:end]
        
        # Parse the dictionary (this is a simple approach)
        # In production, you'd want to use a proper configuration file
        users = {}
        exec(users_dict_str, {'hashlib': hashlib}, {'users': users})
        return users['USERS']
        
    except Exception as e:
        print(f"Error loading users: {e}")
        return {}

def save_users(users):
    """Save users back to app.py."""
    try:
        with open('app.py', 'r') as f:
            content = f.read()
        
        # Find and replace the USERS dictionary
        start = content.find('USERS = {')
        if start == -1:
            print("Error: Could not find USERS dictionary in app.py")
            return False
        
        # Find the end of the USERS dictionary
        brace_count = 0
        end = start
        for i, char in enumerate(content[start:], start):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break
        
        # Generate new USERS dictionary
        new_users_dict = "USERS = {\n"
        for username, info in users.items():
            new_users_dict += f"    '{username}': {{\n"
            new_users_dict += f"        'password_hash': '{info['password_hash']}',\n"
            new_users_dict += f"        'role': '{info['role']}',\n"
            new_users_dict += f"        'last_login': {repr(info.get('last_login'))}\n"
            new_users_dict += f"    }},\n"
        new_users_dict += "}\n"
        
        # Replace the old dictionary with the new one
        new_content = content[:start] + new_users_dict + content[end:]
        
        # Write back to file
        with open('app.py', 'w') as f:
            f.write(new_content)
        
        return True
        
    except Exception as e:
        print(f"Error saving users: {e}")
        return False

def list_users(users):
    """List all users."""
    print("\nCurrent Users:")
    print("-" * 50)
    for username, info in users.items():
        role = info.get('role', 'unknown')
        last_login = info.get('last_login', 'Never')
        print(f"Username: {username}")
        print(f"Role: {role}")
        print(f"Last Login: {last_login}")
        print("-" * 50)

def add_user(users):
    """Add a new user."""
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty")
        return users
    
    if username in users:
        print(f"User '{username}' already exists")
        return users
    
    role = input("Enter role (admin/operator): ").strip().lower()
    if role not in ['admin', 'operator']:
        print("Role must be 'admin' or 'operator'")
        return users
    
    password = getpass("Enter password: ")
    if not password:
        print("Password cannot be empty")
        return users
    
    confirm_password = getpass("Confirm password: ")
    if password != confirm_password:
        print("Passwords do not match")
        return users
    
    users[username] = {
        'password_hash': hash_password(password),
        'role': role,
        'last_login': None
    }
    
    print(f"User '{username}' added successfully")
    return users

def change_password(users):
    """Change a user's password."""
    username = input("Enter username: ").strip()
    if username not in users:
        print(f"User '{username}' not found")
        return users
    
    password = getpass("Enter new password: ")
    if not password:
        print("Password cannot be empty")
        return users
    
    confirm_password = getpass("Confirm new password: ")
    if password != confirm_password:
        print("Passwords do not match")
        return users
    
    users[username]['password_hash'] = hash_password(password)
    print(f"Password for user '{username}' changed successfully")
    return users

def delete_user(users):
    """Delete a user."""
    username = input("Enter username to delete: ").strip()
    if username not in users:
        print(f"User '{username}' not found")
        return users
    
    confirm = input(f"Are you sure you want to delete user '{username}'? (yes/no): ").strip().lower()
    if confirm == 'yes':
        del users[username]
        print(f"User '{username}' deleted successfully")
    else:
        print("User deletion cancelled")
    
    return users

def main():
    """Main function."""
    print("Root CA Certificate Management System - User Management")
    print("=" * 60)
    
    # Load current users
    users = load_users()
    if not users:
        print("Error: Could not load users. Make sure app.py exists and contains a USERS dictionary.")
        sys.exit(1)
    
    while True:
        print("\nUser Management Options:")
        print("1. List users")
        print("2. Add user")
        print("3. Change password")
        print("4. Delete user")
        print("5. Save changes and exit")
        print("6. Exit without saving")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            list_users(users)
        elif choice == '2':
            users = add_user(users)
        elif choice == '3':
            users = change_password(users)
        elif choice == '4':
            users = delete_user(users)
        elif choice == '5':
            if save_users(users):
                print("Changes saved successfully!")
                print("Note: You may need to restart the application for changes to take effect.")
            else:
                print("Error saving changes!")
            break
        elif choice == '6':
            print("Exiting without saving changes...")
            break
        else:
            print("Invalid choice. Please enter 1-6.")

if __name__ == "__main__":
    main()
