# Secure Document Management System

## Overview
This project is a secure web-based document management system built with Flask. It supports user authentication, role-based access control (RBAC), encrypted file storage, and audit logging. The system is designed with security-first principles including session management, input validation, and HTTPS enforcement.

## Features
- User registration and login with bcrypt password hashing
- Role-based access control (Admin, User, Guest)
- Secure session management with token-based authentication
- Encrypted file storage using Fernet encryption
- Document versioning and sharing system
- Security and access logging
- Protection against common web attacks (XSS, IDOR, CSRF, etc.)

## Project Structure
- app.py # Main Flask application (routes + security logic)
- classes.py # Core infrastructure classes
- data/ # User, session, and document storage (JSON)
- data/files/ # Encrypted document storage
- logs/ # Security and access logs
- templates/ # Frontend HTML pages
- static/js # Frontend JS (login.js, dashboard.js)
- static/css # Frontend CSS (style.css)


## Setup Instructions

### 1. Clone the repository
```bash
git clone <repo-url>
cd <project-folder>
```

### 2. Generate SSL certificate (for HTTPS)
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

### 3. Run the application
```bash
python app.py
```

### 4. Open application in browser
```bash
HTTP: http://localhost:5000
HTTPS: https://localhost:5001
```

###5. Login with ADMIN account
```bash
Username: admin
Password: Asdfghjkl12#
```
