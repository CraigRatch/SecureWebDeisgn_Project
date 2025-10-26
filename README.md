# SecureWebDesign_Project

A secure Flask web app built for the Secure Web Page module, implementing OWASP Top 10 protections including authentication, session management, SQL injection, XSS, XXE, CAPTCHA, RBAC, and secure cookie handling. Developed by Craig Ratchford as part of a university project focused on secure web design.

---

# 🛡️ Secure Web Application (SWA) – Personnel, Equipment & Taskings Management System

A secure Flask-based web application developed by **Craig Ratchford (24107358)**. This project implements key security principles from the **OWASP Top 10** to protect against common web vulnerabilities.

## 🔍 Project Overview

This system is designed for military personnel to manage:

- 👤 **User Profiles** – View and update personal information
- 🛠️ **Equipment Inventory** – Add, update, delete, and order stock
- 📋 **Task Assignments** – Create and manage operational taskings
- 🔐 **Role-Based Access Control (RBAC)** – Admin, Officer, and Soldier roles with distinct permissions

## 🔒 Security Features Implemented

- **Authentication & Password Security**
  - Bcrypt hashing with salting
  - Password strength enforcement
  - Secure password change functionality

- **Session Management**
  - Session tokens with unique identifiers
  - Session timeout and auto-logout
  - Secure cookie handling (Secure, HttpOnly, SameSite)

- **Access Control**
  - Role-Based Access Control (RBAC)
  - Strict redirects using `url_for()`
  - No public registration (admin-only user creation)

- **Input Validation & Protection**
  - Parameterized SQL queries (SQL Injection prevention)
  - CSRF protection using Flask-WTF
  - CAPTCHA integration (Google reCAPTCHA)

- **Monitoring & Logging**
  - Login history tracking (ArmyNo, Role, Timestamp)
  - Penetration testing using OWASP ZAP with no high-risk vulnerabilities found

## 🧰 Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript (Jinja2 templates)
- **Database**: SQLite
- **Security Tools**: Flask-WTF, Flask-Limiter, bcrypt, Google reCAPTCHA, OWASP ZAP

## 📦 Required Packages

Install the following packages in your Python environment:

### Flask Core
- `click`
- `Flask`
- `itsdangerous`
- `Jinja2`
- `MarkupSafe`
- `Werkzeug`

### Flask Extensions
- `Flask-Login`
- `Flask-Migrate`
- `Flask-Script`
- `Flask-SQLAlchemy`
- `Flask-WTF`
- `Flask-Bcrypt`

## 🚀 Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SecureWebDesign_Project.git
   cd SecureWebDesign_Project
