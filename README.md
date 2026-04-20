# LuminaWAF: Premium Next-Gen Web Application Firewall

![LuminaWAF Logo](frontend/public/luminawaf_logo.png)

LuminaWAF is a high-performance, enterprise-grade Web Application Firewall (WAF) and SOC Dashboard designed for modern infrastructure. Built on top of **Envoy Proxy** and the **Coraza Wasm Filter**, LuminaWAF provides real-time threat detection, advanced rate limiting, and deep security intelligence with a stunning, premium interface.

![Dashboard Preview](assets/Dashboard.gif)

## 🚀 Key Features

- **Envoy-Powered Gateway**: Leverages the power of Envoy Proxy for high-throughput, low-latency traffic handling.
- **OWASP CRS Integration**: Full support for the OWASP Core Rule Set (CRS) v4.0 for protection against SQLi, XSS, RCE, and more.
- **Premium SOC Dashboard**: A glassmorphic, dark-mode-first dashboard for real-time telemetry and management.
- **Dynamic xDS Configuration**: Real-time rule updates without proxy restarts via a custom control plane.
- **AI-Powered Analytics**: Integrated security digest and reporting for actionable threat intelligence.
- **Auto-Discovery Scanner**: Automatically fingerprints backend services to suggest optimal protection profiles.
- **Multi-Factor Authentication (MFA)**: Secure administrative access with TOTP.

## 🏗️ System Architecture & Traffic Flow

![Architecture Flow](assets/flow.png)

LuminaWAF is designed to sit internally, acting as the intelligent security gateway directly before your designated containerized applications. 

## 📸 Screenshots

### 🛡️ Authentication & MFA
Secure login panel with mandatory MFA and logo branding.
![Login Screen](assets/login.png)
![Login with MFA](assets/login%20with%20MFA.png)

### 🖥️ Virtual Servers Management
Add and manage multiple virtual servers dynamically mapping to Envoy endpoints.
![Virtual Servers](assets/Virtual%20Servers.png)
![Add Virtual Server](assets/add%20virtual%20servers.png)

### ⚙️ Threat Engine Tuning
Take precise control over edge configurations without ever touching raw configurations.
**Core Rules:**
![Core Rules](assets/waf%20settings%20core.png)

**Application Configurations:**
![Application Configurations](assets/waf%20settings%20Apps.png)

**DDoS & Mitigation:**
![DDoS Protection](assets/ddos.png)

**Exclusions & WAF Behavior Modes:**
![Exclusions & Status](assets/waf%20settings%20exclusions%20and%20waf%20status.png)

### 🔍 Real-Time Diagnostics & Analytics
Review blocked packets, exact JSON payloads, and WAF intercepts organically.
![Security Intelligence](assets/security%20intel.png)
![Logs and Audits](assets/logs.png)

### 👥 Strict Access Control
Manage user access and roles directly via the control plane.
![Users Management](assets/users.png)

## 🛠 Tech Stack

- **Frontend**: React, TypeScript, Tailwind CSS, Lucide Icons.
- **Backend**: FastAPI (Python), PostgreSQL, SQLAlchemy.
- **Proxy**: Envoy Proxy (v1.29+), Coraza WAF (Proxy-Wasm).
- **Automation**: Docker, Docker Compose, Lua (Envoy filters).

## 🚦 Quick Start

### 1. Prerequisites
- Docker & Docker Compose
- Node.js (for local frontend development)
- Python 3.10+ (for local backend development)

### 2. Deployment
```bash
docker compose up --build -d
```

### 3. Default Credentials
- **URL**: `http://localhost:5173`
- **Username**: `superadmin`
- **Password**: `ChangeMeNow123!` 

## 🛡 Security Policy
LuminaWAF is designed for security-first environments. All default secrets (MFA Issuers, API Keys) should be rotated in production environments via environment variables.

---

*LuminaWAF - Illuminating threats, shielding your digital assets.*
