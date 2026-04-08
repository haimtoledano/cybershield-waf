# 🛡️ CyberShield WAF

**CyberShield** is an advanced, high-performance Web Application Firewall (WAF) Control Plane built for modern cloud and on-premise infrastructure. It deeply integrates an Envoy-based data plane with a robust Python/FastAPI backend and a premium React dashboard, delivering enterprise-grade web security management with ease.

![Virtual Servers Dashboard](assets/Virtual%20Servers.png)

## 🌟 Key Features

* **Real-time Traffic Monitoring**: Live stream of network events, payloads, and threat blocks down to the millisecond.
* **Granular Threat Engine Tuning**: Activate advanced heuristics per Virtual Server.
  * *Protocol Enforcement & HTTP Attack Prevention*
  * *RCE, SQLi, XSS, and LFI Protections*
  * *Scanner Detection & Data Leakage Prevention*
* **Application-Specific Profiles**: Hand-tailored profiles to optimize WAF behavior for platforms like WordPress, Nextcloud, Drupal, and Node.js.
* **Role-Based Access Control (RBAC)**: Secure user separation (`admin` vs `viewer`) protecting infrastructure altering endpoints.
* **Mandatory Multi-Factor Authentication (MFA)**: Uncompromising authentication flow ensuring robust protection of the control plane itself.
* **Micro-second Envoy Proxy integration**: The backend translates UI configurations into Envoy's LDS/CDS mechanisms in real time.
* **Bidirectional Custom Headers Integration**: Dynamically inject custom HTTP Request and Response headers seamlessly via Envoy's engine.

## 📸 Screenshots

### 🛡️ Authentication & MFA
Secure login panel with mandatory MFA and logo branding.
![Login Screen](assets/login.png)

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

**Exclusions & WAF Behavior Modes:**
![Exclusions & Status](assets/waf%20settings%20exclusions%20and%20waf%20status.png)

### 🔍 Real-Time Diagnostics
Review blocked packets, exact JSON payloads, and WAF intercepts organically.
![Logs and Audits](assets/logs.png)

### 👥 Strict Access Control
Manage user access and roles directly via the control plane.
![Users Management](assets/users.png)

## 🛠️ Technology Stack

| Layer       | Technologies                                   |
| ----------- | ---------------------------------------------- |
| **Frontend**| React, Vite, Tailwind CSS, Lucide Icons        |
| **Backend** | Python, FastAPI, SQLAlchemy, PyJWT, PyOTP      |
| **Data**    | PostgreSQL                                     |
| **Proxy**   | Envoy, Coraza (WASM)                           |

## 🚀 Getting Started

### Prerequisites
* Docker and Docker Compose
* Node.js v18+ (for local frontend development)
* Python 3.10+ (for local backend development)

### Deployment
To spin up the entire isolated stack:
```bash
docker compose up -d --build
```
This deploys the Envoy data-plane, Postgres database, logging workers, backend API, and frontend control plane.

### Initial Setup
1. Upon first run, the system bootstraps a superadmin. Navigate to `http://localhost:5173`.
2. Initial credentials: `admin` / `CyberShield2026!`.
3. You will be immediately prompted to link your Authenticator app via QR code.
4. Begin mapping Virtual Servers and routing HTTP traffic through Envoy (Default Port mappings via Docker).

## 📄 Licensing

CyberShield's control plane is proprietary software. It utilizes several powerful open-source packages in its runtime environment (such as Envoy Proxy, FastAPI, and React). Please refer to the `THIRD-PARTY-NOTICES.txt` file for required attribution and OSS license compliance.
