# LuminaWAF: Premium Next-Gen Web Application Firewall

![LuminaWAF Logo](frontend/public/luminawaf_logo.png)

LuminaWAF is a high-performance, enterprise-grade Web Application Firewall (WAF) and SOC Dashboard designed for modern infrastructure. Built on top of **Envoy Proxy** and the **Coraza Wasm Filter**, LuminaWAF provides real-time threat detection, advanced rate limiting, and deep security intelligence with a stunning, premium interface.

## 🚀 Key Features

- **Envoy-Powered Gateway**: Leverages the power of Envoy Proxy for high-throughput, low-latency traffic handling.
- **OWASP CRS Integration**: Full support for the OWASP Core Rule Set (CRS) v4.0 for protection against SQLi, XSS, RCE, and more.
- **Premium SOC Dashboard**: A glassmorphic, dark-mode-first dashboard for real-time telemetry and management.
- **Dynamic xDS Configuration**: Real-time rule updates without proxy restarts via a custom control plane.
- **AI-Powered Analytics**: Integrated security digest and reporting for actionable threat intelligence.
- **Auto-Discovery Scanner**: Automatically fingerprints backend services to suggest optimal protection profiles.
- **Multi-Factor Authentication (MFA)**: Secure administrative access with TOTP.

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
docker-compose up --build -d
```

### 3. Default Credentials
- **URL**: `http://localhost:5173`
- **Username**: `superadmin`
- **Password**: `LuminaWAF2026!` (Change immediately upon login)

## 🛡 Security Policy
LuminaWAF is designed for security-first environments. All default secrets (MFA Issuers, API Keys) should be rotated in production environments via environment variables.

---

*LuminaWAF - Illuminating threats, shielding your digital assets.*
