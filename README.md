# 🛡️ Automated Web Security Scanner

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0.3-green.svg)](https://flask.palletsprojects.com/)
[![Pytest 102 Passed](https://img.shields.io/badge/Tests-102%20Passed-brightgreen.svg)](https://pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Theme: Pure Black](https://img.shields.io/badge/Theme-Pure%20Black%20%23000000-black.svg)](#interactive-dashboard)

> **Automated inspection of HTTP security headers and Cross-Origin Resource Sharing (CORS) configurations.**  
> A cybersecurity tool designed for identifying web misconfigurations, evaluating risk, and exporting comprehensive security audit reports.

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Project Architecture & Directory Structure](#project-architecture--directory-structure)
- [Prerequisites & Installation](#prerequisites--installation)
- [Running Locally](#running-locally)
- [Running Automated Tests](#running-automated-tests)
- [Interactive Dashboard & Pure-Black Theme](#interactive-dashboard)
- [Downloading Reports (JSON, CSV, PDF)](#downloading-reports)
- [Security Features & SSRF Protections](#security-features--ssrf-protections)
- [Sample Findings & Remediation](#sample-findings--remediation)
- [Deployment (Render)](#deployment-render)
- [Limitations & Responsible Use Disclaimer](#limitations--responsible-use-disclaimer)

---

## 🎯 Project Overview

The **Automated Web Security Scanner** is a defensive cybersecurity assessment application that performs passive, non-authenticated audits of public web applications. It automates the inspection of HTTP security response headers and CORS directives, computes transparent rule-based risk ratings, and generates downloadable client-ready reports in **JSON**, **CSV**, and **PDF** formats.

Developed with **Python 3**, **Flask**, and **ReportLab**, the tool provides both a RESTful scanning API and a pure-black cybersecurity dashboard.

---

## 🔍 Problem Statement

Misconfigured security headers and overly permissive CORS policies represent some of the most prevalent vulnerabilities across modern web applications. 
- The absence of a **Content Security Policy (CSP)** leaves applications susceptible to Cross-Site Scripting (XSS) and code injection.
- Missing **Strict-Transport-Security (HSTS)** permits SSL-stripping and man-in-the-middle downgrade attacks.
- Omission of **X-Content-Type-Options** allows browsers to perform MIME-type sniffing on untrusted files.
- Permissive **CORS** configurations (such as reflecting `Access-Control-Allow-Origin: *` alongside credential permissions) expose sensitive user sessions to unauthorized third-party sites.

This project delivers an automated, defensive tool that pinpoints these risks and provides clear remediation instructions.

---

## 🎯 Objectives

1. **Automate HTTP Security Header Auditing:** Inspect CSP, HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.
2. **Detect CORS Weaknesses:** Audit Origin, Credentials, Methods, and Allowed Headers.
3. **Enforce SSRF Defenses:** Protect the scanner against loopback, private IP ranges, link-local addresses, and cloud metadata services.
4. **Transparent Risk Scoring:** Categorize issues into High, Medium, Low, or Informational severities.
5. **Interactive Black-Themed GUI:** Provide a single-page dashboard with status indicators and interactive tabs.
6. **Multi-Format Exporting:** Generate JSON, CSV, and formal vector-styled PDF reports.
7. **Comprehensive Test Suite:** Maintain 102 automated Pytest unit and integration tests with 100% mocked HTTP requests.

---

## 🚀 Key Features

| Feature | Description |
|---|---|
| 🛡️ **SSRF Protection** | Validates URLs, resolves DNS, and blocks private IPs (RFC 1918), loopback, link-local, and cloud metadata (169.254.169.254). |
| 🔒 **Header Inspection** | Context-aware assessment of 5 critical security response headers. |
| 🌐 **CORS Analysis** | Passive evaluation of cross-origin rules, wildcards, and credential configurations. |
| ⚖️ **Rule-Based Risk Engine** | Transparent severity mapping with evidence, impact, and remediation code. |
| 🖥️ **Pure-Black Theme** | Minimalist aesthetic (`#000000` base, `#00ff88` accents) engineered for SOC and auditor workflows. |
| 📑 **Report Exports** | One-click downloads for structured JSON, tabular CSV, and styled PDF reports. |
| 🧪 **102 Automated Tests** | Deterministic Pytest suite with zero external network dependencies. |

---

## 💻 Technology Stack

- **Backend:** Python 3.10+ / Flask 3.0.3
- **HTTP Client:** Requests 2.32.3
- **PDF Generation:** ReportLab 4.2.2
- **Testing:** Pytest 8.3.3
- **Production WSGI:** Gunicorn 22.0.0
- **Frontend:** Semantic HTML5, CSS3 (pure-black design), Vanilla JavaScript (ES6)

---

## 📁 Project Architecture & Directory Structure

```
automated-web-security-scanner/
│
├── app.py                      # Flask application and route controllers
├── requirements.txt            # Pinned project dependencies
├── Procfile                    # Render / Gunicorn startup definition
├── README.md                   # Complete documentation
├── LICENSE                     # MIT License
├── .gitignore                  # Git exclusion rules
├── Project_Report.pdf          # Professional bootcamp capstone PDF report
│
├── scanner/                    # Core security scanner package
│   ├── __init__.py             # Main scan orchestrator
│   ├── validator.py            # URL validation & SSRF defense engine
│   ├── headers.py              # HTTP security header analysis module
│   ├── cors.py                 # Cross-Origin Resource Sharing analysis module
│   ├── risk_assessment.py      # Rule-based severity & remediation engine
│   └── report_generator.py     # JSON, CSV, and ReportLab PDF exporters
│
├── templates/
│   └── index.html              # Main dashboard interface
│
├── static/
│   ├── css/
│   │   └── style.css           # Pure-black theme stylesheet (#000000 base)
│   └── js/
│       └── script.js           # Frontend interactions, AJAX, tab controls
│
├── tests/                      # Automated Pytest suite (102 tests)
│   ├── __init__.py
│   ├── test_validator.py       # SSRF & URL validation tests (26 tests)
│   ├── test_headers.py         # Security headers inspection tests (32 tests)
│   ├── test_cors.py            # CORS policy tests (24 tests)
│   └── test_app.py             # Flask route & integration tests (20 tests)
│
├── docs/
│   ├── project_report.md       # Project report documentation (Markdown)
│   ├── Project_Report.pdf      # Compiled formal PDF report
│   └── generate_bootcamp_report.py # Automated report generation script
│
├── screenshots/
│   └── .gitkeep
│
└── reports/
    └── .gitkeep
```

---

## ⚙️ Prerequisites & Installation

### Prerequisites
- Python 3.10 or higher
- Git
- Windows PowerShell (or macOS / Linux terminal)

### 1. Clone the Repository
```powershell
git clone https://github.com/ZoyaTahareen/Web-Security-Scanner.git
cd Web-Security-Scanner
```

### 2. Create and Activate Virtual Environment
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```
*(On macOS/Linux: `source .venv/bin/activate`)*

### 3. Install Dependencies
```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## 🖥️ Running Locally

Start the local Flask application:
```powershell
python -m flask --app app run
```

Then navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Running Automated Tests

The test suite covers URL validation, SSRF protections, header rules, CORS heuristics, and Flask download routes. All external HTTP requests are mocked.

Run all 102 tests:
```powershell
python -m pytest tests/ -v
```

Expected output:
```
tests/test_cors.py ........................                              [ 23%]
tests/test_headers.py ................................                  [ 55%]
tests/test_validator.py ..........................                      [ 80%]
tests/test_app.py ....................                                  [100%]

======================= 102 passed, 2 warnings in 1.10s =======================
```

Run specific test modules:
```powershell
python -m pytest tests/test_validator.py -v
python -m pytest tests/test_headers.py -v
python -m pytest tests/test_cors.py -v
python -m pytest tests/test_app.py -v
```

---

## 🎨 Interactive Dashboard

The dashboard is built with a **pure-black theme** (`#000000` base) designed specifically for security professionals:
- **Base Canvas:** `#000000` pure black background with deep charcoal elevations (`#0a0a0a`, `#111111`).
- **Accent Highlighting:** High-contrast electric green (`#00ff88`) for active tabs, status indicators, and success states.
- **Severity Badging:** Color-coded badges for High (`#ff4444`), Medium (`#ffaa00`), Low (`#00c8ff`), and Info (`#888888`).
- **Tabbed Layout:** Effortlessly switch between **Security Headers**, **CORS Analysis**, **Findings & Remediation**, and **Reports**.

---

## 📥 Downloading Reports

Following a target scan, auditors can download assessment findings in three distinct formats:
1. **JSON Report (`/report/json`):** Machine-readable structured output including raw headers and timestamps for ingestion into SIEM or vulnerability management tools.
2. **CSV Report (`/report/csv`):** Tabular format compatible with spreadsheet software (Excel, Google Sheets) for management tracking.
3. **PDF Report (`/report/pdf`):** Formal security assessment document generated on the fly via ReportLab.

---

## 🛡️ Security Features & SSRF Protections

To protect the host server from Server-Side Request Forgery (SSRF) when executing outbound probes, `scanner/validator.py` enforces rigorous checks:
- **Scheme Validation:** Only `http://` and `https://` are permitted.
- **Host Blocking:** `localhost`, `127.0.0.1`, and `[::1]` are blocked.
- **DNS Resolution & Subnet Inspection:** Resolves hostnames to IP addresses and rejects:
  - Private subnets (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Loopback range (`127.0.0.0/8`)
  - Link-local subnets (RFC 3927: `169.254.0.0/16`)
  - Cloud metadata endpoints (`metadata.google.internal`, `169.254.169.254`)

---

## 📑 Sample Findings & Remediation

| Issue | Severity | Risk Explanation | Recommended Remediation |
|---|---|---|---|
| **Missing Content-Security-Policy** | `HIGH` | Leaves application vulnerable to XSS and content injection attacks. | Deploy header: `Content-Security-Policy: default-src 'self'; script-src 'self';` |
| **Missing Strict-Transport-Security** | `MEDIUM` | Unencrypted initial connections can be intercepted via SSL stripping. | Deploy header: `Strict-Transport-Security: max-age=31536000; includeSubDomains;` |
| **Absent X-Content-Type-Options** | `MEDIUM` | Browsers may interpret untrusted content as executable script (MIME sniffing). | Deploy header: `X-Content-Type-Options: nosniff` |
| **Permissive CORS Wildcard** | `REVIEW` | Wildcard origin allows external websites to make cross-origin reads. | Restrict `Access-Control-Allow-Origin` to trusted origins if endpoint serves sensitive data. |

---

## ☁️ Deployment (Render)

This repository includes a `Procfile` configured for deployment on [Render](https://render.com):

1. Link your GitHub repository (`https://github.com/ZoyaTahareen/Web-Security-Scanner`) to Render.
2. Create a new **Web Service**.
3. Configure the start command:
   ```bash
   gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30
   ```
4. Set the environment variable `SECRET_KEY` to a secure random string.

---

## ⚖️ Limitations & Responsible Use Disclaimer

- **Passive Assessment Only:** This scanner performs passive observation of HTTP response headers. It does not perform active exploit verification or credential testing.
- **Context Dependent:** Findings indicate the presence or absence of standard configurations. Practical exploitability depends on the architecture and sensitivity of the application.
- **Authorized Testing Only:** This tool is intended for educational purposes and assessing systems you own or have explicit authorization to audit.

---

**Author:** [Zoya Tahareen](https://github.com/ZoyaTahareen)  
**Repository:** [Web-Security-Scanner](https://github.com/ZoyaTahareen/Web-Security-Scanner)  
**License:** [MIT](LICENSE)
