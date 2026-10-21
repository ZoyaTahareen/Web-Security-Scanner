# 🛡️ Automated Web Security Scanner: Project Report

**Project Title:** Automated Web Security Scanner for Security Headers and CORS Misconfigurations  
**Candidate / Author:** Zoya Tahareen  
**GitHub:** [github.com/ZoyaTahareen/Web-Security-Scanner](https://github.com/ZoyaTahareen/Web-Security-Scanner)  
**Submission:** Cybersecurity Bootcamp Capstone Project  
**Date:** October 2026  
**Test Suite Verification:** 102 Passed, 0 Failures (Pytest)

---

## 1. Abstract & Introduction

The **Automated Web Security Scanner** is a defensive cybersecurity tool engineered to identify common, high-impact web misconfigurations by evaluating HTTP security response headers and Cross-Origin Resource Sharing (CORS) policies. 

Modern web architectures rely heavily on browser-enforced security boundaries. However, development teams frequently deploy web applications without essential defensive headers or with inadvertently permissive cross-origin policies. This scanner automates passive reconnaissance against target URLs, assigns deterministic risk severity ratings (High, Medium, Low, Informational), provides technical explanations with remediation code snippets, and allows downloading reports in JSON, CSV, and PDF formats through a responsive pure-black themed cybersecurity dashboard.

---

## 2. Problem Statement & Industry Context

Web security vulnerabilities often stem from configuration oversights rather than obscure software bugs:
- **Missing CSP:** Enables script injection and Cross-Site Scripting (XSS).
- **Missing HSTS:** Leaves traffic vulnerable to SSL stripping and man-in-the-middle attacks.
- **Absent X-Content-Type-Options:** Allows MIME confusion and drive-by malware execution.
- **Missing Clickjacking Protection (X-Frame-Options / frame-ancestors):** Allows framing inside malicious UI overlays.
- **Permissive CORS:** Misconfigured `Access-Control-Allow-Origin: *` or dynamically reflected origins with credentials allow unauthorized domains to read authenticated user payloads.

This tool solves the need for an accessible, defensive scanner that incorporates SSRF defense, automated risk categorization, and multi-format reporting.

---

## 3. Project Objectives

1. **Automate Security Header Inspection:** Inspect 5 fundamental HTTP response headers:
   - `Content-Security-Policy` (CSP)
   - `Strict-Transport-Security` (HSTS)
   - `X-Content-Type-Options`
   - `X-Frame-Options`
   - `Referrer-Policy`
2. **Analyze CORS Misconfigurations:** Inspect `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers`.
3. **Enforce Defense-in-Depth SSRF Protections:** Block local addresses (`127.0.0.1`, `[::1]`), private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local IPs (`169.254.0.0/16`), and cloud metadata APIs (`metadata.google.internal`, `169.254.169.254`).
4. **Transparent Risk Scoring:** Map findings to High, Medium, Low, and Informational tiers based on clear, deterministic rules.
5. **Interactive Dashboard:** Pure-black themed UI with animated status badges, dynamic tabs, and instant feedback.
6. **Multi-Format Report Generation:** Generate JSON, CSV, and formal PDF security audit reports.
7. **Automated Testing Suite:** 102 automated tests using Pytest with 100% mocked network requests to verify edge cases and reliability.

---

## 4. System Architecture & Tech Stack

```
[Client Web Browser]
        │
        ▼ (HTTP / AJAX)
[Flask Application Controller (app.py)]
        │
        ├─► [Validator (validator.py)] ────► [SSRF & DNS Checks (ipaddress, socket)]
        │
        ├─► [Network Prober (requests)] ───► [Passive HTTP GET Probe]
        │
        ├─► [Headers Engine (headers.py)] ─► [Evaluate 5 Security Headers]
        │
        ├─► [CORS Engine (cors.py)] ───────► [Evaluate 4 CORS Directives]
        │
        ├─► [Risk Engine (risk_assessment.py)] ─► [Deterministic Severity Mapping]
        │
        └─► [Report Engine (report_generator.py)] ──► [JSON, CSV & ReportLab PDF Exporters]
```

### Technology Breakdown
- **Backend Framework:** Python 3.12 + Flask 3.0.3
- **HTTP Engine:** Requests 2.32.3 (enforcing timeouts, TLS verification, redirect validation)
- **PDF Engine:** ReportLab 4.2.2 (canvas-based vector styling and typography)
- **Testing Engine:** Pytest 8.3.3 (102 tests, mocked responses)
- **Production Server:** Gunicorn 22.0.0
- **Frontend Stack:** HTML5, Modern CSS3 (pure black theme `#000000`, cyber green accents `#00ff88`), Vanilla JavaScript (ES6)

---

## 5. Implementation Details

### 5.1 URL Validator & SSRF Prevention
Located in `scanner/validator.py`:
- Enforces `http` and `https` schemes only.
- Strips trailing fragments and sanitizes target paths.
- Resolves DNS hostnames and verifies each IP address using Python's `ipaddress` module.
- Rejects loopback addresses, RFC 1918 private subnets, link-local addresses, and cloud provider metadata IPs (`169.254.169.254`).

### 5.2 Security Headers Engine
Located in `scanner/headers.py`:
- Context-aware inspection for 5 critical headers.
- Evaluates `Strict-Transport-Security` specifically in the context of HTTPS, noting that HSTS is not applicable over plain HTTP.
- Detects weakened CSP directives such as `'unsafe-inline'` and `'unsafe-eval'`.
- Validates `X-Content-Type-Options: nosniff` strictly.
- Recognizes modern `CSP frame-ancestors` as compensation for missing `X-Frame-Options`.

### 5.3 CORS Analysis Engine
Located in `scanner/cors.py`:
- Analyzes `Access-Control-Allow-Origin` for wildcards (`*`) and `null` origins.
- Flags dangerous combinations of credentials (`Access-Control-Allow-Credentials: true`) paired with dynamic reflection.
- Audits overly permissive methods (`PUT`, `DELETE`) and broad allowed headers.

### 5.4 Risk Assessment & Severity Heuristics
Located in `scanner/risk_assessment.py`:
- **High:** Critical missing protections (e.g., missing CSP and frame protection on web interfaces, dangerous CORS credential reflection).
- **Medium:** Missing HSTS on HTTPS, absent X-Content-Type-Options, overly permissive Referrer-Policy.
- **Low:** Sub-optimal configurations (e.g., HSTS `max-age` less than 1 year).
- **Informational:** Validated passing configurations, informational CORS notices.

### 5.5 Report Generator
Located in `scanner/report_generator.py`:
- **JSON:** Complete machine-readable data structure for automated pipeline integration.
- **CSV:** Formatted table of findings with titles, severities, evidence, and recommendations.
- **PDF:** Styled, formal report generated using ReportLab with custom styling and timestamps.

---

## 6. Testing Methodology & Verification

The project includes 102 comprehensive tests in the `tests/` directory:
- `tests/test_validator.py` (26 tests): Valid schemes, invalid schemes, DNS failures, SSRF loopback/private/link-local/metadata IP rejection.
- `tests/test_headers.py` (32 tests): Header presence, missing headers, value validation, directive parsing, case-insensitivity.
- `tests/test_cors.py` (24 tests): Origin checks, credential flags, broad methods, wildcards, null origin handling.
- `tests/test_app.py` (20 tests): Route handling, input rejection (400), scan execution (200), session storage, report downloads (JSON, CSV, PDF).

### Verification Command & Output
```bash
python -m pytest tests/ -v
```
**Result:** `102 passed, 2 warnings in 1.10s` (100% passing).

---

## 7. Sample Security Findings

| Finding Title | Severity | Evidence | Remediation |
|---|---|---|---|
| Missing Content-Security-Policy | HIGH | Header absent from response | Implement `Content-Security-Policy: default-src 'self'; script-src 'self';` |
| Missing Strict-Transport-Security | MEDIUM | Header absent on HTTPS | Add `Strict-Transport-Security: max-age=31536000; includeSubDomains;` |
| Absent X-Content-Type-Options | MEDIUM | Header absent from response | Add `X-Content-Type-Options: nosniff` |
| Permissive CORS Wildcard Origin | REVIEW | `Access-Control-Allow-Origin: *` | Restrict origin to trusted domains if endpoint handles private data |

---

## 8. Limitations & Responsible Use

- **Passive Analysis:** The scanner only audits publicly returned headers without executing exploits.
- **Context Dependent:** Findings should be reviewed in the context of the specific application architecture.
- **Authorized Use Only:** The application must only be utilized on systems owned or authorized by the assessor.
