"""
================================================================================
IBM SkillsBuild Cyber Security 2026 · BharatCares Capstone Project
Project: Automated Web Security Scanner for Security Headers and CORS Misconfigurations
Author:  Zoya Tahareen
GitHub:  https://github.com/ZoyaTahareen/Web-Security-Scanner
File:    ZoyaTahareen_WebSecurityScanner.py
================================================================================
"""

import sys
import ipaddress
import socket
import json
import csv
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

# ─────────────────────────────────────────────────────────────────────────────
# 1. URL VALIDATOR & SSRF PROTECTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

BLOCKED_HOSTNAMES = {
    'localhost',
    'metadata.google.internal',
    'metadata',
    '169.254.169.254',
    'instance-data',
}


def is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP address is private, loopback, link-local, or cloud metadata."""
    if ip_obj.is_loopback:
        return True
    if ip_obj.is_private:
        return True
    if ip_obj.is_link_local:
        return True
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address):
        cloud_meta_net = ipaddress.IPv4Network('169.254.169.0/24')
        if ip_obj in cloud_meta_net:
            return True
    return False


def validate_url(raw_url: str) -> str:
    """Validate and sanitize user-supplied URL with strict SSRF controls."""
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL cannot be empty.")
    
    raw_url = raw_url.strip()
    if len(raw_url) > 2048:
        raise ValueError("URL exceeds maximum allowed length of 2048 characters.")
    
    parsed = urlparse(raw_url)
    scheme = (parsed.scheme or '').lower()
    if scheme not in ('http', 'https'):
        raise ValueError(f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
    
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname or domain name.")
    
    if hostname.lower() in BLOCKED_HOSTNAMES:
        raise ValueError(f"Scanning '{hostname}' is not permitted (blocked destination).")
    
    try:
        ip_obj = ipaddress.ip_address(hostname.strip('[]'))
        if is_blocked_ip(ip_obj):
            raise ValueError(f"Scanning IP address '{hostname}' is not permitted. Private, loopback, and cloud-metadata destinations are blocked.")
    except ValueError as e:
        if "not permitted" in str(e):
            raise
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                resolved_ip_str = item[4][0]
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                if is_blocked_ip(resolved_ip):
                    raise ValueError(f"Destination host '{hostname}' resolves to private/prohibited IP ({resolved_ip_str}). Access is blocked.")
        except socket.gaierror:
            raise ValueError(f"Could not resolve hostname '{hostname}'. Verify the domain name exists and DNS is reachable.")
    
    clean_path = parsed.path if parsed.path else '/'
    clean_url = f"{scheme}://{parsed.netloc}{clean_path}"
    if parsed.query:
        clean_url += f"?{parsed.query}"
    return clean_url


# ─────────────────────────────────────────────────────────────────────────────
# 2. HTTP SECURITY HEADERS ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def analyze_headers(headers: dict, is_https: bool = True) -> list[dict]:
    """Analyze 5 core HTTP security headers against defensive benchmarks."""
    norm = {k.lower(): v.strip() for k, v in headers.items()}
    results = []

    # 1. Content-Security-Policy
    csp_val = norm.get('content-security-policy')
    if not csp_val:
        results.append({
            'name': 'Content-Security-Policy',
            'present': False,
            'value': None,
            'status': 'WARNING',
            'purpose': 'Restricts sources from which content (scripts, styles, images) can be loaded.',
            'implications': 'Without CSP, the browser will execute any injected scripts, increasing vulnerability to XSS attacks.',
            'remediation': "Deploy a Content-Security-Policy header, e.g.: Content-Security-Policy: default-src 'self'; script-src 'self';"
        })
    else:
        lower_csp = csp_val.lower()
        concerns = []
        if "'unsafe-inline'" in lower_csp:
            concerns.append("'unsafe-inline' directive permits inline script execution")
        if "'unsafe-eval'" in lower_csp:
            concerns.append("'unsafe-eval' directive permits dynamic code evaluation via eval()")
        status = 'REVIEW' if concerns else 'PASS'
        results.append({
            'name': 'Content-Security-Policy',
            'present': True,
            'value': csp_val,
            'status': status,
            'purpose': 'Restricts sources from which content (scripts, styles, images) can be loaded.',
            'implications': '; '.join(concerns) if concerns else 'CSP is present and restricts script execution.',
            'remediation': 'Consider using nonces or hashes instead of unsafe-inline/unsafe-eval.' if concerns else 'None required.'
        })

    # 2. Strict-Transport-Security (HSTS)
    hsts_val = norm.get('strict-transport-security')
    if not is_https:
        results.append({
            'name': 'Strict-Transport-Security',
            'present': bool(hsts_val),
            'value': hsts_val,
            'status': 'NOT APPLICABLE',
            'purpose': 'Enforces HTTPS-only connections and prevents SSL-stripping attacks.',
            'implications': 'HSTS is only effective when served over HTTPS. The scanned target was reached over plain HTTP.',
            'remediation': 'Migrate site traffic to HTTPS, then configure the Strict-Transport-Security header.'
        })
    elif not hsts_val:
        results.append({
            'name': 'Strict-Transport-Security',
            'present': False,
            'value': None,
            'status': 'WARNING',
            'purpose': 'Enforces HTTPS-only connections and prevents SSL-stripping attacks.',
            'implications': 'Missing HSTS on an HTTPS site allows users to be downgraded to HTTP via man-in-the-middle attacks.',
            'remediation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        })
    else:
        results.append({
            'name': 'Strict-Transport-Security',
            'present': True,
            'value': hsts_val,
            'status': 'PASS',
            'purpose': 'Enforces HTTPS-only connections and prevents SSL-stripping attacks.',
            'implications': 'HSTS is present, protecting HTTPS sessions from downgrade attacks.',
            'remediation': 'None required.'
        })

    # 3. X-Content-Type-Options
    xcto_val = norm.get('x-content-type-options')
    if not xcto_val:
        results.append({
            'name': 'X-Content-Type-Options',
            'present': False,
            'value': None,
            'status': 'WARNING',
            'purpose': 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
            'implications': 'Browsers may interpret non-executable MIME types as executable JavaScript if content appears script-like.',
            'remediation': 'Add header: X-Content-Type-Options: nosniff'
        })
    elif xcto_val.lower() == 'nosniff':
        results.append({
            'name': 'X-Content-Type-Options',
            'present': True,
            'value': xcto_val,
            'status': 'PASS',
            'purpose': 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
            'implications': 'nosniff directive is correctly configured.',
            'remediation': 'None required.'
        })
    else:
        results.append({
            'name': 'X-Content-Type-Options',
            'present': True,
            'value': xcto_val,
            'status': 'REVIEW',
            'purpose': 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
            'implications': f"Unexpected value '{xcto_val}'. The only standard value is 'nosniff'.",
            'remediation': 'Update header value to: X-Content-Type-Options: nosniff'
        })

    # 4. X-Frame-Options
    xfo_val = norm.get('x-frame-options')
    has_frame_ancestors = bool(csp_val and 'frame-ancestors' in csp_val.lower())
    if not xfo_val:
        if has_frame_ancestors:
            status = 'PASS'
            implications = 'X-Frame-Options is absent, but CSP frame-ancestors is present and supersedes it.'
            remediation = 'Consider adding X-Frame-Options for defense-in-depth with legacy browsers.'
        else:
            status = 'WARNING'
            implications = 'Without clickjacking protection, third-party sites can embed this page inside an iframe.'
            remediation = 'Add header: X-Frame-Options: DENY (or SAMEORIGIN)'
        results.append({
            'name': 'X-Frame-Options',
            'present': False,
            'value': None,
            'status': status,
            'purpose': 'Controls whether a browser is permitted to render a page inside an iframe.',
            'implications': implications,
            'remediation': remediation
        })
    else:
        upper_xfo = xfo_val.upper()
        if upper_xfo in ('DENY', 'SAMEORIGIN'):
            results.append({
                'name': 'X-Frame-Options',
                'present': True,
                'value': xfo_val,
                'status': 'PASS',
                'purpose': 'Controls whether a browser is permitted to render a page inside an iframe.',
                'implications': f"Configured with standard '{upper_xfo}' directive.",
                'remediation': 'None required.'
            })
        else:
            results.append({
                'name': 'X-Frame-Options',
                'present': True,
                'value': xfo_val,
                'status': 'REVIEW',
                'purpose': 'Controls whether a browser is permitted to render a page inside an iframe.',
                'implications': f"Non-standard or legacy value '{xfo_val}'. Modern browsers prefer DENY or SAMEORIGIN.",
                'remediation': 'Update to: X-Frame-Options: DENY (or SAMEORIGIN), or use CSP frame-ancestors.'
            })

    # 5. Referrer-Policy
    rp_val = norm.get('referrer-policy')
    if not rp_val:
        results.append({
            'name': 'Referrer-Policy',
            'present': False,
            'value': None,
            'status': 'REVIEW',
            'purpose': 'Controls how much referrer information is sent with requests made from this page.',
            'implications': 'No policy set. Browsers default to strict-origin-when-cross-origin, but explicit configuration is recommended.',
            'remediation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
        })
    elif rp_val.lower() == 'unsafe-url':
        results.append({
            'name': 'Referrer-Policy',
            'present': True,
            'value': rp_val,
            'status': 'WARNING',
            'purpose': 'Controls how much referrer information is sent with requests.',
            'implications': "'unsafe-url' leaks full URL paths, including any sensitive tokens or query parameters, to external destinations.",
            'remediation': 'Change policy to: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)'
        })
    else:
        results.append({
            'name': 'Referrer-Policy',
            'present': True,
            'value': rp_val,
            'status': 'PASS',
            'purpose': 'Controls how much referrer information is sent with requests.',
            'implications': f"Policy '{rp_val}' is configured.",
            'remediation': 'None required.'
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 3. CORS ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def analyze_cors(headers: dict) -> dict:
    """Passively inspect Cross-Origin Resource Sharing response headers."""
    norm = {k.lower(): v.strip() for k, v in headers.items()}
    origin = norm.get('access-control-allow-origin')
    credentials = norm.get('access-control-allow-credentials')
    methods = norm.get('access-control-allow-methods')
    allow_headers = norm.get('access-control-allow-headers')
    
    any_present = any([origin, credentials, methods, allow_headers])
    concerns = []
    header_rows = []

    # Origin
    if origin == '*':
        header_rows.append({'name': 'Access-Control-Allow-Origin', 'value': origin, 'status': 'REVIEW'})
        concerns.append("Wildcard origin ('*') permits cross-origin requests from any website.")
    elif origin == 'null':
        header_rows.append({'name': 'Access-Control-Allow-Origin', 'value': origin, 'status': 'WARNING'})
        concerns.append("Origin 'null' can be abused by sandboxed iframes or local HTML files.")
    elif origin:
        header_rows.append({'name': 'Access-Control-Allow-Origin', 'value': origin, 'status': 'INFO'})
    else:
        header_rows.append({'name': 'Access-Control-Allow-Origin', 'value': 'Not Set', 'status': 'INFO'})

    # Credentials
    if credentials and credentials.lower() == 'true':
        header_rows.append({'name': 'Access-Control-Allow-Credentials', 'value': credentials, 'status': 'REVIEW'})
        if origin and origin != '*':
            concerns.append(f"Credentials allowed for origin '{origin}'. Verify that this origin is explicitly trusted.")
    elif credentials:
        header_rows.append({'name': 'Access-Control-Allow-Credentials', 'value': credentials, 'status': 'INFO'})
    else:
        header_rows.append({'name': 'Access-Control-Allow-Credentials', 'value': 'Not Set', 'status': 'INFO'})

    summary = (
        f"CORS headers detected ({len(concerns)} concern(s) identified)." if concerns
        else "CORS headers present with standard configuration."
    ) if any_present else "No CORS response headers detected. Same-Origin Policy applies by default."

    return {
        'present': any_present,
        'headers': header_rows,
        'summary': summary,
        'concerns': concerns
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. RULE-BASED RISK SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def assess_risks(header_analysis: list[dict], cors_analysis: dict, is_https: bool) -> list[dict]:
    """Assign rule-based severity levels and remediation advice."""
    findings = []
    header_map = {item['name']: item for item in header_analysis}

    # CSP
    csp = header_map.get('Content-Security-Policy', {})
    if not csp.get('present'):
        findings.append({
            'title': 'Missing Content-Security-Policy (CSP)',
            'severity': 'HIGH',
            'evidence': 'Header Content-Security-Policy absent',
            'explanation': 'The application does not declare a CSP. Any XSS injection flaw can execute arbitrary scripts.',
            'impact': 'Cross-Site Scripting, session token theft, malicious DOM manipulation.',
            'remediation': "Define a strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self';"
        })

    # HSTS
    hsts = header_map.get('Strict-Transport-Security', {})
    if is_https and not hsts.get('present'):
        findings.append({
            'title': 'Strict-Transport-Security Missing on HTTPS Target',
            'severity': 'MEDIUM',
            'evidence': 'Target reached via HTTPS; Strict-Transport-Security absent',
            'explanation': 'Browsers will not force encrypted transport for future visits, leaving initial requests open to SSL stripping.',
            'impact': 'Man-in-the-middle downgrade to HTTP, credential interception.',
            'remediation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        })

    # X-Content-Type-Options
    xcto = header_map.get('X-Content-Type-Options', {})
    if not xcto.get('present'):
        findings.append({
            'title': 'X-Content-Type-Options Header Absent',
            'severity': 'MEDIUM',
            'evidence': 'Header X-Content-Type-Options absent',
            'explanation': 'Browsers may attempt MIME sniffing on file downloads and execute untrusted files as script.',
            'impact': 'Drive-by script execution via user-uploaded files.',
            'remediation': 'Add header: X-Content-Type-Options: nosniff'
        })

    # X-Frame-Options
    xfo = header_map.get('X-Frame-Options', {})
    if not xfo.get('present') and xfo.get('status') == 'WARNING':
        findings.append({
            'title': 'Clickjacking Protection Absent (X-Frame-Options)',
            'severity': 'MEDIUM',
            'evidence': 'Neither X-Frame-Options nor CSP frame-ancestors detected',
            'explanation': 'The application allows itself to be rendered within an external iframe overlay.',
            'impact': 'Clickjacking attacks tricking users into unauthorized actions.',
            'remediation': 'Add header: X-Frame-Options: DENY (or SAMEORIGIN)'
        })

    # CORS
    for concern in cors_analysis.get('concerns', []):\
        findings.append({
            'title': 'Permissive CORS Configuration Detected',
            'severity': 'LOW',
            'evidence': concern,
            'explanation': 'CORS policies govern browser read permissions across domain origins.',
            'impact': 'Potential unauthorized data extraction if the endpoint serves sensitive content.',
            'remediation': 'Restrict Access-Control-Allow-Origin to authorized domains only.'
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 5. SCANNER ORCHESTRATION & CLI INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def scan_target(target_url: str) -> dict:
    """Execute complete security assessment against target URL."""
    clean_url = validate_url(target_url)
    is_https = clean_url.startswith('https://')
    
    response = requests.get(
        clean_url,
        timeout=10,
        verify=True,
        allow_redirects=True,
        headers={'User-Agent': 'WebSecScan-Tool/1.0 (IBM-SkillsBuild-2026)'}
    )
    
    headers = dict(response.headers)
    header_analysis = analyze_headers(headers, is_https=is_https)
    cors_analysis = analyze_cors(headers)
    findings = assess_risks(header_analysis, cors_analysis, is_https=is_https)
    
    return {
        'target_url': target_url,
        'final_url': response.url,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'http_status': response.status_code,
        'header_analysis': header_analysis,
        'cors_analysis': cors_analysis,
        'findings': findings
    }


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    print("=" * 70)
    print("🛡️  Automated Web Security Scanner · IBM SkillsBuild 2026")
    print(f"[*] Auditing target: {target}")
    print("=" * 70)
    
    try:
        result = scan_target(target)
        print(f"\n[+] Status: HTTP {result['http_status']} | Final URL: {result['final_url']}")
        print(f"[+] Scan Timestamp: {result['timestamp']}\n")
        
        print("--- [1] HTTP Security Headers Analysis ---")
        for h in result['header_analysis']:
            badge = f"[{h['status']}]"
            val = h['value'] if h['present'] else 'Absent'
            print(f"{badge:<10} {h['name']:<28} : {val}")
            
        print(f"\n--- [2] CORS Analysis ---\n{result['cors_analysis']['summary']}")
        
        print("\n--- [3] Identified Findings ---")
        if not result['findings']:
            print("No vulnerabilities identified. Good defensive posture!")
        else:
            for idx, f in enumerate(result['findings'], 1):
                print(f"{idx}. [{f['severity']}] {f['title']}")
                print(f"   Evidence: {f['evidence']}")
                print(f"   Fix: {f['remediation']}\n")
                
    except Exception as e:
        print(f"\n[-] Error scanning target: {e}")


if __name__ == '__main__':
    main()
