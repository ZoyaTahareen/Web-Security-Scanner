"""
generate_docx_report.py
Generates a comprehensive, professional Microsoft Word (.docx) project report
for IBM SkillsBuild Cyber Security 2026 (BharatCares).
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn


def set_cell_background(cell, hex_color):
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('w:top', top), ('w:bottom', bottom), ('w:left', left), ('w:right', right)]:
        node = OxmlElement(m)
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)


def build_docx_report(output_filename):
    doc = Document()

    # Set page margins to 1 inch
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Palette
    c_primary = RGBColor(15, 23, 42)    # Slate 900
    c_accent = RGBColor(2, 132, 199)    # Blue 600
    c_dark_green = RGBColor(15, 118, 110) # Teal 700
    c_charcoal = RGBColor(30, 41, 59)   # Slate 800
    c_muted = RGBColor(100, 116, 139)   # Slate 500

    # ─────────────────────────────────────────────────────────────────────────
    # HEADER / TITLE BLOCK
    # ─────────────────────────────────────────────────────────────────────────
    p_meta = doc.add_paragraph()
    r_track = p_meta.add_run("IBM SKILLSBUILD CYBER SECURITY 2026 · BHARATCARES")
    r_track.font.name = "Calibri"
    r_track.font.size = Pt(10)
    r_track.font.bold = True
    r_track.font.color.rgb = c_accent
    p_meta.paragraph_format.space_after = Pt(4)

    p_title = doc.add_paragraph()
    r_title = p_title.add_run("Automated Web Security Scanner for Security Headers and CORS Misconfigurations")
    r_title.font.name = "Calibri"
    r_title.font.size = Pt(22)
    r_title.font.bold = True
    r_title.font.color.rgb = c_primary
    p_title.paragraph_format.space_after = Pt(6)

    p_sub = doc.add_paragraph()
    r_sub = p_sub.add_run("Final Capstone Project Documentation & Vulnerability Assessment Specification")
    r_sub.font.name = "Calibri"
    r_sub.font.size = Pt(12)
    r_sub.font.italic = True
    r_sub.font.color.rgb = c_muted
    p_sub.paragraph_format.space_after = Pt(16)

    # Metadata Table
    table_meta = doc.add_table(rows=6, cols=2)
    table_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    table_meta.autofit = False

    meta_items = [
        ("Candidate Name", "Zoya Tahareen"),
        ("Program / Submission", "IBM SkillsBuild Cyber Security 2026 (Conducted by BharatCares)"),
        ("Project Title", "Automated Web Security Scanner for Security Headers and CORS Misconfigurations"),
        ("GitHub Repository", "https://github.com/ZoyaTahareen/Web-Security-Scanner"),
        ("Tech Stack", "Python 3.12, Flask 3.0.3, Requests, ReportLab, Pytest, Gunicorn, HTML/CSS/JS"),
        ("Test Verification", "102 Automated Tests Passed (100% Pass Rate via Pytest)"),
    ]

    for row_idx, (label, val) in enumerate(meta_items):
        row = table_meta.rows[row_idx]
        cell_lbl, cell_val = row.cells[0], row.cells[1]
        cell_lbl.width = Inches(2.0)
        cell_val.width = Inches(4.5)

        set_cell_background(cell_lbl, "F1F5F9")
        set_cell_background(cell_val, "F8FAFC")
        set_cell_margins(cell_lbl, 80, 80, 120, 120)
        set_cell_margins(cell_val, 80, 80, 120, 120)

        p0 = cell_lbl.paragraphs[0]
        p0.paragraph_format.space_after = Pt(0)
        r0 = p0.add_run(label)
        r0.font.name = "Calibri"
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = c_primary

        p1 = cell_val.paragraphs[0]
        p1.paragraph_format.space_after = Pt(0)
        r1 = p1.add_run(val)
        r1.font.name = "Calibri"
        r1.font.size = Pt(9.5)
        r1.font.color.rgb = c_charcoal

    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_after = Pt(16)

    # ─────────────────────────────────────────────────────────────────────────
    # 1. ABSTRACT & INTRODUCTION
    # ─────────────────────────────────────────────────────────────────────────
    h1 = doc.add_heading("1. Abstract & Introduction", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "Modern web applications operate in an adversarial threat landscape where malicious actors continually "
        "probe for misconfigurations. While substantial attention is devoted to backend database exploits and zero-day vulnerabilities, "
        "a critical proportion of security incidents stem from basic HTTP response header omissions and permissive Cross-Origin "
        "Resource Sharing (CORS) configurations. These client-side defenses, enforced natively by modern web browsers, represent the "
        "first line of defense against Cross-Site Scripting (XSS), clickjacking, MIME-type confusion, SSL stripping, and cross-domain data leakage."
    )
    p.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "Developed under the IBM SkillsBuild Cyber Security 2026 initiative conducted by BharatCares, this project delivers an "
        "Automated Web Security Scanner written in Python and Flask. The scanner performs automated, passive security audits against "
        "user-supplied public web endpoints. It validates targets with rigorous Server-Side Request Forgery (SSRF) protections, parses "
        "and evaluates 5 core HTTP security headers, analyzes 4 CORS directives, assigns deterministic risk ratings, and generates "
        "exportable reports in JSON, CSV, and PDF formats through an interactive pure-black themed web dashboard."
    )
    p.paragraph_format.space_after = Pt(10)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. PROBLEM STATEMENT & OBJECTIVES
    # ─────────────────────────────────────────────────────────────────────────
    h2 = doc.add_heading("2. Problem Statement & Project Objectives", level=1)
    h2.paragraph_format.space_before = Pt(14)
    h2.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "Problem Statement: Manual security auditing of HTTP response headers and CORS directives is inefficient, inconsistent, "
        "and error-prone when conducted across multiple environments. Additionally, naive automated scanners often introduce dangerous "
        "SSRF vectors if they blindly fetch user-supplied URLs without resolving DNS and checking for private RFC 1918 or cloud metadata "
        "IP addresses. Security analysts require a dependable, defensive tool that provides automated risk classification with actionable "
        "remediation code."
    )
    p.paragraph_format.space_after = Pt(6)

    doc.add_paragraph("Core Project Objectives:", style='List Bullet')
    objs = [
        ("Automated Security Header Analysis", "Systematically inspect Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy."),
        ("CORS Directive Audit", "Passively inspect Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Access-Control-Allow-Methods, and Access-Control-Allow-Headers for dangerous reflections."),
        ("Robust SSRF Protections", "Reject loopback (127.0.0.1, ::1), RFC 1918 private subnets (10/8, 172.16/12, 192.168/16), link-local (169.254/16), and cloud metadata endpoints (169.254.169.254)."),
        ("Rule-Based Severity Engine", "Classify issues transparently into High, Medium, Low, and Informational tiers with concrete evidence and remediation guidance."),
        ("Multi-Format Reporting", "Export comprehensive security assessment findings to JSON, spreadsheet-ready CSV, and formal ReportLab PDF reports."),
        ("Automated Quality Verification", "Maintain 100% test coverage of validation and scanning logic via 102 Pytest automated unit and integration tests using mocked networking."),
    ]
    for title, desc in objs:
        p_obj = doc.add_paragraph(style='List Bullet')
        r_t = p_obj.add_run(f"{title}: ")
        r_t.bold = True
        p_obj.add_run(desc)
        p_obj.paragraph_format.space_after = Pt(3)

    # ─────────────────────────────────────────────────────────────────────────
    # 3. TECHNOLOGIES USED & ARCHITECTURE
    # ─────────────────────────────────────────────────────────────────────────
    h3 = doc.add_heading("3. Technologies Used & System Architecture", level=1)
    h3.paragraph_format.space_before = Pt(14)
    h3.paragraph_format.space_after = Pt(6)

    table_tech = doc.add_table(rows=6, cols=3)
    table_tech.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Component", "Technology", "Architectural Role & Justification"]
    for i, title in enumerate(headers):
        cell = table_tech.rows[0].cells[i]
        set_cell_background(cell, "0F172A")
        set_cell_margins(cell, 80, 80, 100, 100)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.bold = True
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    tech_data = [
        ("Backend Framework", "Flask 3.0.3 (Python 3.12)", "Provides REST endpoints, session-based scan persistence, and template rendering."),
        ("HTTP Client Engine", "Requests 2.32.3", "Executes outbound probes with strict 10s timeouts and TLS certificate validation."),
        ("SSRF Defense Layer", "ipaddress & socket standard modules", "Resolves DNS, inspects IP ranges, and blocks private/loopback/cloud metadata destinations."),
        ("Report Generators", "ReportLab 4.2.2 & CSV/JSON standard modules", "Generates vector-styled PDF security audit certificates, CSV sheets, and raw JSON."),
        ("Automated Testing", "Pytest 8.3.3", "Executes 102 unit and integration tests using mocked network responses."),
    ]
    for row_idx, (c0, c1, c2) in enumerate(tech_data, start=1):
        row = table_tech.rows[row_idx]
        for col_idx, text in enumerate([c0, c1, c2]):
            cell = row.cells[col_idx]
            set_cell_background(cell, "F8FAFC" if row_idx % 2 == 0 else "FFFFFF")
            set_cell_margins(cell, 60, 60, 100, 100)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(text)
            r.font.size = Pt(9)
            r.font.color.rgb = c_charcoal

    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_after = Pt(10)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. IMPLEMENTATION DETAILS
    # ─────────────────────────────────────────────────────────────────────────
    h4 = doc.add_heading("4. Implementation Details", level=1)
    h4.paragraph_format.space_before = Pt(14)
    h4.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "4.1 URL Validator & SSRF Shield (scanner/validator.py):\n"
        "To prevent attackers from using the scanner as an intranet proxy or attacking local cloud metadata services, "
        "every submitted URL undergoes strict validation. Schemes are restricted strictly to 'http' and 'https'. Hostnames are "
        "extracted, checked against known cloud metadata domains (e.g. metadata.google.internal), and resolved to IP addresses via "
        "socket.getaddrinfo(). Each resolved IP address is verified against Python's ipaddress module. Any IP classified as private (RFC 1918), "
        "loopback (127.0.0.0/8), link-local (169.254.0.0/16), or IPv6 loopback (::1) is immediately rejected with a 400 Bad Request error."
    )
    p.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "4.2 HTTP Security Header Inspection (scanner/headers.py):\n"
        "The header analyzer inspects 5 fundamental security headers using rule-based assessment logic:\n"
        "• Content-Security-Policy (CSP): Validates presence of restrictive directives; flags 'unsafe-inline', 'unsafe-eval', or missing policies.\n"
        "• Strict-Transport-Security (HSTS): Evaluates max-age (recommending >= 31536000 seconds / 1 year) and includeSubDomains. Context-aware: only required over HTTPS.\n"
        "• X-Content-Type-Options: Requires exact value 'nosniff' to prevent MIME-confusion exploits.\n"
        "• X-Frame-Options: Evaluates 'DENY' or 'SAMEORIGIN' to prevent clickjacking overlays; recognizes CSP frame-ancestors as modern replacement.\n"
        "• Referrer-Policy: Checks for privacy-preserving values ('strict-origin-when-cross-origin', 'no-referrer') and flags 'unsafe-url'."
    )
    p.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "4.3 CORS Configuration Analysis (scanner/cors.py):\n"
        "Audits Cross-Origin Resource Sharing response directives:\n"
        "• Access-Control-Allow-Origin: Identifies wildcard (*) policies and dangerous 'null' origins.\n"
        "• Access-Control-Allow-Credentials: Evaluates pairing with origins; notes high risk if origins are reflected dynamically alongside credentials.\n"
        "• Access-Control-Allow-Methods & Headers: Flags broad methods (PUT, DELETE) or dangerous headers (Authorization) exposed to cross-origin callers."
    )
    p.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "4.4 Risk Assessment & Remediation (scanner/risk_assessment.py):\n"
        "Maps every observed issue to a structured finding record containing Title, Severity (High, Medium, Low, Informational), "
        "Observed Evidence, Exploit Impact Explanation, and Recommended Fix code snippet."
    )
    p.paragraph_format.space_after = Pt(10)

    # ─────────────────────────────────────────────────────────────────────────
    # 5. TESTING METHODOLOGY & RESULTS
    # ─────────────────────────────────────────────────────────────────────────
    h5 = doc.add_heading("5. Testing Methodology & Verification Results", level=1)
    h5.paragraph_format.space_before = Pt(14)
    h5.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "Automated software quality verification was implemented via Pytest. To guarantee 100% deterministic test execution "
        "independent of external network conditions, all external HTTP requests and socket connections are fully mocked using unittest.mock.patch."
    )
    p.paragraph_format.space_after = Pt(6)

    table_tests = doc.add_table(rows=6, cols=4)
    table_tests.alignment = WD_TABLE_ALIGNMENT.CENTER
    test_headers = ["Test Module", "Verification Focus", "Test Count", "Result"]
    for i, title in enumerate(test_headers):
        cell = table_tests.rows[0].cells[i]
        set_cell_background(cell, "0F172A")
        set_cell_margins(cell, 80, 80, 100, 100)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.bold = True
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    test_rows = [
        ("tests/test_validator.py", "SSRF protection, scheme filtering, DNS resolution, private/loopback/cloud IP rejection", "26 tests", "PASSED"),
        ("tests/test_headers.py", "CSP, HSTS (HTTPS context), nosniff validation, clickjacking defenses, Referrer-Policy", "32 tests", "PASSED"),
        ("tests/test_cors.py", "Wildcard origins, credentials handling, null origins, dangerous HTTP methods/headers", "24 tests", "PASSED"),
        ("tests/test_app.py", "Flask REST routes, input validation (400), scan sessions, JSON/CSV/PDF download endpoints", "20 tests", "PASSED"),
        ("TOTAL VERIFIED", "Complete Application Test Suite", "102 tests", "102 / 102 PASSED (100%)"),
    ]

    for row_idx, (c0, c1, c2, c3) in enumerate(test_rows, start=1):
        row = table_tests.rows[row_idx]
        is_total = (row_idx == len(test_rows))
        bg = "E2E8F0" if is_total else ("F8FAFC" if row_idx % 2 == 0 else "FFFFFF")
        for col_idx, text in enumerate([c0, c1, c2, c3]):
            cell = row.cells[col_idx]
            set_cell_background(cell, bg)
            set_cell_margins(cell, 60, 60, 100, 100)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(text)
            r.font.bold = is_total or (col_idx == 3)
            r.font.size = Pt(9)
            if col_idx == 3:
                r.font.color.rgb = RGBColor(22, 163, 74) # Green
            else:
                r.font.color.rgb = c_primary if is_total else c_charcoal

    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_after = Pt(10)

    # ─────────────────────────────────────────────────────────────────────────
    # 6. SAMPLE FINDINGS & REMEDIATION
    # ─────────────────────────────────────────────────────────────────────────
    h6 = doc.add_heading("6. Sample Findings & Remediation Guidance", level=1)
    h6.paragraph_format.space_before = Pt(14)
    h6.paragraph_format.space_after = Pt(6)

    sample_findings = [
        ("Missing Content-Security-Policy", "HIGH", "Header absent from HTTP response", "Add header: Content-Security-Policy: default-src 'self'; script-src 'self';"),
        ("Strict-Transport-Security (HSTS) Missing on HTTPS", "MEDIUM", "Observed scheme: https://, header absent", "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains;"),
        ("Absent X-Content-Type-Options", "MEDIUM", "Header absent from HTTP response", "Add header: X-Content-Type-Options: nosniff"),
        ("Permissive CORS Wildcard Origin", "REVIEW", "Access-Control-Allow-Origin: *", "Restrict origin to authorized client domains if endpoint serves sensitive data."),
    ]
    for title, sev, evidence, rem in sample_findings:
        p_f = doc.add_paragraph()
        r_title = p_f.add_run(f"• {title} ")
        r_title.bold = True
        r_sev = p_f.add_run(f"[{sev}]\n")
        r_sev.bold = True
        r_sev.font.color.rgb = RGBColor(220, 38, 38) if sev == "HIGH" else (RGBColor(234, 88, 12) if sev == "MEDIUM" else c_accent)
        p_f.add_run(f"  Evidence: {evidence}\n")
        p_f.add_run(f"  Remediation: {rem}")
        p_f.paragraph_format.space_after = Pt(4)

    # ─────────────────────────────────────────────────────────────────────────
    # 7. LIMITATIONS & RESPONSIBLE USE
    # ─────────────────────────────────────────────────────────────────────────
    h7 = doc.add_heading("7. Limitations & Responsible Use Disclaimer", level=1)
    h7.paragraph_format.space_before = Pt(14)
    h7.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "Limitations: The scanner performs passive reconnaissance of public HTTP response headers. It does not perform active "
        "fuzzing, exploitation, or credential testing. A missing header does not automatically imply complete compromise, but indicates "
        "omission of defense-in-depth protections."
    )
    p.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "Responsible Use Disclaimer: This tool is developed strictly for educational and authorized defensive audits under the "
        "IBM SkillsBuild Cyber Security 2026 program. Scanning websites without explicit prior authorization from the system owner is illegal. "
        "Users are solely responsible for compliance with applicable cyber laws."
    )
    p.paragraph_format.space_after = Pt(16)

    # ─────────────────────────────────────────────────────────────────────────
    # 8. CONCLUSION & SIGN-OFF
    # ─────────────────────────────────────────────────────────────────────────
    h8 = doc.add_heading("8. Conclusion & Sign-Off", level=1)
    h8.paragraph_format.space_before = Pt(14)
    h8.paragraph_format.space_after = Pt(6)

    p = doc.add_paragraph(
        "The Automated Web Security Scanner fulfills all requirements established by IBM SkillsBuild and BharatCares. "
        "With a verified 102-test Pytest suite, robust SSRF mitigation, deterministic severity categorization, multi-format export capability, "
        "and a complete codebase on GitHub, the project demonstrates technical competence in cybersecurity and Python software engineering."
    )
    p.paragraph_format.space_after = Pt(10)

    p_sign = doc.add_paragraph()
    r_sign1 = p_sign.add_run("Submitted by: ")
    r_sign1.bold = True
    p_sign.add_run("Zoya Tahareen\n")
    r_sign2 = p_sign.add_run("Program: ")
    r_sign2.bold = True
    p_sign.add_run("IBM SkillsBuild Cyber Security 2026 (BharatCares)\n")
    r_sign3 = p_sign.add_run("Repository: ")
    r_sign3.bold = True
    p_sign.add_run("https://github.com/ZoyaTahareen/Web-Security-Scanner")

    doc.save(output_filename)
    print(f"Word Document successfully created: {output_filename}")


if __name__ == '__main__':
    build_docx_report("ZoyaTahareen_ProjectReport.docx")
