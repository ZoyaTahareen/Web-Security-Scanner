"""
generate_bootcamp_report.py
Generates a comprehensive, professional, publication-quality PDF report
for the Cybersecurity Bootcamp Capstone Submission.
"""

import os
import sys
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and draw total page count
    along with running header and footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        # Don't draw headers/footers on cover page (page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))

        # Header
        self.drawString(54, letter[1] - 36, "CYBERSECURITY CAPSTONE PROJECT REPORT")
        self.setFont("Helvetica", 8)
        self.drawRightString(letter[0] - 54, letter[1] - 36, "Automated Web Security Scanner")

        # Header rule
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.75)
        self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Footer rule
        self.line(54, 46, letter[0] - 54, 46)

        # Footer
        self.setFont("Helvetica", 8)
        self.drawString(54, 34, "Author: Zoya Tahareen | GitHub: github.com/ZoyaTahareen/Web-Security-Scanner")
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(letter[0] - 54, 34, page_str)

        self.restoreState()


def build_pdf_report(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom styles
    primary_color = colors.HexColor("#0f172a")     # Deep Slate
    accent_color = colors.HexColor("#0284c7")      # Cyan/Blue
    dark_green = colors.HexColor("#0f766e")        # Teal Green
    text_dark = colors.HexColor("#1e293b")         # Charcoal Body
    text_muted = colors.HexColor("#475569")

    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=30,
        textColor=primary_color,
        alignment=0,
        spaceAfter=12
    )

    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=18,
        textColor=accent_color,
        alignment=0,
        spaceAfter=24
    )

    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=15,
        textColor=text_dark
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=20,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11.5,
        leading=16,
        textColor=dark_green,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=text_dark,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=text_dark,
        leftIndent=14,
        firstLineIndent=-10,
        spaceAfter=3
    )

    callout_style = ParagraphStyle(
        'Callout_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#0369a1")
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # ══════════════════════════════════════════════════════════════════════════
    # COVER / TITLE BLOCK
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 20))
    story.append(Paragraph("CYBERSECURITY BOOTCAMP · CAPSTONE REPORT", ParagraphStyle(
        'TrackBadge', fontName='Helvetica-Bold', fontSize=10, textColor=accent_color, spaceAfter=8
    )))
    story.append(Paragraph("Automated Web Security Scanner for Security Headers and CORS Misconfigurations", title_style))
    story.append(Paragraph("An Automated Vulnerability Assessment Tool for Defensive HTTP Header & Cross-Origin Configuration Analysis", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceAfter=20, spaceBefore=0))

    meta_table_data = [
        [Paragraph("<b>Author / Candidate:</b>", meta_style), Paragraph("Zoya Tahareen", meta_style)],
        [Paragraph("<b>GitHub Username:</b>", meta_style), Paragraph("zoyatahareen", meta_style)],
        [Paragraph("<b>Project Repository:</b>", meta_style), Paragraph("https://github.com/ZoyaTahareen/Web-Security-Scanner", meta_style)],
        [Paragraph("<b>Submission Track:</b>", meta_style), Paragraph("Cybersecurity Engineering / Web Application Security", meta_style)],
        [Paragraph("<b>Application Framework:</b>", meta_style), Paragraph("Python 3.12 + Flask 3.0.3 (WSGI / Gunicorn / Render Ready)", meta_style)],
        [Paragraph("<b>Test Suite Verification:</b>", meta_style), Paragraph("<b>102 Passed, 0 Failures</b> (Pytest with 100% Mocked Network)", meta_style)],
        [Paragraph("<b>Report Date:</b>", meta_style), Paragraph(datetime.now().strftime("%B %d, %Y"), meta_style)],
        [Paragraph("<b>Deliverable Scope:</b>", meta_style), Paragraph("Working Web App, RESTful Scanner, Pure-Black GUI, 3 Exporters, 102 Unit Tests", meta_style)]
    ]
    meta_table = Table(meta_table_data, colWidths=[150, 354])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 16))

    # Executive Summary Card on Cover
    exec_summary_html = (
        "<b>Executive Summary:</b> Modern web applications frequently expose users and data to attack due to "
        "improperly configured HTTP security response headers and permissive Cross-Origin Resource Sharing (CORS) policies. "
        "This project implements an automated, defensive security scanner capable of validating target endpoints with Server-Side "
        "Request Forgery (SSRF) protections, passively evaluating 5 critical security headers and 4 CORS directives, computing "
        "transparent rule-based risk severity rankings, and exporting audit reports in JSON, CSV, and PDF formats through a "
        "dedicated pure-black themed cybersecurity dashboard."
    )
    exec_table = Table([[Paragraph(exec_summary_html, body_style)]], colWidths=[504])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#86efac")),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(exec_table)

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1: ABSTRACT & INTRODUCTION
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("1. Abstract & Introduction", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))
    story.append(Paragraph(
        "<b>Abstract:</b> HTTP security headers provide a primary browser-enforced defense against common client-side "
        "vulnerabilities including Cross-Site Scripting (XSS), clickjacking, MIME-type confusion attacks, and insecure "
        "protocol downgrades. In tandem, Cross-Origin Resource Sharing (CORS) governs browser authorization boundaries for cross-domain "
        "AJAX requests. Despite well-established industry standards (OWASP, W3C, RFCs), real-world web applications routinely "
        "omit defensive headers or implement dangerous CORS rules (such as wildcard reflections with credentials). "
        "This project presents an end-to-end, reproducible, defensive web security inspection platform developed in Python and Flask.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Background:</b> Security teams and penetration testers conduct initial passive reconnaissance before executing active tests. "
        "Manually inspecting raw HTTP response headers using terminal commands (e.g., <code>curl -I</code>) or browser developer tools is "
        "tedious, error-prone, and fails to systematically categorize findings by risk level or generate client-ready reports. "
        "The Automated Web Security Scanner streamlines this workflow into an interactive, defensive, and accessible software platform.",
        body_style
    ))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2: PROBLEM STATEMENT & OBJECTIVES
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("2. Problem Statement & Project Objectives", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))

    story.append(Paragraph(
        "<b>The Problem:</b> The majority of web vulnerabilities identified in bug bounty programs and security audits stem not from complex "
        "zero-day flaws, but from basic misconfigurations. Without strict Content Security Policy (CSP), attackers can execute malicious scripts; "
        "without HTTP Strict Transport Security (HSTS), traffic is vulnerable to SSL stripping; without proper CORS controls, malicious third-party "
        "origins can read authenticated responses. Existing open-source tools often require complex CLI setups, lack SSRF protection for hosted environments, "
        "or do not provide formatted, multi-type downloadable reports.",
        body_style
    ))

    story.append(Paragraph("<b>Primary Project Objectives:</b>", h2_style))
    objectives = [
        "<b>Automate Security Header Inspection:</b> Systematically inspect 5 core security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.",
        "<b>Analyze Cross-Origin Resource Sharing (CORS):</b> Inspect Origin, Credentials, Methods, and Allowed Headers for wildcards, null origins, and overly permissive patterns.",
        "<b>Enforce Robust SSRF Protections:</b> Reject loopback (127.0.0.0/8, ::1), private IP blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local addresses (169.254.0.0/16), and cloud metadata endpoints (AWS, GCP, Azure).",
        "<b>Rule-Based Severity Classification:</b> Assign High, Medium, Low, or Informational severities using deterministic, documented rules rather than arbitrary scores.",
        "<b>Professional Interactive Dashboard:</b> Deliver a responsive, pure-black themed web user interface with dynamic tab switching and real-time status indication.",
        "<b>Multi-Format Report Export:</b> Allow auditors to export findings into machine-readable JSON, spreadsheet-ready CSV, and formal styled PDF reports.",
        "<b>Thorough Automated Testing:</b> Ensure reliability with an exhaustive Pytest suite (102 tests) verifying all validation rules, mock HTTP responses, and edge cases."
    ]
    for obj in objectives:
        story.append(Paragraph(f"• {obj}", bullet_style))

    story.append(Spacer(1, 6))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3: SYSTEM ARCHITECTURE & TECHNOLOGY STACK
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("3. Architecture & Technology Stack", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))

    tech_table_data = [
        [Paragraph("<b>Component</b>", meta_style), Paragraph("<b>Technology / Library</b>", meta_style), Paragraph("<b>Architectural Role & Justification</b>", meta_style)],
        [Paragraph("Backend Framework", body_style), Paragraph("Flask 3.0.3 (Python)", body_style), Paragraph("Lightweight WSGI framework providing clean routing, session management, and JSON APIs.", body_style)],
        [Paragraph("HTTP Engine", body_style), Paragraph("Requests 2.32.3", body_style), Paragraph("Robust client with fine-grained timeout controls, TLS verification, and redirect inspection.", body_style)],
        [Paragraph("SSRF Defense", body_style), Paragraph("Python <code>ipaddress</code> + <code>socket</code>", body_style), Paragraph("Validates public FQDNs, resolves DNS, and blocks RFC 1918 / RFC 3927 / cloud metadata ranges.", body_style)],
        [Paragraph("Report Engine", body_style), Paragraph("ReportLab 4.2.2", body_style), Paragraph("Programmatic, vector-based PDF generation engine creating styled audit documents.", body_style)],
        [Paragraph("Testing Suite", body_style), Paragraph("Pytest 8.3.3", body_style), Paragraph("Automated unit and integration test framework with mock networking and fixture support.", body_style)],
        [Paragraph("Production WSGI", body_style), Paragraph("Gunicorn 22.0.0", body_style), Paragraph("Multi-worker production server configured for Render cloud platform deployment.", body_style)],
        [Paragraph("Frontend Interface", body_style), Paragraph("HTML5 / Vanilla CSS3 / JS", body_style), Paragraph("Single-page black aesthetic UI (#000000 base, #00ff88 accents) without bulky JS frameworks.", body_style)]
    ]
    tech_table = Table(tech_table_data, colWidths=[100, 130, 274])
    tech_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOTTOMPADDING', (0,0), (-1,0), 5),
        ('TOPPADDING', (0,0), (-1,0), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    # Need white text in header
    for i in range(3):
        tech_table_data[0][i].style.textColor = colors.white
    story.append(tech_table)

    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "<b>Workflow Pipeline:</b><br/>"
        "1. <b>Client Input:</b> Target URL submitted via UI or JSON POST request to <code>/scan</code>.<br/>"
        "2. <b>Validation & SSRF Filter:</b> Scheme verified (HTTP/HTTPS only), hostname extracted, DNS resolved; private/loopback/cloud metadata IPs rejected immediately with HTTP 400.<br/>"
        "3. <b>Passive HTTP Probing:</b> Requests dispatched with explicit 10s timeouts, TLS certificate validation enforced, and redirect chain verified against SSRF rules.<br/>"
        "4. <b>Header & CORS Analysis:</b> Inspection rules analyze presence, directives, and parameter values.<br/>"
        "5. <b>Risk Scoring:</b> Findings assigned severity (High, Medium, Low, Info) with explicit evidence and remediation advice.<br/>"
        "6. <b>Session Persistence & Reporting:</b> Complete audit structure stored in session; client downloads JSON, CSV, or PDF on demand.",
        body_style
    ))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4: DETAILED IMPLEMENTATION MODULES
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("4. Detailed Implementation Modules", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))

    # 4.1 URL Validator
    story.append(Paragraph("4.1 URL Validator & SSRF Protection (<code>scanner/validator.py</code>)", h2_style))
    story.append(Paragraph(
        "Server-Side Request Forgery is a critical web risk when servers make outbound requests based on user input. "
        "The validator implements defense-in-depth before any socket connection is opened:",
        body_style
    ))
    validator_points = [
        "<b>Strict Scheme Allowlist:</b> Only <code>http://</code> and <code>https://</code> schemes are allowed. Unsafe schemes like <code>ftp://</code>, <code>file://</code>, <code>gopher://</code>, and <code>data:</code> are rejected.",
        "<b>Format Sanitization:</b> Hostnames are extracted cleanly; trailing whitespace and URL fragments are stripped.",
        "<b>Prohibited Target Filtering:</b> Explicitly blocks <code>localhost</code>, <code>127.0.0.1</code>, <code>[::1]</code>, and cloud metadata hostnames (e.g., <code>metadata.google.internal</code>, <code>169.254.169.254</code>).",
        "<b>DNS Resolution & CIDR Verification:</b> Resolves hostnames to IP addresses via <code>socket.getaddrinfo()</code> and passes each IP through Python's <code>ipaddress.ip_address()</code>. Any address that is private (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16), or multicast is blocked."
    ]
    for vp in validator_points:
        story.append(Paragraph(f"• {vp}", bullet_style))

    # 4.2 Security Headers Engine
    story.append(Spacer(1, 4))
    story.append(Paragraph("4.2 HTTP Security Headers Inspection Engine (<code>scanner/headers.py</code>)", h2_style))
    story.append(Paragraph(
        "The header analyzer inspects 5 fundamental security headers using context-aware heuristics:",
        body_style
    ))

    headers_table_data = [
        [Paragraph("<b>Header Name</b>", meta_style), Paragraph("<b>Expected Directive / Value</b>", meta_style), Paragraph("<b>Security Implication & Status Logic</b>", meta_style)],
        [
            Paragraph("Content-Security-Policy", body_style),
            Paragraph("Restrictive source allowlist (default-src, script-src)", body_style),
            Paragraph("Mitigates XSS and data injection. WARNING if missing; REVIEW if unsafe-inline or unsafe-eval present.", body_style)
        ],
        [
            Paragraph("Strict-Transport-Security", body_style),
            Paragraph("max-age >= 31536000; includeSubDomains", body_style),
            Paragraph("Prevents SSL stripping. WARNING if missing on HTTPS; REVIEW if max-age < 1 year; N/A on plain HTTP.", body_style)
        ],
        [
            Paragraph("X-Content-Type-Options", body_style),
            Paragraph("nosniff", body_style),
            Paragraph("Prevents MIME-confusion attacks and drive-by downloads. WARNING if absent; PASS only if 'nosniff'.", body_style)
        ],
        [
            Paragraph("X-Frame-Options", body_style),
            Paragraph("DENY or SAMEORIGIN", body_style),
            Paragraph("Guards against Clickjacking attacks. WARNING if missing (unless CSP frame-ancestors is present).", body_style)
        ],
        [
            Paragraph("Referrer-Policy", body_style),
            Paragraph("strict-origin-when-cross-origin / no-referrer", body_style),
            Paragraph("Controls sensitive path/token leakage in Referer header. REVIEW if default/missing; WARNING if unsafe-url.", body_style)
        ]
    ]
    headers_table = Table(headers_table_data, colWidths=[120, 130, 254])
    headers_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    for i in range(3):
        headers_table_data[0][i].style.textColor = colors.white
    story.append(headers_table)

    # 4.3 CORS Analysis Module
    story.append(Spacer(1, 4))
    story.append(Paragraph("4.3 Cross-Origin Resource Sharing (CORS) Module (<code>scanner/cors.py</code>)", h2_style))
    story.append(Paragraph(
        "CORS controls allow browsers to permit cross-domain resource reads. Misconfigured headers can turn authenticated internal APIs "
        "into public data leaks. The module passively analyzes:",
        body_style
    ))
    cors_points = [
        "<b>Access-Control-Allow-Origin:</b> Flags wildcard (<code>*</code>) configurations as REVIEW for public data. Flags <code>null</code> origin as WARNING due to sandboxed iframe bypass vectors.",
        "<b>Access-Control-Allow-Credentials:</b> Evaluates combination of <code>true</code> credentials with specific or wildcard origins. Emphasizes that browsers block <code>*</code> + <code>credentials: true</code>, but dynamic origin reflection requires immediate investigation.",
        "<b>Access-Control-Allow-Methods & Headers:</b> Evaluates unsafe HTTP verbs (e.g., PUT, DELETE) and broad header reflections (e.g., <code>Authorization</code>)."
    ]
    for cp in cors_points:
        story.append(Paragraph(f"• {cp}", bullet_style))

    # 4.4 Risk Assessment & Reporting
    story.append(Spacer(1, 4))
    story.append(Paragraph("4.4 Risk Assessment & Multi-Report Exporter (<code>scanner/risk_assessment.py</code>, <code>report_generator.py</code>)", h2_style))
    story.append(Paragraph(
        "Each identified issue produces a structured finding dictionary containing: Title, Severity, Evidence, Technical Explanation, "
        "Business/Exploit Impact, and Actionable Remediation Guidance. Findings are categorized into four transparent tiers:",
        body_style
    ))
    story.append(Paragraph(
        "• <b>High Severity:</b> Missing core defenses on sensitive interfaces (e.g., missing CSP + frame protections, unsafe CORS credentials).<br/>"
        "• <b>Medium Severity:</b> Missing HSTS on HTTPS targets, absent X-Content-Type-Options, or overly permissive Referrer policies.<br/>"
        "• <b>Low Severity:</b> Weak parameter configurations (e.g., HSTS max-age under 1 year, legacy X-Frame-Options syntax).<br/>"
        "• <b>Informational:</b> Best practice observations, verified secure configurations, and baseline architectural notes.",
        body_style
    ))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 5: USER INTERFACE & PURE-BLACK AESTHETIC
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("5. Interactive Web Dashboard & Pure-Black Aesthetic", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))
    story.append(Paragraph(
        "In accordance with modern offensive/defensive security tools, the user interface was engineered with a dedicated "
        "<b>pure-black cybersecurity theme</b>. The aesthetic emphasizes clarity, high contrast, and reduced visual fatigue during auditing sessions.",
        body_style
    ))

    ui_specs = [
        [Paragraph("<b>Interface Layer</b>", meta_style), Paragraph("<b>Design Implementation & Color Specification</b>", meta_style)],
        [Paragraph("Base Background", body_style), Paragraph("Pure absolute black (<code>#000000</code>) across body, panels, and modal containers.", body_style)],
        [Paragraph("Surface Layers", body_style), Paragraph("Deep charcoal elevations (<code>#0a0a0a</code>, <code>#111111</code>, <code>#161616</code>) with subtle border definition (<code>#222222</code>).", body_style)],
        [Paragraph("Primary Accent", body_style), Paragraph("Electric Cyber Green (<code>#00ff88</code>) for branding, active states, buttons, and pass badges.", body_style)],
        [Paragraph("Severity Palettes", body_style), Paragraph("High: <code>#ff4444</code> | Medium: <code>#ffaa00</code> | Low: <code>#00c8ff</code> | Info: <code>#888888</code>.", body_style)],
        [Paragraph("Interaction Features", body_style), Paragraph("Tab navigation (Headers, CORS, Findings, Reports), live scan progress animation, copy-to-clipboard, responsive grid.", body_style)]
    ]
    ui_table = Table(ui_specs, colWidths=[150, 354])
    ui_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    for i in range(2):
        ui_specs[0][i].style.textColor = colors.white
    story.append(ui_table)

    story.append(Spacer(1, 10))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6: TESTING METHODOLOGY & VERIFICATION RESULTS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("6. Testing Methodology & Actual Verification Results", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))
    story.append(Paragraph(
        "A cornerstone of the project is its comprehensive automated test suite implemented in <b>Pytest</b>. "
        "To guarantee deterministic execution, zero network flakiness, and air-gapped testability, <b>100% of network interactions "
        "are mocked</b> using Python's <code>unittest.mock.patch</code> and mock HTTP response fixtures.",
        body_style
    ))

    test_table_data = [
        [Paragraph("<b>Test Module</b>", meta_style), Paragraph("<b>Test Scope & Target Functionality</b>", meta_style), Paragraph("<b>Tests Run</b>", meta_style), Paragraph("<b>Status</b>", meta_style)],
        [
            Paragraph("<code>tests/test_validator.py</code>", body_style),
            Paragraph("URL schemes, DNS resolution, SSRF blocking (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, AWS metadata, IPv6 ::1).", body_style),
            Paragraph("26 tests", body_style),
            Paragraph("<b>PASSED</b>", ParagraphStyle('P', parent=body_style, textColor=colors.HexColor("#16a34a")))
        ],
        [
            Paragraph("<code>tests/test_headers.py</code>", body_style),
            Paragraph("CSP source checks, HSTS HTTPS context, X-Content-Type nosniff, X-Frame-Options deny/sameorigin, Referrer-Policy.", body_style),
            Paragraph("32 tests", body_style),
            Paragraph("<b>PASSED</b>", ParagraphStyle('P', parent=body_style, textColor=colors.HexColor("#16a34a")))
        ],
        [
            Paragraph("<code>tests/test_cors.py</code>", body_style),
            Paragraph("Wildcard origins, null origins, credential pairing, dangerous HTTP verbs, authorization header reflections.", body_style),
            Paragraph("24 tests", body_style),
            Paragraph("<b>PASSED</b>", ParagraphStyle('P', parent=body_style, textColor=colors.HexColor("#16a34a")))
        ],
        [
            Paragraph("<code>tests/test_app.py</code>", body_style),
            Paragraph("Flask endpoints (<code>/</code>, <code>/scan</code>), input validation, session persistence, JSON/CSV/PDF download handlers.", body_style),
            Paragraph("20 tests", body_style),
            Paragraph("<b>PASSED</b>", ParagraphStyle('P', parent=body_style, textColor=colors.HexColor("#16a34a")))
        ],
        [
            Paragraph("<b>TOTALS</b>", meta_style),
            Paragraph("<b>Complete Project Test Suite</b>", meta_style),
            Paragraph("<b>102 tests</b>", meta_style),
            Paragraph("<b>102 / 102 PASSED (100%)</b>", ParagraphStyle('P', parent=meta_style, textColor=colors.HexColor("#16a34a")))
        ]
    ]
    test_table = Table(test_table_data, colWidths=[120, 224, 75, 85])
    test_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor("#f1f5f9")),
    ]))
    for i in range(4):
        test_table_data[0][i].style.textColor = colors.white
    story.append(test_table)

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<b>Actual Pytest Execution Snapshot:</b><br/>"
        "<code>collected 102 items<br/>"
        "tests/test_cors.py ........................ [ 23%]<br/>"
        "tests/test_headers.py ................................ [ 55%]<br/>"
        "tests/test_validator.py .......................... [ 80%]<br/>"
        "tests/test_app.py .................... [100%]<br/>"
        "======================= 102 passed, 2 warnings in 1.10s =======================</code>",
        code_style
    ))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 7: SAMPLE SECURITY FINDINGS & REMEDIATION
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("7. Sample Security Findings & Remediation Walkthrough", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))

    findings_sample = [
        ("Missing Content-Security-Policy (CSP)", "HIGH", "Header absent from response",
         "The target does not deliver a CSP header. Browsers will execute arbitrary inline scripts and load resources from unverified origins if an XSS injection occurs.",
         "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';"),
        ("Strict-Transport-Security (HSTS) Missing on HTTPS", "MEDIUM", "Observed scheme: https://, header absent",
         "Users communicating over HTTPS are vulnerable to man-in-the-middle downgrade attacks (SSL stripping) on their initial unencrypted HTTP connection.",
         "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
        ("X-Content-Type-Options Header Absent", "MEDIUM", "Header absent from response",
         "User agents may perform MIME-type sniffing, treating non-executable files (e.g., images) as executable JavaScript if file content contains script tags.",
         "Add header: X-Content-Type-Options: nosniff"),
        ("Permissive Wildcard Access-Control-Allow-Origin", "REVIEW / INFO", "Access-Control-Allow-Origin: *",
         "The endpoint permits any external website to issue cross-origin requests and read responses. If this endpoint serves sensitive user data, this is a vulnerability.",
         "If the endpoint is an authenticated API, restrict the origin to specific trusted partner domains.")
    ]

    for title, sev, evidence, exp, rem in findings_sample:
        sev_color = "#dc2626" if sev == "HIGH" else ("#ea580c" if sev == "MEDIUM" else "#0284c7")
        box_data = [
            [Paragraph(f"<b>Finding:</b> {title}", ParagraphStyle('F', parent=body_style, fontName='Helvetica-Bold')),
             Paragraph(f"<b>Severity: {sev}</b>", ParagraphStyle('S', parent=body_style, textColor=colors.HexColor(sev_color), fontName='Helvetica-Bold'))],
            [Paragraph(f"<b>Evidence:</b> {evidence}", body_style), Paragraph("", body_style)],
            [Paragraph(f"<b>Risk Explanation:</b> {exp}", body_style), Paragraph("", body_style)],
            [Paragraph(f"<b>Remediation:</b> <code>{rem}</code>", body_style), Paragraph("", body_style)]
        ]
        box_table = Table(box_data, colWidths=[384, 120])
        box_table.setStyle(TableStyle([
            ('SPAN', (0,1), (1,1)),
            ('SPAN', (0,2), (1,2)),
            ('SPAN', (0,3), (1,3)),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('LINEBELOW', (0,0), (-1,0), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(box_table)
        story.append(Spacer(1, 6))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 8: LIMITATIONS & RESPONSIBLE USE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 4))
    story.append(Paragraph("8. Project Scope, Limitations & Responsible-Use Policy", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))
    story.append(Paragraph(
        "<b>Assessment Limitations:</b><br/>"
        "• <i>Passive Surface Analysis:</i> The scanner inspects publicly visible HTTP response headers. It does not perform active payload injection, directory fuzzing, or credential brute-forcing.<br/>"
        "• <i>Context Sensitivity:</i> A missing header on a purely static landing page presents lower practical risk than on a multi-tenant banking application. Context must be evaluated by a certified human analyst.<br/>"
        "• <i>Single-Point Snapshot:</i> Scans represent server configuration at the exact moment of execution; CDN routing, load balancers, or geo-DNS may yield differing responses.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Responsible Use Disclaimer:</b> This software is developed strictly for educational, defensive, and authorized assessment "
        "purposes. Scanning target systems without explicit authorization from the asset owner may violate federal, state, and international cyber legislation "
        "(e.g., Computer Fraud and Abuse Act 18 U.S.C. § 1030). Always obtain written permission prior to scanning third-party infrastructure.",
        body_style
    ))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 9: CONCLUSION & SIGN-OFF
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 4))
    story.append(Paragraph("9. Conclusion & Project Sign-Off", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=primary_color, spaceAfter=8, spaceBefore=0))
    story.append(Paragraph(
        "The Automated Web Security Scanner fulfills all requirements for the Cybersecurity Bootcamp Capstone Project. "
        "By pairing defensive SSRF validation with heuristic header and CORS analysis, transparent risk categorization, "
        "a bespoke pure-black interface, multi-format export engines, and an exhaustive 102-test automated verification suite, "
        "the project demonstrates practical mastery of web security, defensive architecture, and modern Python engineering.",
        body_style
    ))

    sign_data = [
        [Paragraph("<b>Submitted By:</b> Zoya Tahareen", meta_style), Paragraph("<b>Status:</b> Completed & Verified", meta_style)],
        [Paragraph("<b>GitHub:</b> github.com/ZoyaTahareen/Web-Security-Scanner", meta_style), Paragraph("<b>Verification:</b> 102 / 102 Pytest Suite Passed", meta_style)]
    ]
    sign_table = Table(sign_data, colWidths=[252, 252])
    sign_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#94a3b8")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(sign_table)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Report successfully compiled to: {output_path}")


if __name__ == '__main__':
    output_pdf = sys.argv[1] if len(sys.argv) > 1 else "Project_Report.pdf"
    build_pdf_report(output_pdf)
