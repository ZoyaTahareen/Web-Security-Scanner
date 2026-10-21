"""
scanner/risk_assessment.py
Translate header and CORS analysis results into prioritised findings.

Severity levels (lowest → highest):
  Informational  – context or best-practice notes; no immediate action needed
  Low            – minor gaps; limited exploitability alone
  Medium         – real weakness; should be addressed
  High           – significant misconfiguration; prioritise remediation

Rules are transparent and documented inline.
High severity is NOT assigned simply because a header is absent.
"""

from __future__ import annotations

# Severity constants
INFO   = "Informational"
LOW    = "Low"
MEDIUM = "Medium"
HIGH   = "High"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def assess_risk(header_results: list[dict], cors_results: dict) -> list[dict]:
    """
    Produce a list of Finding dicts from header and CORS analysis.

    Each Finding contains:
      title, severity, evidence, explanation, impact, fix, category
    """
    findings: list[dict] = []
    findings.extend(_assess_headers(header_results))
    findings.extend(_assess_cors(cors_results))
    return findings


# ---------------------------------------------------------------------------
# Header findings
# ---------------------------------------------------------------------------

# Maps status → base severity for missing/misconfigured headers.
# "REVIEW" means more context is needed before assigning a definitive severity.
_HEADER_SEVERITY_MAP = {
    "Content-Security-Policy": {
        "WARNING": MEDIUM,   # Absent CSP is a real gap
        "REVIEW":  LOW,      # Exists but has weaknesses
    },
    "Strict-Transport-Security": {
        "WARNING": MEDIUM,   # Absent HSTS on HTTPS is noteworthy
        "REVIEW":  LOW,
        "NOT APPLICABLE": None,  # HTTP site — not a finding
    },
    "X-Content-Type-Options": {
        "WARNING": LOW,      # Absent, but limited direct impact
        "REVIEW":  LOW,
    },
    "X-Frame-Options": {
        "WARNING": MEDIUM,   # Clickjacking risk
        "REVIEW":  LOW,
    },
    "Referrer-Policy": {
        "WARNING": LOW,
        "REVIEW":  INFO,     # Absent RP → browser default, not critical
    },
}


def _assess_headers(results: list[dict]) -> list[dict]:
    findings = []
    for r in results:
        name   = r["name"]
        status = r["status"]

        severity_map = _HEADER_SEVERITY_MAP.get(name, {})
        severity = severity_map.get(status)

        if severity is None:
            continue  # PASS or NOT APPLICABLE — no finding

        findings.append(_finding(
            title=f"{'Missing' if not r['present'] else 'Misconfigured'} {name}",
            severity=severity,
            evidence=(
                f"Header absent." if not r["present"]
                else f"Observed value: {r['value']}"
            ),
            explanation=r["implications"],
            impact=_header_impact(name, status),
            fix=r["remediation"],
            category="Security Header",
        ))

    return findings


def _header_impact(name: str, status: str) -> str:
    impacts = {
        "Content-Security-Policy": {
            "WARNING": (
                "Increases vulnerability to Cross-Site Scripting (XSS) and "
                "data injection attacks."
            ),
            "REVIEW": (
                "Weakened CSP may still allow certain injection attacks. "
                "Effectiveness depends on the specific directives."
            ),
        },
        "Strict-Transport-Security": {
            "WARNING": (
                "Users may be susceptible to protocol-downgrade attacks and "
                "man-in-the-middle interception if HTTP connections are possible."
            ),
            "REVIEW": (
                "Short HSTS duration limits protection window. "
                "Users may revert to HTTP after the policy expires."
            ),
        },
        "X-Content-Type-Options": {
            "WARNING": (
                "Some browsers may execute uploaded files with incorrect MIME types, "
                "potentially enabling content-injection attacks."
            ),
            "REVIEW": "Incorrect value may not be honoured by browsers.",
        },
        "X-Frame-Options": {
            "WARNING": (
                "Pages may be embeddable in iframes, enabling clickjacking attacks "
                "that trick users into performing unintended actions."
            ),
            "REVIEW": (
                "Deprecated or unrecognised value may not be honoured by "
                "modern browsers."
            ),
        },
        "Referrer-Policy": {
            "WARNING": (
                "Full URLs (including query strings) may be leaked as referrer "
                "information to third-party sites."
            ),
            "REVIEW": (
                "Browser default behaviour may vary; explicit policy is clearer."
            ),
        },
    }
    return impacts.get(name, {}).get(status, "Review this configuration.")


# ---------------------------------------------------------------------------
# CORS findings
# ---------------------------------------------------------------------------

def _assess_cors(cors_results: dict) -> list[dict]:
    findings = []

    for hdr in cors_results.get("headers", []):
        name    = hdr["name"]
        status  = hdr["status"]
        concern = hdr.get("concern", "")

        if not concern:
            continue  # INFO / NOT SET with no concern — skip

        severity, impact = _cors_severity(name, status, hdr)

        findings.append(_finding(
            title=f"CORS: {name} — {status}",
            severity=severity,
            evidence=(
                f"Observed value: {hdr['value']}" if hdr["value"] is not None
                else "Header not set."
            ),
            explanation=concern,
            impact=impact,
            fix=hdr["recommendation"],
            category="CORS",
        ))

    return findings


def _cors_severity(name: str, status: str, hdr: dict) -> tuple[str, str]:
    """Return (severity, impact) for a CORS concern."""
    n = name.lower()

    if "allow-credentials" in n and status == "REVIEW":
        return MEDIUM, (
            "Credential inclusion in CORS requests raises the impact of any "
            "origin-validation weakness. Authenticated data could be read by "
            "a cross-origin attacker if the ACAO value is insufficiently restricted."
        )

    if "allow-origin" in n:
        if status == "WARNING":  # 'null' origin
            return MEDIUM, (
                "'null' origin may allow sandboxed pages or local files to "
                "read cross-origin responses, depending on browser handling."
            )
        if status == "REVIEW":   # wildcard
            return LOW, (
                "Any origin can read response bodies. For public APIs this may "
                "be intentional. The actual risk depends on what data the "
                "endpoint returns."
            )

    if "allow-methods" in n and status == "REVIEW":
        return LOW, (
            "Cross-origin clients may invoke broad HTTP methods. "
            "Risk depends on whether the server enforces separate authorisation checks."
        )

    if "allow-headers" in n and status == "REVIEW":
        return LOW, (
            "Cross-origin requests may include sensitive headers. "
            "Actual impact depends on how the server processes them."
        )

    return INFO, "Review this CORS configuration for business context."


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _finding(
    *,
    title: str,
    severity: str,
    evidence: str,
    explanation: str,
    impact: str,
    fix: str,
    category: str,
) -> dict:
    return {
        "title":       title,
        "severity":    severity,
        "evidence":    evidence,
        "explanation": explanation,
        "impact":      impact,
        "fix":         fix,
        "category":    category,
    }
