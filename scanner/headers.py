"""
scanner/headers.py
Analyse HTTP security response headers.

Inspected headers:
  1. Content-Security-Policy (CSP)
  2. Strict-Transport-Security (HSTS)
  3. X-Content-Type-Options
  4. X-Frame-Options
  5. Referrer-Policy

Each check returns a structured dict with:
  name, present, value, status, purpose, implications, remediation
"""

from __future__ import annotations

# Status constants
PASS = "PASS"
WARNING = "WARNING"
REVIEW = "REVIEW"
NOT_APPLICABLE = "NOT APPLICABLE"


# ---------------------------------------------------------------------------
# Individual header checks
# ---------------------------------------------------------------------------

def _check_csp(headers: dict) -> dict:
    """Content-Security-Policy"""
    name = "Content-Security-Policy"
    purpose = (
        "Restricts the sources from which the browser may load resources "
        "(scripts, styles, images, etc.), significantly reducing XSS and "
        "data-injection attack surface."
    )

    raw = _get_header(headers, name)
    if raw is None:
        return _result(
            name=name,
            present=False,
            value=None,
            status=WARNING,
            purpose=purpose,
            implications=(
                "Without CSP, browsers will execute inline scripts and load "
                "resources from any origin, making XSS attacks easier to exploit."
            ),
            remediation=(
                "Define a Content-Security-Policy header. Start with a strict "
                "policy such as: default-src 'self'; then incrementally expand "
                "only what your application requires."
            ),
        )

    # Basic value review
    concerns = []
    lower = raw.lower()
    if "unsafe-inline" in lower:
        concerns.append("'unsafe-inline' permits inline scripts/styles — weakens XSS protection.")
    if "unsafe-eval" in lower:
        concerns.append("'unsafe-eval' permits eval() — a common XSS vector.")
    if "default-src *" in lower or "script-src *" in lower:
        concerns.append("Wildcard source (*) allows scripts from any origin.")

    if concerns:
        return _result(
            name=name,
            present=True,
            value=raw,
            status=REVIEW,
            purpose=purpose,
            implications=" | ".join(concerns),
            remediation=(
                "Remove 'unsafe-inline', 'unsafe-eval', and wildcard sources. "
                "Use nonces or hashes for inline content and restrict script-src "
                "to trusted origins."
            ),
        )

    return _result(
        name=name,
        present=True,
        value=raw,
        status=PASS,
        purpose=purpose,
        implications="No immediately obvious weaknesses detected in the policy value.",
        remediation=(
            "Periodically review and tighten the policy. Consider enabling a "
            "CSP report-uri/report-to endpoint to monitor violations."
        ),
    )


def _check_hsts(headers: dict, is_https: bool = True) -> dict:
    """Strict-Transport-Security"""
    name = "Strict-Transport-Security"
    purpose = (
        "Instructs browsers to access the site only over HTTPS for a specified "
        "duration, preventing protocol downgrade and cookie-hijacking attacks."
    )

    if not is_https:
        return _result(
            name=name,
            present=False,
            value=None,
            status=NOT_APPLICABLE,
            purpose=purpose,
            implications=(
                "HSTS is only meaningful over HTTPS. The scanned URL uses HTTP, "
                "so this header would be ignored by browsers."
            ),
            remediation=(
                "Redirect all HTTP traffic to HTTPS and serve HSTS only on the "
                "HTTPS endpoint."
            ),
        )

    raw = _get_header(headers, name)
    if raw is None:
        return _result(
            name=name,
            present=False,
            value=None,
            status=WARNING,
            purpose=purpose,
            implications=(
                "Without HSTS, browsers may downgrade connections to HTTP or accept "
                "invalid certificates without warning."
            ),
            remediation=(
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
        )

    # Validate max-age
    import re
    match = re.search(r"max-age\s*=\s*(\d+)", raw, re.IGNORECASE)
    if match:
        max_age = int(match.group(1))
        if max_age < 2592000:  # 30 days
            return _result(
                name=name,
                present=True,
                value=raw,
                status=REVIEW,
                purpose=purpose,
                implications=(
                    f"max-age of {max_age} seconds ({max_age // 86400} days) is quite short. "
                    "Short durations reduce HSTS effectiveness."
                ),
                remediation="Increase max-age to at least 31536000 (1 year).",
            )

    return _result(
        name=name,
        present=True,
        value=raw,
        status=PASS,
        purpose=purpose,
        implications=(
            "HSTS is configured. Note: this header check alone cannot confirm "
            "the overall TLS configuration of the server."
        ),
        remediation=(
            "Ensure includeSubDomains and preload directives are present if appropriate."
        ),
    )


def _check_xcto(headers: dict) -> dict:
    """X-Content-Type-Options"""
    name = "X-Content-Type-Options"
    purpose = (
        "Prevents browsers from MIME-sniffing a response away from the declared "
        "content type, reducing exposure to certain content-injection attacks."
    )

    raw = _get_header(headers, name)
    if raw is None:
        return _result(
            name=name,
            present=False,
            value=None,
            status=WARNING,
            purpose=purpose,
            implications=(
                "Without this header, older browsers may MIME-sniff responses, "
                "potentially executing content as a different type than intended."
            ),
            remediation="Add: X-Content-Type-Options: nosniff",
        )

    if raw.strip().lower() == "nosniff":
        return _result(
            name=name,
            present=True,
            value=raw,
            status=PASS,
            purpose=purpose,
            implications="Correctly configured with the 'nosniff' directive.",
            remediation="No action required.",
        )

    return _result(
        name=name,
        present=True,
        value=raw,
        status=REVIEW,
        purpose=purpose,
        implications=(
            f"Unexpected value '{raw}'. The only valid value for this header is 'nosniff'."
        ),
        remediation="Set the header to exactly: X-Content-Type-Options: nosniff",
    )


def _check_xfo(headers: dict) -> dict:
    """X-Frame-Options"""
    name = "X-Frame-Options"
    purpose = (
        "Controls whether the browser allows the page to be embedded in a frame "
        "or iframe, protecting against clickjacking attacks."
    )

    raw = _get_header(headers, name)
    if raw is None:
        # Check if CSP covers frame-ancestors instead
        csp_raw = _get_header(headers, "Content-Security-Policy") or ""
        if "frame-ancestors" in csp_raw.lower():
            return _result(
                name=name,
                present=False,
                value=None,
                status=PASS,
                purpose=purpose,
                implications=(
                    "X-Frame-Options is absent, but a Content-Security-Policy with "
                    "'frame-ancestors' directive was detected, which is the modern "
                    "equivalent and takes precedence in compliant browsers."
                ),
                remediation="No action required if CSP frame-ancestors is correctly configured.",
            )
        return _result(
            name=name,
            present=False,
            value=None,
            status=WARNING,
            purpose=purpose,
            implications=(
                "Without this header (or CSP frame-ancestors), the page may be "
                "embeddable in iframes, facilitating clickjacking attacks."
            ),
            remediation=(
                "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN  "
                "Alternatively, use CSP frame-ancestors."
            ),
        )

    val = raw.strip().upper()
    if val in ("DENY", "SAMEORIGIN"):
        return _result(
            name=name,
            present=True,
            value=raw,
            status=PASS,
            purpose=purpose,
            implications="Clickjacking protection is in place.",
            remediation="No action required.",
        )

    if val.startswith("ALLOW-FROM"):
        return _result(
            name=name,
            present=True,
            value=raw,
            status=REVIEW,
            purpose=purpose,
            implications=(
                "ALLOW-FROM is deprecated and not supported by modern browsers. "
                "Verify that the intended restriction is enforced."
            ),
            remediation=(
                "Replace ALLOW-FROM with a CSP frame-ancestors directive, "
                "which is supported by current browsers."
            ),
        )

    return _result(
        name=name,
        present=True,
        value=raw,
        status=REVIEW,
        purpose=purpose,
        implications=f"Unrecognised value '{raw}'. May not be interpreted as intended.",
        remediation="Use DENY or SAMEORIGIN.",
    )


def _check_referrer_policy(headers: dict) -> dict:
    """Referrer-Policy"""
    name = "Referrer-Policy"
    purpose = (
        "Controls how much referrer information is sent with requests, "
        "reducing the risk of leaking sensitive URL fragments to third parties."
    )

    # Policies considered strong
    strong_policies = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    weak_policies = {"unsafe-url", ""}

    raw = _get_header(headers, name)
    if raw is None:
        return _result(
            name=name,
            present=False,
            value=None,
            status=REVIEW,
            purpose=purpose,
            implications=(
                "Without an explicit Referrer-Policy, browsers fall back to "
                "'strict-origin-when-cross-origin' (modern default). "
                "Older browsers may send full URLs as the referrer."
            ),
            remediation=(
                "Add: Referrer-Policy: strict-origin-when-cross-origin  "
                "to make the policy explicit and consistent."
            ),
        )

    val = raw.strip().lower()
    # Handle comma-separated fallback lists
    policies = [p.strip() for p in val.split(",")]

    if any(p in weak_policies for p in policies):
        return _result(
            name=name,
            present=True,
            value=raw,
            status=WARNING,
            purpose=purpose,
            implications=(
                f"'{raw}' may send full URLs as referrer to third-party origins, "
                "potentially leaking sensitive path or query parameters."
            ),
            remediation=(
                "Replace with: Referrer-Policy: strict-origin-when-cross-origin"
            ),
        )

    if all(p in strong_policies for p in policies):
        return _result(
            name=name,
            present=True,
            value=raw,
            status=PASS,
            purpose=purpose,
            implications="Referrer information is appropriately restricted.",
            remediation="No immediate action required.",
        )

    return _result(
        name=name,
        present=True,
        value=raw,
        status=REVIEW,
        purpose=purpose,
        implications=f"Unrecognised policy value '{raw}'. Verify browser compatibility.",
        remediation="Use a well-known value such as 'strict-origin-when-cross-origin'.",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_headers(headers: dict, url: str = "") -> list[dict]:
    """
    Run all header checks and return a list of result dicts.

    Parameters
    ----------
    headers : dict
        Raw HTTP response headers (case-insensitive access handled internally).
    url : str
        The scanned URL — used to determine HTTPS context for HSTS.
    """
    is_https = url.lower().startswith("https://") if url else True
    return [
        _check_csp(headers),
        _check_hsts(headers, is_https=is_https),
        _check_xcto(headers),
        _check_xfo(headers),
        _check_referrer_policy(headers),
    ]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _get_header(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _result(
    *,
    name: str,
    present: bool,
    value: str | None,
    status: str,
    purpose: str,
    implications: str,
    remediation: str,
) -> dict:
    return {
        "name": name,
        "present": present,
        "value": value,
        "status": status,
        "purpose": purpose,
        "implications": implications,
        "remediation": remediation,
    }
