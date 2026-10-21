"""
scanner/cors.py
Passive CORS configuration analysis.

Inspects:
  - Access-Control-Allow-Origin
  - Access-Control-Allow-Credentials
  - Access-Control-Allow-Methods
  - Access-Control-Allow-Headers

Does NOT transmit credentials or attempt to access private data.
Does NOT treat every wildcard as an exploitable vulnerability —
  context matters and is explained in each finding.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_cors(headers: dict) -> dict:
    """
    Inspect CORS headers and return a structured analysis dict.

    Returns
    -------
    dict with keys:
      present        – True if any CORS header was found
      headers        – list of individual header analyses
      summary        – plain-language summary
      concerns       – list of concern strings (may be empty)
    """
    acao  = _get(headers, "Access-Control-Allow-Origin")
    acac  = _get(headers, "Access-Control-Allow-Credentials")
    acam  = _get(headers, "Access-Control-Allow-Methods")
    acah  = _get(headers, "Access-Control-Allow-Headers")

    any_present = any(v is not None for v in [acao, acac, acam, acah])

    header_details = [
        _analyse_acao(acao),
        _analyse_acac(acac, acao),
        _analyse_acam(acam),
        _analyse_acah(acah),
    ]

    concerns = [h["concern"] for h in header_details if h["concern"]]

    if not any_present:
        summary = (
            "No CORS headers were detected in the response. "
            "This is normal for websites that do not intentionally expose resources "
            "to other origins. It does not indicate a security problem."
        )
    elif not concerns:
        summary = (
            "CORS headers are present and no immediately concerning configurations "
            "were identified. Review the values below for accuracy."
        )
    else:
        summary = (
            f"{len(concerns)} potentially noteworthy CORS configuration(s) detected. "
            "See individual header details for context and recommended actions."
        )

    return {
        "present": any_present,
        "headers": header_details,
        "summary": summary,
        "concerns": concerns,
    }


# ---------------------------------------------------------------------------
# Individual header analysers
# ---------------------------------------------------------------------------

def _analyse_acao(value: str | None) -> dict:
    name = "Access-Control-Allow-Origin"
    purpose = (
        "Specifies which origin(s) are permitted to read responses to cross-origin "
        "requests. A value of '*' allows any origin to read the response."
    )

    if value is None:
        return _hdr(
            name=name, value=None, status="NOT SET", purpose=purpose,
            observation="Header not present.",
            concern="",
            recommendation="No action required if cross-origin access is not intended.",
        )

    if value.strip() == "*":
        return _hdr(
            name=name, value=value, status="REVIEW", purpose=purpose,
            observation="Wildcard origin (*) detected.",
            concern=(
                "A wildcard ACAO policy allows any website to read the response body. "
                "This is appropriate for truly public APIs and CDN resources, but "
                "inappropriate for endpoints that return user-specific or sensitive data. "
                "By itself, a wildcard does not allow credentials to accompany the request "
                "(browsers block that combination)."
            ),
            recommendation=(
                "Verify this endpoint only returns public data. "
                "If responses include user-specific content, restrict ACAO to "
                "specific trusted origins."
            ),
        )

    if value.strip().lower() == "null":
        return _hdr(
            name=name, value=value, status="WARNING", purpose=purpose,
            observation="Origin value is 'null'.",
            concern=(
                "'null' origin can be sent by sandboxed iframes, local files, "
                "and certain redirects. Allowing 'null' may grant unexpected access "
                "to these contexts."
            ),
            recommendation=(
                "Replace 'null' with explicit trusted origins. "
                "Avoid using 'null' as an allowed origin."
            ),
        )

    return _hdr(
        name=name, value=value, status="INFO", purpose=purpose,
        observation=f"Origin restricted to: {value}",
        concern="",
        recommendation=(
            "Confirm this origin list is intentional and does not include "
            "untrusted or user-controlled values."
        ),
    )


def _analyse_acac(acac_value: str | None, acao_value: str | None) -> dict:
    name = "Access-Control-Allow-Credentials"
    purpose = (
        "When set to 'true', allows browsers to include cookies and HTTP "
        "authentication in cross-origin requests."
    )

    if acac_value is None:
        return _hdr(
            name=name, value=None, status="NOT SET", purpose=purpose,
            observation="Header not present — credentials will not be included in CORS requests.",
            concern="",
            recommendation="No action required.",
        )

    if acac_value.strip().lower() == "true":
        acao_is_wildcard = (acao_value or "").strip() == "*"
        if acao_is_wildcard:
            return _hdr(
                name=name, value=acac_value, status="INFO", purpose=purpose,
                observation=(
                    "Allow-Credentials: true combined with Allow-Origin: *. "
                    "Browsers reject this combination — credentials will not be sent."
                ),
                concern=(
                    "Although browsers block this combination, having both set may "
                    "indicate a misconfigured CORS policy that could become problematic "
                    "if the origin is later changed to a specific value."
                ),
                recommendation=(
                    "If credentials are required, set Allow-Origin to a specific trusted "
                    "origin instead of the wildcard."
                ),
            )
        return _hdr(
            name=name, value=acac_value, status="REVIEW", purpose=purpose,
            observation=(
                "Credentials are permitted with cross-origin requests to the "
                f"allowed origin: {acao_value or 'unspecified'}."
            ),
            concern=(
                "Allowing credentials expands the trust placed in the allowed origin. "
                "If an attacker can influence the ACAO value, they may be able to "
                "read authenticated responses. This requires further investigation "
                "beyond this passive header check."
            ),
            recommendation=(
                "Ensure the allowed origin is strictly controlled and cannot be "
                "influenced by user input. Restrict CORS with credentials to the "
                "minimum necessary origins."
            ),
        )

    return _hdr(
        name=name, value=acac_value, status="INFO", purpose=purpose,
        observation=f"Value is '{acac_value}' — credentials will not be included.",
        concern="",
        recommendation="No action required.",
    )


def _analyse_acam(value: str | None) -> dict:
    name = "Access-Control-Allow-Methods"
    purpose = (
        "Lists the HTTP methods permitted in cross-origin requests to this resource."
    )
    broad_methods = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}

    if value is None:
        return _hdr(
            name=name, value=None, status="NOT SET", purpose=purpose,
            observation="Header not present.",
            concern="",
            recommendation="No action required if broad method access is not intended.",
        )

    methods = {m.strip().upper() for m in value.split(",")}
    found_broad = methods & broad_methods

    if found_broad:
        return _hdr(
            name=name, value=value, status="REVIEW", purpose=purpose,
            observation=f"Methods present: {', '.join(sorted(methods))}.",
            concern=(
                f"Broad methods detected: {', '.join(sorted(found_broad))}. "
                "Cross-origin access to mutating or sensitive methods should be "
                "explicitly required and justified."
            ),
            recommendation=(
                "Restrict allowed methods to only those required by legitimate "
                "cross-origin clients."
            ),
        )

    return _hdr(
        name=name, value=value, status="INFO", purpose=purpose,
        observation=f"Methods present: {', '.join(sorted(methods))}.",
        concern="",
        recommendation="Verify these methods are the minimum required.",
    )


def _analyse_acah(value: str | None) -> dict:
    name = "Access-Control-Allow-Headers"
    purpose = (
        "Lists the request headers that cross-origin clients are allowed to include."
    )
    sensitive_headers = {"authorization", "cookie", "x-api-key", "x-auth-token"}

    if value is None:
        return _hdr(
            name=name, value=None, status="NOT SET", purpose=purpose,
            observation="Header not present.",
            concern="",
            recommendation="No action required.",
        )

    if value.strip() == "*":
        return _hdr(
            name=name, value=value, status="REVIEW", purpose=purpose,
            observation="Wildcard (*) — all request headers are permitted.",
            concern=(
                "Allowing all headers may expose sensitive header fields to "
                "cross-origin requests unnecessarily."
            ),
            recommendation=(
                "Enumerate only the specific headers your API requires."
            ),
        )

    provided = {h.strip().lower() for h in value.split(",")}
    found_sensitive = provided & sensitive_headers

    if found_sensitive:
        return _hdr(
            name=name, value=value, status="REVIEW", purpose=purpose,
            observation=f"Sensitive headers allowed: {', '.join(sorted(found_sensitive))}.",
            concern=(
                "Permitting authentication or cookie headers in cross-origin requests "
                "may be appropriate for authenticated APIs, but should be intentional."
            ),
            recommendation=(
                "Confirm this is required. Pair with a restricted Allow-Origin "
                "to limit which origins can include these headers."
            ),
        )

    return _hdr(
        name=name, value=value, status="INFO", purpose=purpose,
        observation=f"Allowed headers: {value}.",
        concern="",
        recommendation="Verify these are the minimum headers required.",
    )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _get(headers: dict, name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def _hdr(
    *,
    name: str,
    value: str | None,
    status: str,
    purpose: str,
    observation: str,
    concern: str,
    recommendation: str,
) -> dict:
    return {
        "name": name,
        "value": value,
        "status": status,
        "purpose": purpose,
        "observation": observation,
        "concern": concern,
        "recommendation": recommendation,
    }
