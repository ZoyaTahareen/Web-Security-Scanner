"""
scanner/__init__.py
Exposes the main scan() convenience function for the scanner package.
"""

from .validator import validate_url
from .headers import analyze_headers
from .cors import analyze_cors
from .risk_assessment import assess_risk


def scan(url: str) -> dict:
    """
    Run a full security scan against *url*.

    Returns a structured dict consumed by the Flask app and report generator.
    Raises ValueError for invalid/disallowed URLs so the caller can surface a
    user-friendly message without catching broad exceptions.
    """
    import datetime, requests

    # 1. Validate (raises ValueError on failure)
    validated_url = validate_url(url)

    # 2. Fetch — passive HEAD first, fall back to GET for servers that reject HEAD
    timeout = 10
    session = requests.Session()
    session.max_redirects = 5

    try:
        response = session.head(
            validated_url,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )
        # Some servers return 405 for HEAD; retry with GET
        if response.status_code == 405:
            response = session.get(
                validated_url,
                timeout=timeout,
                allow_redirects=True,
                verify=True,
                stream=True,
            )
            # Read only a small chunk to honour response-size limits
            _ = response.content[:4096]
    except requests.exceptions.SSLError as exc:
        raise ValueError(f"TLS/SSL certificate verification failed: {exc}") from exc
    except requests.exceptions.ConnectionError as exc:
        raise ValueError(f"Connection failed: {exc}") from exc
    except requests.exceptions.Timeout:
        raise ValueError("Request timed out. The target server did not respond in time.")
    except requests.exceptions.TooManyRedirects:
        raise ValueError("Too many redirects. The target URL may be misconfigured.")
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"HTTP request failed: {exc}") from exc

    headers = dict(response.headers)
    status_code = response.status_code
    final_url = response.url

    # 3. Validate redirect destination (SSRF check after redirect)
    validate_url(final_url)

    # 4. Analyse
    header_results = analyze_headers(headers)
    cors_results = analyze_cors(headers)
    findings = assess_risk(header_results, cors_results)

    return {
        "target_url": validated_url,
        "final_url": final_url,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "http_status": status_code,
        "headers_raw": headers,
        "header_analysis": header_results,
        "cors_analysis": cors_results,
        "findings": findings,
    }
