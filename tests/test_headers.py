"""
tests/test_headers.py
Tests for the security header analysis module.
Uses plain dicts to simulate HTTP response headers — no real requests.
"""

import pytest
from scanner.headers import analyze_headers, PASS, WARNING, REVIEW, NOT_APPLICABLE


def headers_status(results, name):
    """Return the status for a named header from analyze_headers output."""
    for h in results:
        if h['name'] == name:
            return h['status']
    raise KeyError(f"{name} not found in results")


def headers_result(results, name):
    """Return the full result dict for a named header."""
    for h in results:
        if h['name'] == name:
            return h
    raise KeyError(f"{name} not found in results")


# ── CSP ──────────────────────────────────────────────────────────────────────

class TestCSP:
    def test_missing_csp_is_warning(self):
        r = analyze_headers({})
        assert headers_status(r, 'Content-Security-Policy') == WARNING

    def test_missing_csp_not_present(self):
        r = analyze_headers({})
        assert headers_result(r, 'Content-Security-Policy')['present'] is False

    def test_good_csp_passes(self):
        hdrs = {'Content-Security-Policy': "default-src 'self'; script-src 'self'"}
        r = analyze_headers(hdrs)
        assert headers_status(r, 'Content-Security-Policy') == PASS

    def test_unsafe_inline_triggers_review(self):
        hdrs = {'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'"}
        r = analyze_headers(hdrs)
        assert headers_status(r, 'Content-Security-Policy') == REVIEW

    def test_unsafe_eval_triggers_review(self):
        hdrs = {'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-eval'"}
        r = analyze_headers(hdrs)
        assert headers_status(r, 'Content-Security-Policy') == REVIEW

    def test_wildcard_script_src_triggers_review(self):
        hdrs = {'Content-Security-Policy': "script-src *"}
        r = analyze_headers(hdrs)
        assert headers_status(r, 'Content-Security-Policy') == REVIEW

    def test_csp_value_recorded(self):
        val = "default-src 'self'"
        hdrs = {'Content-Security-Policy': val}
        r = analyze_headers(hdrs)
        assert headers_result(r, 'Content-Security-Policy')['value'] == val


# ── HSTS ─────────────────────────────────────────────────────────────────────

class TestHSTS:
    def test_missing_hsts_on_https_is_warning(self):
        r = analyze_headers({}, url='https://example.com')
        assert headers_status(r, 'Strict-Transport-Security') == WARNING

    def test_hsts_not_applicable_on_http(self):
        r = analyze_headers(
            {'Strict-Transport-Security': 'max-age=31536000'},
            url='http://example.com'
        )
        assert headers_status(r, 'Strict-Transport-Security') == NOT_APPLICABLE

    def test_good_hsts_passes(self):
        hdrs = {'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'}
        r = analyze_headers(hdrs, url='https://example.com')
        assert headers_status(r, 'Strict-Transport-Security') == PASS

    def test_short_max_age_triggers_review(self):
        hdrs = {'Strict-Transport-Security': 'max-age=86400'}  # 1 day
        r = analyze_headers(hdrs, url='https://example.com')
        assert headers_status(r, 'Strict-Transport-Security') == REVIEW

    def test_hsts_default_assumes_https(self):
        """If no URL provided, assume HTTPS context."""
        r = analyze_headers({})
        assert headers_status(r, 'Strict-Transport-Security') == WARNING


# ── X-Content-Type-Options ───────────────────────────────────────────────────

class TestXCTO:
    def test_missing_xcto_is_warning(self):
        r = analyze_headers({})
        assert headers_status(r, 'X-Content-Type-Options') == WARNING

    def test_nosniff_passes(self):
        r = analyze_headers({'X-Content-Type-Options': 'nosniff'})
        assert headers_status(r, 'X-Content-Type-Options') == PASS

    def test_nosniff_case_insensitive(self):
        r = analyze_headers({'X-Content-Type-Options': 'NOSNIFF'})
        assert headers_status(r, 'X-Content-Type-Options') == PASS

    def test_wrong_value_triggers_review(self):
        r = analyze_headers({'X-Content-Type-Options': 'sniff'})
        assert headers_status(r, 'X-Content-Type-Options') == REVIEW


# ── X-Frame-Options ──────────────────────────────────────────────────────────

class TestXFO:
    def test_missing_xfo_without_csp_is_warning(self):
        r = analyze_headers({})
        assert headers_status(r, 'X-Frame-Options') == WARNING

    def test_deny_passes(self):
        r = analyze_headers({'X-Frame-Options': 'DENY'})
        assert headers_status(r, 'X-Frame-Options') == PASS

    def test_sameorigin_passes(self):
        r = analyze_headers({'X-Frame-Options': 'SAMEORIGIN'})
        assert headers_status(r, 'X-Frame-Options') == PASS

    def test_allow_from_triggers_review(self):
        r = analyze_headers({'X-Frame-Options': 'ALLOW-FROM https://trusted.example.com'})
        assert headers_status(r, 'X-Frame-Options') == REVIEW

    def test_csp_frame_ancestors_compensates(self):
        hdrs = {'Content-Security-Policy': "frame-ancestors 'self'"}
        r = analyze_headers(hdrs)
        assert headers_status(r, 'X-Frame-Options') == PASS

    def test_case_insensitive_deny(self):
        r = analyze_headers({'X-Frame-Options': 'deny'})
        assert headers_status(r, 'X-Frame-Options') == PASS


# ── Referrer-Policy ──────────────────────────────────────────────────────────

class TestReferrerPolicy:
    def test_missing_rp_is_review(self):
        r = analyze_headers({})
        assert headers_status(r, 'Referrer-Policy') == REVIEW

    def test_strict_origin_passes(self):
        r = analyze_headers({'Referrer-Policy': 'strict-origin-when-cross-origin'})
        assert headers_status(r, 'Referrer-Policy') == PASS

    def test_no_referrer_passes(self):
        r = analyze_headers({'Referrer-Policy': 'no-referrer'})
        assert headers_status(r, 'Referrer-Policy') == PASS

    def test_unsafe_url_is_warning(self):
        r = analyze_headers({'Referrer-Policy': 'unsafe-url'})
        assert headers_status(r, 'Referrer-Policy') == WARNING

    def test_empty_value_is_warning(self):
        r = analyze_headers({'Referrer-Policy': ''})
        assert headers_status(r, 'Referrer-Policy') == WARNING

    def test_unrecognised_value_is_review(self):
        r = analyze_headers({'Referrer-Policy': 'custom-unknown-policy'})
        assert headers_status(r, 'Referrer-Policy') == REVIEW


# ── General ──────────────────────────────────────────────────────────────────

class TestGeneralHeaderAnalysis:
    def test_returns_five_results(self):
        r = analyze_headers({})
        assert len(r) == 5

    def test_all_results_have_required_keys(self):
        required = {'name', 'present', 'value', 'status', 'purpose', 'implications', 'remediation'}
        for h in analyze_headers({}):
            assert required.issubset(h.keys()), f"Missing keys in {h['name']}"

    def test_case_insensitive_header_lookup(self):
        """Headers from real HTTP responses may have mixed case."""
        r = analyze_headers({'content-security-policy': "default-src 'self'"})
        assert headers_status(r, 'Content-Security-Policy') == PASS

    def test_full_pass_scenario(self):
        good_headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
        }
        r = analyze_headers(good_headers, url='https://example.com')
        for h in r:
            assert h['status'] in (PASS, NOT_APPLICABLE), \
                f"{h['name']} should PASS but got {h['status']}"
