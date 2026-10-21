"""
tests/test_cors.py
Tests for the CORS analysis module.
Uses plain header dicts — no real HTTP requests.
"""

import pytest
from scanner.cors import analyze_cors


def get_header(cors_result, name):
    for h in cors_result['headers']:
        if h['name'] == name:
            return h
    raise KeyError(f"{name} not found in CORS results")


# ── No CORS Headers ───────────────────────────────────────────────────────────

class TestNoCorsHeaders:
    def test_no_headers_present_is_false(self):
        r = analyze_cors({})
        assert r['present'] is False

    def test_no_headers_no_concerns(self):
        r = analyze_cors({})
        assert r['concerns'] == []

    def test_no_headers_summary_mentions_not_detected(self):
        r = analyze_cors({})
        assert 'not detected' in r['summary'].lower() or 'No CORS' in r['summary']


# ── Access-Control-Allow-Origin ───────────────────────────────────────────────

class TestACAlloowOrigin:
    def test_wildcard_origin_is_review(self):
        r = analyze_cors({'Access-Control-Allow-Origin': '*'})
        h = get_header(r, 'Access-Control-Allow-Origin')
        assert h['status'] == 'REVIEW'

    def test_wildcard_generates_concern(self):
        r = analyze_cors({'Access-Control-Allow-Origin': '*'})
        h = get_header(r, 'Access-Control-Allow-Origin')
        assert h['concern']  # non-empty

    def test_null_origin_is_warning(self):
        r = analyze_cors({'Access-Control-Allow-Origin': 'null'})
        h = get_header(r, 'Access-Control-Allow-Origin')
        assert h['status'] == 'WARNING'

    def test_specific_origin_is_info(self):
        r = analyze_cors({'Access-Control-Allow-Origin': 'https://trusted.example.com'})
        h = get_header(r, 'Access-Control-Allow-Origin')
        assert h['status'] == 'INFO'

    def test_specific_origin_no_concern(self):
        r = analyze_cors({'Access-Control-Allow-Origin': 'https://trusted.example.com'})
        h = get_header(r, 'Access-Control-Allow-Origin')
        assert not h['concern']

    def test_absent_origin_is_not_set(self):
        r = analyze_cors({})
        h = get_header(r, 'Access-Control-Allow-Origin')
        assert h['status'] == 'NOT SET'
        assert h['value'] is None


# ── Access-Control-Allow-Credentials ─────────────────────────────────────────

class TestACAllowCredentials:
    def test_credentials_true_with_specific_origin_is_review(self):
        r = analyze_cors({
            'Access-Control-Allow-Origin': 'https://app.example.com',
            'Access-Control-Allow-Credentials': 'true',
        })
        h = get_header(r, 'Access-Control-Allow-Credentials')
        assert h['status'] == 'REVIEW'

    def test_credentials_true_with_wildcard_is_info(self):
        """Browsers block this combination; warn but don't panic."""
        r = analyze_cors({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
        })
        h = get_header(r, 'Access-Control-Allow-Credentials')
        assert h['status'] == 'INFO'

    def test_credentials_false_is_info(self):
        r = analyze_cors({'Access-Control-Allow-Credentials': 'false'})
        h = get_header(r, 'Access-Control-Allow-Credentials')
        assert h['status'] == 'INFO'
        assert not h['concern']

    def test_absent_credentials_no_concern(self):
        r = analyze_cors({})
        h = get_header(r, 'Access-Control-Allow-Credentials')
        assert h['status'] == 'NOT SET'
        assert not h['concern']


# ── Access-Control-Allow-Methods ─────────────────────────────────────────────

class TestACAllowMethods:
    def test_broad_methods_trigger_review(self):
        r = analyze_cors({'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT'})
        h = get_header(r, 'Access-Control-Allow-Methods')
        assert h['status'] == 'REVIEW'

    def test_safe_methods_are_info(self):
        r = analyze_cors({'Access-Control-Allow-Methods': 'GET, POST'})
        h = get_header(r, 'Access-Control-Allow-Methods')
        assert h['status'] == 'INFO'

    def test_absent_methods_are_not_set(self):
        r = analyze_cors({})
        h = get_header(r, 'Access-Control-Allow-Methods')
        assert h['status'] == 'NOT SET'


# ── Access-Control-Allow-Headers ─────────────────────────────────────────────

class TestACAllowHeaders:
    def test_wildcard_headers_trigger_review(self):
        r = analyze_cors({'Access-Control-Allow-Headers': '*'})
        h = get_header(r, 'Access-Control-Allow-Headers')
        assert h['status'] == 'REVIEW'

    def test_authorization_header_triggers_review(self):
        r = analyze_cors({'Access-Control-Allow-Headers': 'Authorization, Content-Type'})
        h = get_header(r, 'Access-Control-Allow-Headers')
        assert h['status'] == 'REVIEW'

    def test_safe_headers_are_info(self):
        r = analyze_cors({'Access-Control-Allow-Headers': 'Content-Type'})
        h = get_header(r, 'Access-Control-Allow-Headers')
        assert h['status'] == 'INFO'

    def test_absent_allow_headers_is_not_set(self):
        r = analyze_cors({})
        h = get_header(r, 'Access-Control-Allow-Headers')
        assert h['status'] == 'NOT SET'


# ── Result Structure ──────────────────────────────────────────────────────────

class TestCorsResultStructure:
    def test_always_returns_four_header_entries(self):
        assert len(analyze_cors({})['headers']) == 4

    def test_required_keys_present(self):
        required = {'name', 'value', 'status', 'purpose', 'observation', 'concern', 'recommendation'}
        for h in analyze_cors({})['headers']:
            assert required.issubset(h.keys()), f"Missing keys in {h['name']}"

    def test_concerns_list_contains_only_non_empty_strings(self):
        r = analyze_cors({'Access-Control-Allow-Origin': '*'})
        for c in r['concerns']:
            assert isinstance(c, str) and c.strip()

    def test_present_flag_true_when_any_cors_header_exists(self):
        r = analyze_cors({'Access-Control-Allow-Origin': 'https://example.com'})
        assert r['present'] is True
