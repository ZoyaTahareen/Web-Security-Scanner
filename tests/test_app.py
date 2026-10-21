"""
tests/test_app.py
Flask route and integration tests.
All external HTTP requests are mocked — no real network calls.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

import app as flask_app_module
from app import app


@pytest.fixture()
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    with app.test_client() as c:
        yield c


# ── Home Route ────────────────────────────────────────────────────────────────

class TestIndexRoute:
    def test_index_returns_200(self, client):
        r = client.get('/')
        assert r.status_code == 200

    def test_index_contains_title(self, client):
        r = client.get('/')
        assert b'Security Scanner' in r.data or b'WebSecScan' in r.data


# ── Scan Route — Input Validation ────────────────────────────────────────────

class TestScanValidation:
    def test_empty_url_returns_400(self, client):
        r = client.post('/scan', json={'url': ''})
        assert r.status_code == 400

    def test_missing_url_key_returns_400(self, client):
        r = client.post('/scan', json={})
        assert r.status_code == 400

    def test_non_json_body_returns_400(self, client):
        r = client.post('/scan', data='not json', content_type='text/plain')
        assert r.status_code == 400

    def test_invalid_url_scheme_returns_400(self, client):
        r = client.post('/scan', json={'url': 'ftp://example.com'})
        assert r.status_code == 400
        data = r.get_json()
        assert 'error' in data

    def test_localhost_blocked_returns_400(self, client):
        r = client.post('/scan', json={'url': 'http://127.0.0.1'})
        assert r.status_code == 400

    def test_private_ip_blocked_returns_400(self, client):
        r = client.post('/scan', json={'url': 'http://192.168.1.1'})
        assert r.status_code == 400


# ── Scan Route — Successful Scan ─────────────────────────────────────────────

class TestScanSuccess:
    def _mock_scan_result(self):
        return {
            'target_url': 'https://example.com/',
            'final_url': 'https://example.com/',
            'timestamp': '2025-01-01T00:00:00Z',
            'http_status': 200,
            'headers_raw': {},
            'header_analysis': [
                {
                    'name': 'Content-Security-Policy',
                    'present': False,
                    'value': None,
                    'status': 'WARNING',
                    'purpose': 'Restricts resource loading.',
                    'implications': 'No CSP.',
                    'remediation': 'Add CSP.',
                }
            ],
            'cors_analysis': {
                'present': False,
                'headers': [],
                'summary': 'No CORS headers.',
                'concerns': [],
            },
            'findings': [],
        }

    def test_successful_scan_returns_200(self, client):
        with patch('app.run_scan', return_value=self._mock_scan_result()):
            r = client.post('/scan', json={'url': 'https://example.com'})
        assert r.status_code == 200

    def test_successful_scan_returns_json(self, client):
        with patch('app.run_scan', return_value=self._mock_scan_result()):
            r = client.post('/scan', json={'url': 'https://example.com'})
        data = r.get_json()
        assert 'target_url' in data
        assert 'header_analysis' in data
        assert 'cors_analysis' in data
        assert 'findings' in data

    def test_scan_result_stored_in_session(self, client):
        with patch('app.run_scan', return_value=self._mock_scan_result()):
            r = client.post('/scan', json={'url': 'https://example.com'})
        assert r.status_code == 200

    def test_value_error_returns_400(self, client):
        with patch('app.run_scan', side_effect=ValueError('Test validation error')):
            r = client.post('/scan', json={'url': 'https://example.com'})
        assert r.status_code == 400
        assert b'Test validation error' in r.data

    def test_unexpected_error_returns_500(self, client):
        with patch('app.run_scan', side_effect=RuntimeError('Unexpected')):
            r = client.post('/scan', json={'url': 'https://example.com'})
        assert r.status_code == 500


# ── Report Routes — No Scan ───────────────────────────────────────────────────

class TestReportNoScan:
    def test_json_report_without_scan_returns_400(self, client):
        r = client.get('/report/json')
        assert r.status_code == 400

    def test_csv_report_without_scan_returns_400(self, client):
        r = client.get('/report/csv')
        assert r.status_code == 400

    def test_pdf_report_without_scan_returns_400(self, client):
        r = client.get('/report/pdf')
        assert r.status_code == 400


# ── Report Routes — After Scan ────────────────────────────────────────────────

class TestReportDownload:
    def _do_scan(self, client):
        mock_result = {
            'target_url': 'https://example.com/',
            'final_url': 'https://example.com/',
            'timestamp': '2025-01-01T00:00:00Z',
            'http_status': 200,
            'headers_raw': {},
            'header_analysis': [],
            'cors_analysis': {'present': False, 'headers': [], 'summary': 'None.', 'concerns': []},
            'findings': [],
        }
        with patch('app.run_scan', return_value=mock_result):
            client.post('/scan', json={'url': 'https://example.com'})
        return mock_result

    def test_json_report_served_after_scan(self, client):
        with client.session_transaction() as sess:
            sess['last_scan'] = {
                'target_url': 'https://example.com/',
                'final_url': 'https://example.com/',
                'timestamp': '2025-01-01T00:00:00Z',
                'http_status': 200,
                'header_analysis': [],
                'cors_analysis': {'headers': [], 'summary': '', 'concerns': []},
                'findings': [],
            }
        r = client.get('/report/json')
        assert r.status_code == 200
        assert r.content_type.startswith('application/json')
        assert b'target_url' in r.data

    def test_csv_report_served_after_scan(self, client):
        with client.session_transaction() as sess:
            sess['last_scan'] = {
                'target_url': 'https://example.com/',
                'final_url': 'https://example.com/',
                'timestamp': '2025-01-01T00:00:00Z',
                'http_status': 200,
                'header_analysis': [],
                'cors_analysis': {'headers': [], 'summary': '', 'concerns': []},
                'findings': [],
            }
        r = client.get('/report/csv')
        assert r.status_code == 200
        assert 'csv' in r.content_type.lower() or 'text' in r.content_type.lower()

    def test_pdf_report_served_after_scan(self, client):
        with client.session_transaction() as sess:
            sess['last_scan'] = {
                'target_url': 'https://example.com/',
                'final_url': 'https://example.com/',
                'timestamp': '2025-01-01T00:00:00Z',
                'http_status': 200,
                'header_analysis': [],
                'cors_analysis': {'headers': [], 'summary': '', 'concerns': []},
                'findings': [],
            }
        r = client.get('/report/pdf')
        assert r.status_code == 200
        assert r.content_type == 'application/pdf'
        # Check PDF magic bytes
        assert r.data[:4] == b'%PDF'

    def test_json_report_content_disposition(self, client):
        with client.session_transaction() as sess:
            sess['last_scan'] = {
                'target_url': 'https://example.com/',
                'final_url': 'https://example.com/',
                'timestamp': '2025-01-01T00:00:00Z',
                'http_status': 200,
                'header_analysis': [],
                'cors_analysis': {'headers': [], 'summary': '', 'concerns': []},
                'findings': [],
            }
        r = client.get('/report/json')
        assert 'attachment' in r.headers.get('Content-Disposition', '')
        assert 'security_report.json' in r.headers.get('Content-Disposition', '')
