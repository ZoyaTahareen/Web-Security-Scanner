"""
tests/test_validator.py
Tests for the URL validator including SSRF protections.
All tests are self-contained and do not make real HTTP requests.
"""

import pytest
from unittest.mock import patch

from scanner.validator import validate_url


# ── Valid URLs ──────────────────────────────────────────────────────────────

class TestValidUrls:
    def _mock_resolve(self, hostname):
        """Patch DNS so all resolves return a safe public IP."""
        return patch(
            'scanner.validator._resolve_and_check',
            return_value=None
        )

    def test_https_url_accepted(self):
        with self._mock_resolve('example.com'):
            result = validate_url('https://example.com')
        assert result.startswith('https://')

    def test_http_url_accepted(self):
        with self._mock_resolve('example.com'):
            result = validate_url('http://example.com')
        assert result.startswith('http://')

    def test_url_with_path(self):
        with self._mock_resolve('example.com'):
            result = validate_url('https://example.com/path/to/page')
        assert '/path/to/page' in result

    def test_url_with_query(self):
        with self._mock_resolve('example.com'):
            result = validate_url('https://example.com/search?q=test')
        assert 'q=test' in result

    def test_url_fragment_stripped(self):
        with self._mock_resolve('example.com'):
            result = validate_url('https://example.com/page#section')
        assert '#' not in result

    def test_url_trailing_whitespace_stripped(self):
        with self._mock_resolve('example.com'):
            result = validate_url('  https://example.com  ')
        assert result.startswith('https://')

    def test_url_missing_path_gets_slash(self):
        with self._mock_resolve('example.com'):
            result = validate_url('https://example.com')
        assert result.endswith('/')


# ── Invalid / Empty URLs ─────────────────────────────────────────────────────

class TestInvalidUrls:
    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_url('')

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_url('   ')

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="too long"):
            validate_url('https://example.com/' + 'a' * 2048)

    def test_no_hostname_raises(self):
        with pytest.raises(ValueError):
            validate_url('https://')


# ── Unsupported Schemes ──────────────────────────────────────────────────────

class TestUnsupportedSchemes:
    def test_ftp_rejected(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_url('ftp://example.com')

    def test_file_rejected(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_url('file:///etc/passwd')

    def test_javascript_rejected(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_url('javascript:alert(1)')

    def test_data_uri_rejected(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_url('data:text/html,<h1>test</h1>')


# ── SSRF — Private / Loopback IPs ───────────────────────────────────────────

class TestSSRFProtection:
    def test_localhost_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://127.0.0.1:5000')

    def test_loopback_alias_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://127.0.0.254')

    def test_private_10_range_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://10.0.0.1')

    def test_private_192_168_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://192.168.1.100')

    def test_private_172_16_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://172.16.0.1')

    def test_link_local_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://169.254.1.1')

    def test_cloud_metadata_ip_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://169.254.169.254')

    def test_cloud_metadata_hostname_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://metadata.google.internal')

    def test_ipv6_loopback_rejected(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_url('http://[::1]/')


# ── DNS Resolution ───────────────────────────────────────────────────────────

class TestDnsResolution:
    def test_dns_failure_raises_valueerror(self):
        import socket
        with patch('scanner.validator.socket.getaddrinfo', side_effect=socket.gaierror("no such host")):
            with pytest.raises(ValueError, match="DNS resolution failed"):
                validate_url('https://this-domain-does-not-exist.invalid')

    def test_resolved_private_ip_blocked(self):
        """Even if hostname looks public, block if it resolves to a private IP."""
        import socket
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.0.1', 0))]
        with patch('scanner.validator.socket.getaddrinfo', return_value=fake_result):
            with pytest.raises(ValueError, match="restricted"):
                validate_url('https://sneaky-domain.com')
