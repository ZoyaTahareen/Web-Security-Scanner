"""
scanner/validator.py
URL validation and SSRF-prevention logic.

Blocks:
  - Non-HTTP/HTTPS schemes
  - Localhost and loopback (127.x, ::1)
  - RFC-1918 private ranges (10.x, 172.16-31.x, 192.168.x)
  - Link-local (169.254.x, fe80::/10)
  - Cloud metadata services (169.254.169.254, metadata.google.internal, etc.)
  - Resolved IP addresses that fall into blocked ranges
"""

import ipaddress
import re
import socket
import urllib.parse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = {"http", "https"}

# Metadata / cloud services that must never be reached
_BLOCKED_HOSTNAMES: set[str] = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",         # AWS/GCP/Azure IMDS
    "fd00:ec2::254",           # AWS IPv6 IMDS
}

_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Private (RFC-1918)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Unique-local (IPv6)
    ipaddress.ip_network("fc00::/7"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # Unspecified
    ipaddress.ip_network("0.0.0.0/8"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if *ip_str* falls in any blocked network or is a blocked host."""
    if ip_str in _BLOCKED_HOSTNAMES:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _resolve_and_check(hostname: str) -> None:
    """
    Resolve *hostname* to IP addresses and raise ValueError if any of them
    fall in a blocked range.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    for _family, _type, _proto, _canonname, sockaddr in results:
        ip = sockaddr[0]
        if _is_blocked_ip(ip):
            raise ValueError(
                f"Target resolves to a restricted IP address ({ip}). "
                "Scanning private, loopback, or cloud metadata destinations is not permitted."
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_url(url: str) -> str:
    """
    Validate *url* and return the normalised form.

    Raises ValueError with a human-readable message on any violation.
    """
    url = url.strip()

    if not url:
        raise ValueError("URL must not be empty.")

    if len(url) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")

    # Parse
    parsed = urllib.parse.urlparse(url)

    # Scheme
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"Unsupported URL scheme '{scheme}'. Only 'http' and 'https' are accepted."
        )

    # Hostname presence
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must include a valid hostname.")

    if len(hostname) > 253:
        raise ValueError("Hostname is too long.")

    # Reject blocked hostnames directly
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(
            f"Scanning '{hostname}' is not permitted (blocked destination)."
        )

    # Reject numeric IPs in blocked ranges before DNS
    try:
        if _is_blocked_ip(hostname):
            raise ValueError(
                f"Scanning IP address '{hostname}' is not permitted. "
                "Private, loopback, and cloud-metadata destinations are blocked."
            )
    except ValueError:
        raise
    except Exception:
        pass  # Not a raw IP — proceed to DNS check

    # DNS resolution + blocked-IP check
    _resolve_and_check(hostname)

    # Reconstruct a clean URL (strip fragments which are client-only)
    clean = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, "")
    )
    return clean
