"""
Tests for fastrecon.validation — SSRF prevention and domain safety checks.

Verifies that the is_safe_target() function correctly allows legitimate
public domains while blocking internal hostnames, private IPs, and
cloud metadata endpoints.
"""

import pytest
from unittest.mock import patch

from fastrecon.validation import is_safe_target


class TestDomainFormat:
    """Test domain format validation (regex-level checks)."""

    def test_valid_domain(self):
        assert is_safe_target("example.com") is True

    def test_valid_subdomain(self):
        assert is_safe_target("sub.example.com") is True

    def test_valid_deep_subdomain(self):
        assert is_safe_target("a.b.c.example.com") is True

    def test_valid_domain_with_hyphens(self):
        assert is_safe_target("my-site.example.com") is True

    def test_empty_string_rejected(self):
        assert is_safe_target("") is False

    def test_none_rejected(self):
        assert is_safe_target(None) is False

    def test_protocol_prefix_rejected(self):
        assert is_safe_target("http://example.com") is False

    def test_https_prefix_rejected(self):
        assert is_safe_target("https://example.com") is False

    def test_bare_ip_rejected(self):
        """IP addresses don't match the domain regex."""
        assert is_safe_target("192.168.1.1") is False

    def test_single_label_rejected(self):
        """Single-label names (no TLD) are not valid domains."""
        assert is_safe_target("localhost") is False

    def test_path_in_target_rejected(self):
        assert is_safe_target("example.com/path") is False

    def test_port_in_target_rejected(self):
        assert is_safe_target("example.com:8080") is False

    def test_whitespace_only_rejected(self):
        assert is_safe_target("   ") is False


class TestInternalHostBlocking:
    """Test that internal/private hostnames are blocked."""

    def test_localhost_rejected(self):
        assert is_safe_target("localhost") is False

    def test_dotlocal_rejected(self):
        assert is_safe_target("myhost.local") is False

    def test_internal_tld_rejected(self):
        assert is_safe_target("service.internal") is False

    def test_corp_tld_rejected(self):
        assert is_safe_target("app.corp") is False

    def test_home_tld_rejected(self):
        assert is_safe_target("router.home") is False

    def test_lan_tld_rejected(self):
        assert is_safe_target("printer.lan") is False


class TestPrivateIPBlocking:
    """Test that domains resolving to private/reserved IPs are blocked."""

    @patch("fastrecon.validation.socket.gethostbyname")
    def test_private_ip_blocked(self, mock_dns):
        mock_dns.return_value = "192.168.1.1"
        assert is_safe_target("evil.example.com") is False

    @patch("fastrecon.validation.socket.gethostbyname")
    def test_loopback_blocked(self, mock_dns):
        mock_dns.return_value = "127.0.0.1"
        assert is_safe_target("evil.example.com") is False

    @patch("fastrecon.validation.socket.gethostbyname")
    def test_link_local_blocked(self, mock_dns):
        """Block AWS metadata endpoint (169.254.169.254)."""
        mock_dns.return_value = "169.254.169.254"
        assert is_safe_target("evil.example.com") is False

    @patch("fastrecon.validation.socket.gethostbyname")
    def test_ten_network_blocked(self, mock_dns):
        mock_dns.return_value = "10.0.0.1"
        assert is_safe_target("evil.example.com") is False

    @patch("fastrecon.validation.socket.gethostbyname")
    def test_public_ip_allowed(self, mock_dns):
        mock_dns.return_value = "93.184.216.34"  # example.com's real IP
        assert is_safe_target("example.com") is True

    @patch("fastrecon.validation.socket.gethostbyname")
    def test_unresolvable_domain_allowed(self, mock_dns):
        """Domains that don't resolve are allowed — they'll fail naturally."""
        import socket
        mock_dns.side_effect = socket.gaierror("DNS lookup failed")
        assert is_safe_target("nonexistent.example.com") is True
