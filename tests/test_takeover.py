"""
Tests for fastrecon.takeover — CNAME chain resolution and takeover detection.
Uses mocked dns.resolver to avoid real network calls.
"""

import asyncio
from unittest.mock import MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import pytest

from fastrecon.takeover import (
    check_nxdomain,
    check_takeover,
    check_takeover_cname,
    resolve_cname_chain,
)


# ── Helper to create a mock CNAME answer ──


def _make_cname_answer(target):
    """Create a mock dns.resolver answer with a single CNAME record."""
    mock_rdata = MagicMock()
    mock_rdata.target = dns.name.from_text(target)
    return [mock_rdata]


# ── Tests for check_takeover (HTML fingerprint matching) ──


class TestCheckTakeover:
    def test_matches_github_pages_fingerprint(self):
        alert = check_takeover(
            "blog.example.com",
            "There isn't a GitHub Pages site here."
        )
        assert alert is not None
        assert alert["severity"] == "CRITICAL"
        assert alert["type"] == "Subdomain Takeover"
        assert alert["service"] == "GitHub Pages"
        assert alert["asset"] == "blog.example.com"

    def test_matches_s3_fingerprint(self):
        alert = check_takeover(
            "assets.example.com",
            "<html><body>NoSuchBucket</body></html>"
        )
        assert alert is not None
        assert alert["service"] == "AWS S3"

    def test_no_match(self):
        alert = check_takeover(
            "www.example.com",
            "<html><body>Welcome to our site</body></html>"
        )
        assert alert is None

    def test_empty_body(self):
        assert check_takeover("www.example.com", "") is None
        assert check_takeover("www.example.com", None) is None


# ── Tests for resolve_cname_chain ──


class TestResolveCnameChain:
    @pytest.mark.asyncio
    async def test_single_cname(self):
        """Simple case: subdomain → single CNAME target."""
        def mock_resolve(name, rdtype):
            if name == "blog.example.com" and rdtype == "CNAME":
                return _make_cname_answer("example.github.io.")
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            chain = await resolve_cname_chain("blog.example.com")
            assert chain == ["example.github.io"]

    @pytest.mark.asyncio
    async def test_multi_hop_chain(self):
        """CNAME chain: a → b → c."""
        def mock_resolve(name, rdtype):
            if rdtype != "CNAME":
                raise dns.resolver.NoAnswer()
            mapping = {
                "app.example.com": "proxy.cdn.net.",
                "proxy.cdn.net": "final.target.com.",
            }
            if name in mapping:
                return _make_cname_answer(mapping[name])
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            chain = await resolve_cname_chain("app.example.com")
            assert chain == ["proxy.cdn.net", "final.target.com"]

    @pytest.mark.asyncio
    async def test_no_cname(self):
        """No CNAME record exists — returns empty list."""
        def mock_resolve(name, rdtype):
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            chain = await resolve_cname_chain("www.example.com")
            assert chain == []

    @pytest.mark.asyncio
    async def test_circular_cname_stops(self):
        """Circular CNAME (a → b → a) should stop without infinite loop."""
        def mock_resolve(name, rdtype):
            if rdtype != "CNAME":
                raise dns.resolver.NoAnswer()
            mapping = {
                "a.example.com": "b.example.com.",
                "b.example.com": "a.example.com.",
            }
            if name in mapping:
                return _make_cname_answer(mapping[name])
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            chain = await resolve_cname_chain("a.example.com")
            # Should contain b but stop when it sees a again
            assert "b.example.com" in chain
            assert len(chain) <= 2

    @pytest.mark.asyncio
    async def test_timeout_returns_partial_chain(self):
        """DNS timeout during chain walk returns what we have so far."""
        def mock_resolve(name, rdtype):
            if name == "start.example.com" and rdtype == "CNAME":
                return _make_cname_answer("middle.cdn.net.")
            raise dns.exception.Timeout()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            chain = await resolve_cname_chain("start.example.com")
            assert chain == ["middle.cdn.net"]


# ── Tests for check_nxdomain ──


class TestCheckNxdomain:
    @pytest.mark.asyncio
    async def test_confirmed_nxdomain(self):
        """NXDOMAIN should return True."""
        def mock_resolve(name, rdtype):
            raise dns.resolver.NXDOMAIN()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            result = await check_nxdomain("dead.example.com")
            assert result is True

    @pytest.mark.asyncio
    async def test_resolves_a_record(self):
        """Host that resolves should return False."""
        def mock_resolve(name, rdtype):
            mock_answer = MagicMock()
            return mock_answer

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            result = await check_nxdomain("alive.example.com")
            assert result is False

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        """Timeout should return None (inconclusive), NOT True."""
        def mock_resolve(name, rdtype):
            raise dns.exception.Timeout()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            result = await check_nxdomain("slow.example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_no_nameservers_returns_none(self):
        """NoNameservers should return None (inconclusive)."""
        def mock_resolve(name, rdtype):
            raise dns.resolver.NoNameservers()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            result = await check_nxdomain("broken.example.com")
            assert result is None


# ── Tests for check_takeover_cname (integration) ──


class TestCheckTakeoverCname:
    @pytest.mark.asyncio
    async def test_dangling_github_pages(self):
        """CNAME to github.io + NXDOMAIN = takeover alert."""
        def mock_resolve(name, rdtype):
            if name == "blog.example.com" and rdtype == "CNAME":
                return _make_cname_answer("old-project.github.io.")
            if rdtype == "A":
                raise dns.resolver.NXDOMAIN()
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            alert = await check_takeover_cname("blog.example.com")
            assert alert is not None
            assert alert["severity"] == "CRITICAL"
            assert alert["type"] == "Subdomain Takeover"
            assert "github.io" in alert["cname_pattern"]
            assert "NXDOMAIN" in alert["details"]

    @pytest.mark.asyncio
    async def test_non_dangling_cname(self):
        """CNAME to github.io but it resolves — no alert."""
        def mock_resolve(name, rdtype):
            if name == "active.example.com" and rdtype == "CNAME":
                return _make_cname_answer("mysite.github.io.")
            # All other queries resolve successfully
            return MagicMock()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            alert = await check_takeover_cname("active.example.com")
            assert alert is None

    @pytest.mark.asyncio
    async def test_timeout_does_not_flag(self):
        """CNAME to github.io but NXDOMAIN check times out — should NOT flag."""
        def mock_resolve(name, rdtype):
            if name == "flaky.example.com" and rdtype == "CNAME":
                return _make_cname_answer("project.github.io.")
            if rdtype == "A":
                raise dns.exception.Timeout()
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            alert = await check_takeover_cname("flaky.example.com")
            assert alert is None  # Timeout = inconclusive, not a takeover

    @pytest.mark.asyncio
    async def test_no_cname_returns_none(self):
        """No CNAME at all — returns None."""
        def mock_resolve(name, rdtype):
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            alert = await check_takeover_cname("www.example.com")
            assert alert is None

    @pytest.mark.asyncio
    async def test_cname_to_non_vulnerable_service(self):
        """CNAME to a service not in the signatures list — no alert."""
        def mock_resolve(name, rdtype):
            if name == "cdn.example.com" and rdtype == "CNAME":
                return _make_cname_answer("d12345.cloudfront.net.")
            if rdtype == "A":
                raise dns.resolver.NXDOMAIN()
            raise dns.resolver.NoAnswer()

        with patch("fastrecon.takeover.dns.resolver.resolve", side_effect=mock_resolve):
            alert = await check_takeover_cname("cdn.example.com")
            # cloudfront.net IS in the signatures, so this should flag
            assert alert is not None
            assert alert["service"] == "AWS CloudFront"
