"""
Tests for fastrecon.vuln_scanner — XSS, SQLi, Host Header Injection, Info Disclosure.
Uses aioresponses to mock HTTP responses without real network calls.
"""

import asyncio
import json

import aiohttp
import pytest
from aioresponses import aioresponses

from fastrecon.vuln_scanner import (
    _is_payload_in_executable_context,
    check_host_header_injection,
    check_info_disclosure,
    check_reflected_xss,
    check_sqli,
)


# ── Tests for _is_payload_in_executable_context ──


class TestIsPayloadInExecutableContext:
    def test_payload_in_raw_html(self):
        """Payload directly in HTML body — executable."""
        body = '<html><body><div>"><script>alert(1)</script></div></body></html>'
        assert _is_payload_in_executable_context('"><script>alert(1)</script>', body) is True

    def test_payload_in_json_blob(self):
        """Payload inside a JSON response — NOT executable."""
        payload = '"><script>alert(1)</script>'
        body = json.dumps({"input": payload, "status": "ok"})
        # JSON wraps it in quotes with escaping — should be safe
        assert _is_payload_in_executable_context(payload, body) is False

    def test_payload_in_textarea(self):
        """Payload inside <textarea> — NOT executable."""
        payload = "<img src=x onerror=alert(1)>"
        body = f'<html><body><textarea>{payload}</textarea></body></html>'
        assert _is_payload_in_executable_context(payload, body) is False

    def test_payload_in_html_comment(self):
        """Payload inside HTML comment — NOT executable."""
        payload = "<script>alert(1)</script>"
        body = f"<html><!-- debug: {payload} --><body>hello</body></html>"
        assert _is_payload_in_executable_context(payload, body) is False

    def test_empty_body(self):
        assert _is_payload_in_executable_context("test", "") is False
        assert _is_payload_in_executable_context("test", None) is False

    def test_payload_not_present(self):
        body = "<html><body>No payload here</body></html>"
        assert _is_payload_in_executable_context("<script>alert(1)</script>", body) is False


# ── Tests for check_reflected_xss ──


class TestCheckReflectedXss:
    @pytest.mark.asyncio
    async def test_xss_in_executable_context(self):
        """Payload reflected in raw HTML (not in baseline) = flagged."""
        base_url = "http://test.example.com"
        payload = '"><script>alert(1)</script>'

        with aioresponses() as mocked:
            # Baseline request — clean response (no payload in it)
            mocked.get(
                f"{base_url}?q=fastrecon_baseline_test",
                status=200, body="<html><body>Search results</body></html>",
                repeat=True,
            )
            # Injected request — payload reflected in executable context
            mocked.get(
                f"{base_url}?q={payload}",
                status=200,
                body=f'<html><body><div>{payload}</div></body></html>',
            )

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_reflected_xss(session, base_url, sem)
                assert len(findings) >= 1
                assert findings[0]["severity"] == "MEDIUM"
                assert findings[0]["type"] == "Reflected XSS"

    @pytest.mark.asyncio
    async def test_xss_payload_in_baseline_not_flagged(self):
        """Payload appears in both baseline and injected response — generic echo, skip."""
        base_url = "http://echo.example.com"
        payload = '"><script>alert(1)</script>'

        with aioresponses() as mocked:
            # Both baseline and injected return the payload (echo page)
            for param in ["q", "s", "search", "query", "keyword", "id", "page", "url"]:
                mocked.get(
                    f"{base_url}?{param}=fastrecon_baseline_test",
                    status=200,
                    body=f"<html>{payload}</html>",
                    repeat=True,
                )
                for p in ['"><script>alert(1)</script>', "'-alert(1)-'", "<img src=x onerror=alert(1)>"]:
                    mocked.get(
                        f"{base_url}?{param}={p}",
                        status=200,
                        body=f"<html>{payload}</html>",
                        repeat=True,
                    )

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_reflected_xss(session, base_url, sem)
                assert len(findings) == 0  # Should not flag echo pages


# ── Tests for check_sqli ──


class TestCheckSqli:
    @pytest.mark.asyncio
    async def test_sqli_error_only_with_injection(self):
        """SQL error appears only with injection payload — flagged."""
        base_url = "http://vuln.example.com"

        with aioresponses() as mocked:
            # Baseline — no SQL error
            for param in ["q", "s", "search", "query", "keyword"]:
                mocked.get(
                    f"{base_url}?{param}=fastrecon_baseline_1",
                    status=200, body="<html>Normal page</html>",
                    repeat=True,
                )
            # Injection — SQL error triggered
            mocked.get(
                f"{base_url}?q=' OR '1'='1",
                status=200,
                body="<html>you have an error in your sql syntax near</html>",
            )

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_sqli(session, base_url, sem)
                assert len(findings) >= 1
                assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_sqli_error_in_baseline_not_flagged(self):
        """SQL error pattern present in baseline too — skip (generic error page)."""
        base_url = "http://noisy.example.com"

        with aioresponses() as mocked:
            # Both baseline and injection have the SQL error
            for param in ["q", "s", "search", "query", "keyword"]:
                mocked.get(
                    f"{base_url}?{param}=fastrecon_baseline_1",
                    status=200,
                    body="<html>you have an error in your sql syntax</html>",
                    repeat=True,
                )
                for p in ["' OR '1'='1", "' OR 1=1--", "' OR 1=1#"]:
                    mocked.get(
                        f"{base_url}?{param}={p}",
                        status=200,
                        body="<html>you have an error in your sql syntax</html>",
                        repeat=True,
                    )

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_sqli(session, base_url, sem)
                assert len(findings) == 0


# ── Tests for check_host_header_injection ──


class TestCheckHostHeaderInjection:
    @pytest.mark.asyncio
    async def test_canary_in_href_flagged_high(self):
        """Host header canary reflected in <a href=> — HIGH severity."""
        base_url = "http://vuln.example.com"

        # Mock _fetch to simulate Host header reflection in href context
        from unittest.mock import AsyncMock, patch

        original_fetch = None

        async def mock_fetch(session, url, method="GET", headers=None, timeout=None):
            if headers and "Host" in headers:
                canary = headers["Host"]
                body = f'<html><body><a href="http://{canary}/reset">Reset Password</a></body></html>'
                return 200, {"Content-Type": "text/html"}, body, True
            return 200, {"Content-Type": "text/html"}, "<html>Normal</html>", True

        with patch("fastrecon.vuln_scanner._fetch", side_effect=mock_fetch):
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_host_header_injection(session, base_url, sem)
                assert len(findings) >= 1
                assert findings[0]["severity"] == "HIGH"
                assert findings[0]["type"] == "Host Header Injection"

    @pytest.mark.asyncio
    async def test_canary_not_reflected(self):
        """Host header canary NOT reflected — no finding."""
        base_url = "http://safe.example.com"

        from unittest.mock import patch

        async def mock_fetch(session, url, method="GET", headers=None, timeout=None):
            return 200, {"Content-Type": "text/html"}, "<html><body>Normal page</body></html>", True

        with patch("fastrecon.vuln_scanner._fetch", side_effect=mock_fetch):
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_host_header_injection(session, base_url, sem)
                assert len(findings) == 0


# ── Tests for check_info_disclosure ──


class TestCheckInfoDisclosure:
    @pytest.mark.asyncio
    async def test_single_broad_pattern_is_low(self):
        """Only the generic 'Error - Application' title — LOW severity."""
        base_url = "http://app.example.com"

        with aioresponses() as mocked:
            body = "<html><title>Error - Application</title><body>Something went wrong</body></html>"
            mocked.get(base_url, status=200, body=body, headers={"Server": "nginx"})

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_info_disclosure(session, base_url, sem)
                debug_findings = [f for f in findings if f["type"] == "Information Disclosure"]
                if debug_findings:
                    assert debug_findings[0]["severity"] == "LOW"

    @pytest.mark.asyncio
    async def test_strong_pattern_is_medium(self):
        """Python stack trace (strong pattern) — MEDIUM severity."""
        base_url = "http://debug.example.com"

        with aioresponses() as mocked:
            body = "<html><body>Traceback (most recent call last)\nFile 'app.py'</body></html>"
            mocked.get(base_url, status=200, body=body, headers={"Server": "nginx"})

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_info_disclosure(session, base_url, sem)
                debug_findings = [f for f in findings if f["type"] == "Information Disclosure"]
                assert len(debug_findings) >= 1
                assert debug_findings[0]["severity"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_two_patterns_is_medium(self):
        """Two corroborating patterns — MEDIUM severity."""
        base_url = "http://debug2.example.com"

        with aioresponses() as mocked:
            body = (
                "<html><title>Error - Application</title>"
                "<body>SQLSTATE[42S02]: Base table not found</body></html>"
            )
            mocked.get(base_url, status=200, body=body, headers={"Server": "nginx"})

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_info_disclosure(session, base_url, sem)
                debug_findings = [f for f in findings if f["type"] == "Information Disclosure"]
                assert len(debug_findings) >= 1
                assert debug_findings[0]["severity"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_server_version_disclosure(self):
        """Server header with version number — LOW severity."""
        base_url = "http://version.example.com"

        with aioresponses() as mocked:
            mocked.get(base_url, status=200, body="<html></html>",
                       headers={"Server": "Apache/2.4.51"})

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_info_disclosure(session, base_url, sem)
                version_findings = [f for f in findings if f["type"] == "Server Version Disclosure"]
                assert len(version_findings) == 1
                assert version_findings[0]["severity"] == "LOW"
