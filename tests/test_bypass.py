"""
Tests for fastrecon.bypass — 401/403 access-control bypass probing.
"""

import asyncio

import aiohttp
import pytest
from aioresponses import aioresponses

from fastrecon.bypass import check_access_bypass, run_bypass_scan


class TestCheckAccessBypass:
    @pytest.mark.asyncio
    async def test_path_variant_bypass_flagged(self):
        url = "https://x.com/admin"
        with aioresponses() as mocked:
            mocked.get(url, status=403, body="Forbidden", repeat=True)
            # First path variant /admin/ opens with a materially larger body.
            mocked.get("https://x.com/admin/", status=200, body="A" * 300, repeat=True)

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_access_bypass(session, url, sem)
                assert len(findings) == 1
                assert findings[0]["type"] == "Access Control Bypass"
                assert findings[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_no_bypass_when_all_blocked(self):
        url = "https://x.com/admin"
        with aioresponses() as mocked:
            mocked.get(url, status=403, body="Forbidden", repeat=True)
            # No candidate is mocked → every bypass attempt fails.
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_access_bypass(session, url, sem)
                assert findings == []

    @pytest.mark.asyncio
    async def test_not_blocked_is_skipped(self):
        url = "https://x.com/ok"
        with aioresponses() as mocked:
            mocked.get(url, status=200, body="hi", repeat=True)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_access_bypass(session, url, sem)
                assert findings == []

    @pytest.mark.asyncio
    async def test_soft_200_within_delta_not_flagged(self):
        url = "https://x.com/admin"
        with aioresponses() as mocked:
            mocked.get(url, status=403, body="Forbidden", repeat=True)
            # 200 but body length is within the soft-200 delta guard.
            mocked.get("https://x.com/admin/", status=200, body="Forbiddes", repeat=True)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_access_bypass(session, url, sem)
                assert findings == []


class TestRunBypassScan:
    @pytest.mark.asyncio
    async def test_only_probes_blocked_endpoints(self):
        endpoints = [
            {"url": "https://x.com/admin", "status": 403},
            {"url": "https://x.com/pub", "status": 200},
        ]
        with aioresponses() as mocked:
            mocked.get("https://x.com/admin", status=403, body="Forbidden", repeat=True)
            mocked.get("https://x.com/admin/", status=200, body="A" * 300, repeat=True)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await run_bypass_scan(session, endpoints, sem)
                assert len(findings) == 1
                assert findings[0]["asset"] == "https://x.com/admin"

    @pytest.mark.asyncio
    async def test_no_blocked_endpoints_returns_empty(self):
        endpoints = [{"url": "https://x.com/pub", "status": 200}]
        async with aiohttp.ClientSession() as session:
            sem = asyncio.Semaphore(10)
            findings = await run_bypass_scan(session, endpoints, sem)
            assert findings == []
