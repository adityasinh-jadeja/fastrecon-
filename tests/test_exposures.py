"""
Tests for fastrecon.exposures — GraphQL introspection + sensitive file exposure.
"""

import asyncio

import aiohttp
import pytest
from aioresponses import aioresponses

from fastrecon.exposures import (
    check_graphql_introspection,
    check_sensitive_files,
    run_exposures_scan,
)


class TestGraphQLIntrospection:
    @pytest.mark.asyncio
    async def test_introspection_enabled_flagged(self):
        with aioresponses() as mocked:
            mocked.post(
                "https://x.com/graphql", status=200,
                body='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                repeat=True,
            )
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_graphql_introspection(session, "https://x.com", sem)
                assert len(findings) == 1
                assert findings[0]["type"] == "GraphQL Introspection"

    @pytest.mark.asyncio
    async def test_introspection_disabled_not_flagged(self):
        with aioresponses() as mocked:
            mocked.post("https://x.com/graphql", status=400, body="Bad Request", repeat=True)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_graphql_introspection(session, "https://x.com", sem)
                assert findings == []


class TestSensitiveFiles:
    @pytest.mark.asyncio
    async def test_env_file_content_confirmed(self):
        with aioresponses() as mocked:
            mocked.get(
                "https://x.com/.env", status=200,
                body="APP_KEY=base64deadbeef\nDB_PASSWORD=supersecret\n",
                repeat=True,
            )
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_sensitive_files(session, "https://x.com", sem)
                env = [f for f in findings if f["asset"].endswith("/.env")]
                assert len(env) == 1
                assert env[0]["severity"] == "CRITICAL"
                assert env[0]["type"] == "Sensitive File Exposure"

    @pytest.mark.asyncio
    async def test_soft_200_html_not_flagged(self):
        # /.env returns a 200 but it's the SPA index, not a real env file.
        with aioresponses() as mocked:
            mocked.get(
                "https://x.com/.env", status=200,
                body="<!doctype html><html><body>App</body></html>",
                repeat=True,
            )
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_sensitive_files(session, "https://x.com", sem)
                env = [f for f in findings if f["asset"].endswith("/.env")]
                assert env == []


class TestRunExposuresScan:
    @pytest.mark.asyncio
    async def test_merges_findings(self):
        with aioresponses() as mocked:
            mocked.post(
                "https://x.com/graphql", status=200,
                body='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                repeat=True,
            )
            mocked.get(
                "https://x.com/.git/config", status=200,
                body="[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n",
                repeat=True,
            )
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await run_exposures_scan(session, "https://x.com", sem)
                types = {f["type"] for f in findings}
                assert "GraphQL Introspection" in types
                assert "Sensitive File Exposure" in types
