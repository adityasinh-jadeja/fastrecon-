"""
Tests for parameterized injection — the wiring that feeds REAL discovered
endpoints and parameters into the vulnerability scanner (instead of only the
homepage with guessed parameter names).

Covers:
  - _in_scope           (scope enforcement)
  - build_injection_targets  (corpus building from recon data)
  - extract_forms       (form field extraction)
  - check_sqli_on_target / check_xss_on_target  (real-param injection)
"""

import asyncio
from urllib.parse import urlencode

import aiohttp
import pytest
from aioresponses import aioresponses

from fastrecon.config import SQLI_PAYLOADS, XSS_PAYLOADS
from fastrecon.endpoint_discovery import extract_forms
from fastrecon.vuln_scanner import (
    _in_scope,
    build_injection_targets,
    check_sqli_on_target,
    check_xss_on_target,
)

# ── Scope enforcement ──


class TestInScope:
    def test_exact_domain(self):
        assert _in_scope("https://example.com/path?a=1", "example.com") is True

    def test_subdomain(self):
        assert _in_scope("https://api.example.com/v1?a=1", "example.com") is True

    def test_out_of_scope_domain(self):
        assert _in_scope("https://evil.com/x?a=1", "example.com") is False

    def test_lookalike_not_in_scope(self):
        # "notexample.com" must NOT be treated as a subdomain of example.com
        assert _in_scope("https://notexample.com/x?a=1", "example.com") is False

    def test_host_only_semantics(self):
        # _in_scope checks the host only; scheme filtering happens in
        # build_injection_targets, so a non-http same-host URL is "in scope" here.
        assert _in_scope("ftp://example.com/x", "example.com") is True


# ── Corpus building ──


class TestBuildInjectionTargets:
    def test_extracts_params_from_html_links(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=["https://example.com/product?item_id=42"],
        )
        assert len(targets) == 1
        assert targets[0]["url"] == "https://example.com/product"
        assert targets[0]["params"] == {"item_id": "42"}
        assert targets[0]["method"] == "GET"

    def test_skips_links_without_params(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=["https://example.com/about"],
        )
        assert targets == []

    def test_excludes_out_of_scope(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=["https://evil.com/x?q=1"],
        )
        assert targets == []

    def test_excludes_non_http_scheme(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=["ftp://example.com/x?q=1"],
        )
        assert targets == []

    def test_includes_subdomain(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            endpoints=[{"url": "https://sub.example.com/search?s=test"}],
        )
        assert len(targets) == 1
        assert targets[0]["url"] == "https://sub.example.com/search"

    def test_resolves_relative_api_endpoint(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            api_endpoints=["/api/users?role=admin"],
        )
        assert len(targets) == 1
        assert targets[0]["url"] == "https://example.com/api/users"
        assert targets[0]["params"] == {"role": "admin"}

    def test_form_becomes_post_target(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            forms=[{"action": "https://example.com/login", "method": "POST",
                    "params": {"user": "a", "pass": "b"}}],
        )
        assert len(targets) == 1
        assert targets[0]["method"] == "POST"
        assert set(targets[0]["params"].keys()) == {"user", "pass"}

    def test_dedupes_same_path_and_params(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=[
                "https://example.com/p?id=1",
                "https://example.com/p?id=2",  # same path + param set
            ],
        )
        assert len(targets) == 1

    def test_blank_value_gets_default(self):
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=["https://example.com/p?debug"],
        )
        assert targets[0]["params"]["debug"] == "fastrecon"

    def test_respects_max_targets(self):
        links = [f"https://example.com/p{i}?id={i}" for i in range(100)]
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=links, max_targets=10,
        )
        assert len(targets) == 10


# ── Form extraction ──


class TestExtractForms:
    def test_basic_form(self):
        html = (
            '<form action="/login" method="post">'
            '<input name="user" type="text">'
            '<input name="pass" type="password">'
            '<input type="submit" value="Go">'
            "</form>"
        )
        forms = extract_forms(html, "https://example.com")
        assert len(forms) == 1
        assert forms[0]["action"] == "https://example.com/login"
        assert forms[0]["method"] == "POST"
        assert set(forms[0]["params"].keys()) == {"user", "pass"}

    def test_skips_submit_and_file_inputs(self):
        html = (
            '<form action="/x">'
            '<input name="q">'
            '<input name="upload" type="file">'
            '<input name="go" type="submit">'
            "</form>"
        )
        forms = extract_forms(html, "https://example.com")
        assert set(forms[0]["params"].keys()) == {"q"}

    def test_defaults_method_to_get(self):
        html = '<form action="/search"><input name="q"></form>'
        forms = extract_forms(html, "https://example.com")
        assert forms[0]["method"] == "GET"

    def test_empty_body(self):
        assert extract_forms("", "https://example.com") == []

    def test_form_with_no_named_inputs_skipped(self):
        html = '<form action="/x"><input type="submit"></form>'
        assert extract_forms(html, "https://example.com") == []


# ── Real-parameter injection ──


class TestCheckSqliOnTarget:
    @pytest.mark.asyncio
    async def test_sqli_on_real_param(self):
        base_path = "https://test.example.com/product"
        target = {"url": base_path, "method": "GET",
                  "params": {"item_id": "42"}, "source": "html_link"}

        with aioresponses() as mocked:
            baseline_url = f"{base_path}?{urlencode({'item_id': '42'})}"
            mocked.get(baseline_url, status=200, body="<html>ok</html>", repeat=True)
            for payload in SQLI_PAYLOADS[:3]:
                inj = f"{base_path}?{urlencode({'item_id': payload})}"
                mocked.get(inj, status=200,
                           body="You have an error in your SQL syntax near '1'",
                           repeat=True)

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_sqli_on_target(session, target, sem)
                assert len(findings) == 1
                assert findings[0]["severity"] == "CRITICAL"
                assert "item_id" in findings[0]["evidence"]

    @pytest.mark.asyncio
    async def test_sqli_error_in_baseline_not_flagged(self):
        base_path = "https://test.example.com/product"
        target = {"url": base_path, "method": "GET",
                  "params": {"item_id": "42"}, "source": "html_link"}
        sql_err = "You have an error in your SQL syntax"

        with aioresponses() as mocked:
            # Baseline ALSO shows the SQL error — so injection must NOT be flagged.
            baseline_url = f"{base_path}?{urlencode({'item_id': '42'})}"
            mocked.get(baseline_url, status=200, body=sql_err, repeat=True)
            for payload in SQLI_PAYLOADS[:3]:
                inj = f"{base_path}?{urlencode({'item_id': payload})}"
                mocked.get(inj, status=200, body=sql_err, repeat=True)

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_sqli_on_target(session, target, sem)
                assert findings == []


class TestCheckXssOnTarget:
    @pytest.mark.asyncio
    async def test_xss_on_real_param(self):
        base_path = "https://test.example.com/search"
        target = {"url": base_path, "method": "GET",
                  "params": {"q": "hello"}, "source": "html_link"}

        with aioresponses() as mocked:
            baseline_url = f"{base_path}?{urlencode({'q': 'hello'})}"
            mocked.get(baseline_url, status=200,
                       body="<html><body>results</body></html>", repeat=True)
            for payload in XSS_PAYLOADS[:3]:
                inj = f"{base_path}?{urlencode({'q': payload})}"
                mocked.get(inj, status=200,
                           body=f"<html><body><div>{payload}</div></body></html>",
                           repeat=True)

            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                findings = await check_xss_on_target(session, target, sem)
                assert len(findings) == 1
                assert findings[0]["type"] == "Reflected XSS"
                assert "q" in findings[0]["evidence"]
