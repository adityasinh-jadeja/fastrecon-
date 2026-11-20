"""
Tests for fastrecon.endpoint_discovery link extraction.

Regression guard for the bug where relative parameterized links were dropped,
starving the injection engine of real parameters.
"""

import asyncio

from fastrecon.endpoint_discovery import extract_html_links


def _links(html, base="http://testasp.vulnweb.com"):
    return set(asyncio.run(extract_html_links(html, base)))


class TestExtractHtmlLinks:
    def test_relative_link_with_params_resolved(self):
        html = '<a href="Templatize.asp?item=html/about.html">x</a>'
        links = _links(html)
        assert "http://testasp.vulnweb.com/Templatize.asp?item=html/about.html" in links

    def test_dot_relative_link_resolved(self):
        html = '<a href="./Login.asp?RetURL=%2FDefault">y</a>'
        links = _links(html)
        assert "http://testasp.vulnweb.com/Login.asp?RetURL=%2FDefault" in links

    def test_absolute_path_link_resolved(self):
        html = '<a href="/showforum.asp?id=1">z</a>'
        links = _links(html)
        assert "http://testasp.vulnweb.com/showforum.asp?id=1" in links

    def test_full_url_kept(self):
        html = '<a href="https://evil.com/q?a=1">e</a>'
        assert "https://evil.com/q?a=1" in _links(html)

    def test_non_http_schemes_dropped(self):
        html = (
            '<a href="mailto:a@b.com">m</a>'
            '<a href="tel:+100">t</a>'
            '<a href="javascript:void(0)">j</a>'
            '<a href="#section">h</a>'
        )
        assert _links(html) == set()

    def test_form_action_resolved(self):
        html = '<form action="search.asp?q="><input name="q"></form>'
        links = _links(html)
        assert "http://testasp.vulnweb.com/search.asp?q=" in links
