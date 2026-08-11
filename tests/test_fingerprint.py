"""
Tests for fastrecon.fingerprint — Technology detection with confidence levels.
Validates that the raised confidence bar correctly requires 2+ signal types.
"""

import pytest

from fastrecon.fingerprint import (
    _categorize_tech,
    fingerprint_technologies,
    generate_tech_insights,
)


# ── Tests for fingerprint_technologies ──


class TestFingerprintTechnologies:
    def test_single_body_match_is_low_confidence(self):
        """A single body-substring match should be 'low' confidence (30%)."""
        headers = {}
        body = '<html><script src="jquery.min.js"></script></html>'

        result = fingerprint_technologies("http://test.com", headers, body)
        jquery_matches = [t for t in result if t["name"] == "jQuery"]
        assert len(jquery_matches) == 1
        assert jquery_matches[0]["confidence"] == 30
        assert jquery_matches[0]["confidence_level"] == "low"
        assert jquery_matches[0]["signal_types"] == ["body"]

    def test_header_signal_alone_is_medium_or_higher(self):
        """A header match at 50+ confidence is included (single strong signal)."""
        headers = {"Server": "nginx/1.20.2"}
        body = ""

        result = fingerprint_technologies("http://test.com", headers, body)
        nginx_matches = [t for t in result if t["name"] == "nginx"]
        assert len(nginx_matches) == 1
        assert nginx_matches[0]["confidence"] >= 50
        assert nginx_matches[0]["signal_types"] == ["header"]

    def test_two_signal_types_is_medium_or_high(self):
        """Body + header signals → medium/high confidence."""
        headers = {"X-Powered-By": "Next.js"}
        body = '<html><script id="__NEXT_DATA__">{"props":{}}</script></html>'

        result = fingerprint_technologies("http://test.com", headers, body)
        nextjs_matches = [t for t in result if t["name"] == "Next.js"]
        assert len(nextjs_matches) == 1
        assert nextjs_matches[0]["confidence"] >= 50
        assert nextjs_matches[0]["confidence_level"] in ("medium", "high")
        assert "body" in nextjs_matches[0]["signal_types"]
        assert "header" in nextjs_matches[0]["signal_types"]

    def test_body_plus_meta_is_high_confidence(self):
        """Body + meta tag signals → high confidence."""
        headers = {}
        body = '<html><head><meta name="generator" content="WordPress 6.4"></head><body>wp-content/themes/</body></html>'

        result = fingerprint_technologies("http://test.com", headers, body)
        wp_matches = [t for t in result if t["name"] == "WordPress"]
        assert len(wp_matches) == 1
        assert wp_matches[0]["confidence"] >= 80
        assert wp_matches[0]["confidence_level"] == "high"
        assert "body" in wp_matches[0]["signal_types"]
        assert "meta" in wp_matches[0]["signal_types"]

    def test_no_match_returns_empty(self):
        """No matching signatures → empty list."""
        headers = {"Content-Type": "text/html"}
        body = "<html><body>Just a plain page</body></html>"

        result = fingerprint_technologies("http://test.com", headers, body)
        assert len(result) == 0

    def test_sorted_by_confidence(self):
        """Results should be sorted by confidence, highest first."""
        headers = {"Server": "nginx/1.20.2", "X-Powered-By": "Express"}
        body = '<html><script src="jquery.min.js"></script></html>'

        result = fingerprint_technologies("http://test.com", headers, body)
        if len(result) >= 2:
            for i in range(len(result) - 1):
                assert result[i]["confidence"] >= result[i + 1]["confidence"]

    def test_confidence_capped_at_100(self):
        """Confidence should never exceed 100."""
        headers = {"X-Powered-By": "Next.js"}
        body = (
            '<html><head></head><body>'
            '<script id="__NEXT_DATA__">{"props":{}}</script>'
            '<script src="/_next/static/chunks/main.js"></script>'
            '<link rel="preload" href="/_next/static/css/style.css">'
            '</body></html>'
        )

        result = fingerprint_technologies("http://test.com", headers, body)
        for tech in result:
            assert tech["confidence"] <= 100

    def test_signal_types_populated(self):
        """All detections should have signal_types populated."""
        headers = {"Server": "Apache/2.4.51"}
        body = '<html><script src="jquery.min.js"></script></html>'

        result = fingerprint_technologies("http://test.com", headers, body)
        for tech in result:
            assert len(tech["signal_types"]) > 0
            assert all(s in ("body", "header", "meta") for s in tech["signal_types"])


# ── Tests for _categorize_tech ──


class TestCategorizeTech:
    def test_cms(self):
        assert _categorize_tech("WordPress") == "CMS"
        assert _categorize_tech("Joomla") == "CMS"
        assert _categorize_tech("Drupal") == "CMS"
        assert _categorize_tech("Shopify") == "CMS"

    def test_framework(self):
        assert _categorize_tech("React") == "Framework"
        assert _categorize_tech("Django") == "Framework"
        assert _categorize_tech("Flask") == "Framework"

    def test_server(self):
        assert _categorize_tech("nginx") == "Web Server"
        assert _categorize_tech("Apache") == "Web Server"

    def test_cdn_and_waf(self):
        # Cloudflare is in both CDN and WAF lists — WAF check comes first in code
        assert _categorize_tech("Cloudflare") in ("CDN", "WAF / Security")
        assert _categorize_tech("Sucuri WAF") == "WAF / Security"

    def test_analytics(self):
        assert _categorize_tech("Google Analytics") == "Analytics"

    def test_unknown(self):
        assert _categorize_tech("SomeRandomTech") == "Other"


# ── Tests for generate_tech_insights ──


class TestGenerateTechInsights:
    def test_wordpress_insight(self):
        techs = [{"name": "WordPress", "category": "CMS", "confidence": 90, "confidence_level": "high"}]
        insights = generate_tech_insights(techs)
        wp_insights = [i for i in insights if i["technology"] == "WordPress"]
        assert len(wp_insights) == 1

    def test_no_waf_insight(self):
        """When no WAF/CDN is detected at medium/high confidence."""
        techs = [{"name": "nginx", "category": "Web Server", "confidence": 50, "confidence_level": "medium"}]
        insights = generate_tech_insights(techs)
        no_waf = [i for i in insights if i["technology"] == "None"]
        assert len(no_waf) == 1

    def test_low_confidence_not_used_for_insights(self):
        """Low confidence detections should NOT generate insights."""
        techs = [{"name": "WordPress", "category": "CMS", "confidence": 30, "confidence_level": "low"}]
        insights = generate_tech_insights(techs)
        wp_insights = [i for i in insights if i["technology"] == "WordPress"]
        assert len(wp_insights) == 0  # Low confidence = no insight

    def test_flask_insight(self):
        techs = [{"name": "Flask", "category": "Framework", "confidence": 50, "confidence_level": "medium"}]
        insights = generate_tech_insights(techs)
        flask_insights = [i for i in insights if i["technology"] == "Flask"]
        assert len(flask_insights) == 1
        assert flask_insights[0]["risk"] == "HIGH"

    def test_spring_boot_insight(self):
        techs = [{"name": "Spring Boot", "category": "Framework", "confidence": 50, "confidence_level": "medium"}]
        insights = generate_tech_insights(techs)
        spring_insights = [i for i in insights if i["technology"] == "Spring Boot"]
        assert len(spring_insights) == 1
        assert spring_insights[0]["risk"] == "HIGH"
