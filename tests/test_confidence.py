"""
Tests for fastrecon.confidence — confidence scoring of findings.
"""

from fastrecon.confidence import (
    CONFIRMED,
    NEEDS_REVIEW,
    PROBABLE,
    annotate_confidence,
    assign_confidence,
    confidence_breakdown,
)


class TestAssignConfidence:
    def test_sqli_is_probable(self):
        assert assign_confidence({"type": "SQL Injection", "severity": "CRITICAL"}) == PROBABLE

    def test_reflected_xss_is_probable(self):
        assert assign_confidence({"type": "Reflected XSS", "severity": "MEDIUM"}) == PROBABLE

    def test_cors_is_confirmed(self):
        assert assign_confidence({"type": "CORS Misconfiguration", "severity": "HIGH"}) == CONFIRMED

    def test_open_redirect_is_confirmed(self):
        assert assign_confidence({"type": "Open Redirect", "severity": "MEDIUM"}) == CONFIRMED

    def test_clickjacking_is_confirmed(self):
        assert assign_confidence({"type": "Clickjacking", "severity": "MEDIUM"}) == CONFIRMED

    def test_host_header_high_is_confirmed(self):
        assert assign_confidence({"type": "Host Header Injection", "severity": "HIGH"}) == CONFIRMED

    def test_host_header_medium_is_probable(self):
        assert assign_confidence({"type": "Host Header Injection", "severity": "MEDIUM"}) == PROBABLE

    def test_info_disclosure_low_is_needs_review(self):
        assert assign_confidence({"type": "Information Disclosure", "severity": "LOW"}) == NEEDS_REVIEW

    def test_info_disclosure_medium_is_probable(self):
        assert assign_confidence({"type": "Information Disclosure", "severity": "MEDIUM"}) == PROBABLE

    def test_exposed_endpoint_is_probable(self):
        assert assign_confidence({"type": "Exposed Admin Panel", "severity": "HIGH"}) == PROBABLE

    def test_unknown_defaults_needs_review(self):
        assert assign_confidence({"type": "Something New", "severity": "LOW"}) == NEEDS_REVIEW


class TestAnnotate:
    def test_annotate_sets_confidence(self):
        findings = [
            {"type": "CORS Misconfiguration", "severity": "HIGH"},
            {"type": "Reflected XSS", "severity": "MEDIUM"},
        ]
        annotate_confidence(findings)
        assert findings[0]["confidence"] == CONFIRMED
        assert findings[1]["confidence"] == PROBABLE

    def test_annotate_does_not_overwrite(self):
        findings = [{"type": "CORS Misconfiguration", "severity": "HIGH", "confidence": "manual"}]
        annotate_confidence(findings)
        assert findings[0]["confidence"] == "manual"

    def test_breakdown_counts(self):
        findings = [
            {"type": "CORS Misconfiguration", "severity": "HIGH"},
            {"type": "Clickjacking", "severity": "MEDIUM"},
            {"type": "SQL Injection", "severity": "CRITICAL"},
            {"type": "Information Disclosure", "severity": "LOW"},
        ]
        counts = confidence_breakdown(findings)
        assert counts[CONFIRMED] == 2
        assert counts[PROBABLE] == 1
        assert counts[NEEDS_REVIEW] == 1
