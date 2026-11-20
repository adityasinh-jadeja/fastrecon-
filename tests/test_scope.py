"""
Tests for fastrecon.scope — authorization allowlist for active testing.
"""

from fastrecon.scope import Scope, _norm_host
from fastrecon.vuln_scanner import build_injection_targets


class TestNormHost:
    def test_from_url(self):
        assert _norm_host("https://api.example.com:443/path?x=1") == "api.example.com"

    def test_from_bare_host(self):
        assert _norm_host("Example.COM") == "example.com"


class TestScopeMatching:
    def test_bare_domain_matches_apex_and_subdomains(self):
        s = Scope.from_spec(["example.com"])
        assert s.in_scope("example.com") is True
        assert s.in_scope("https://api.example.com/x") is True
        assert s.in_scope("evil.com") is False

    def test_wildcard_matches_subdomains_only(self):
        s = Scope.from_spec(["*.example.com"])
        assert s.in_scope("api.example.com") is True
        assert s.in_scope("example.com") is False

    def test_exclusion_overrides_include(self):
        s = Scope.from_spec(["example.com", "!admin.example.com"])
        assert s.in_scope("api.example.com") is True
        assert s.in_scope("admin.example.com") is False

    def test_lookalike_not_in_scope(self):
        s = Scope.from_spec(["example.com"])
        assert s.in_scope("notexample.com") is False

    def test_default_target_used_when_no_includes(self):
        s = Scope.from_spec(["!admin.example.com"], default_target="example.com")
        assert s.in_scope("api.example.com") is True
        assert s.in_scope("admin.example.com") is False

    def test_empty_scope_is_falsy(self):
        assert bool(Scope.from_spec([])) is False


class TestScopeInCorpus:
    def test_corpus_respects_scope_excludes(self):
        # admin.example.com is excluded even though it's a subdomain.
        scope = Scope.from_spec(["example.com", "!admin.example.com"])
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=[
                "https://api.example.com/p?id=1",
                "https://admin.example.com/p?id=2",
            ],
            scope=scope,
        )
        hosts = {t["url"] for t in targets}
        assert "https://api.example.com/p" in hosts
        assert "https://admin.example.com/p" not in hosts

    def test_corpus_without_scope_uses_target_default(self):
        # No scope passed — falls back to target domain + subdomains.
        targets = build_injection_targets(
            "https://example.com", "example.com",
            html_links=["https://evil.com/p?id=1", "https://example.com/p?id=2"],
        )
        hosts = {t["url"] for t in targets}
        assert hosts == {"https://example.com/p"}
