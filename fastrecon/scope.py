"""
FastRecon Scope — authorization allowlist for active testing.

Active injection against a host you were not authorized to test is how a
bug-bounty hunter gets banned (or worse). This module encodes which hosts are
in scope so the scanner refuses to fire active payloads anywhere else.

Pattern forms (one per entry; '#' lines and blanks ignored in files):
  example.com        apex + all subdomains (the pragmatic default)
  *.example.com      subdomains only (not the apex)
  api.example.com    that host + its subdomains
  !admin.example.com exclusion — forces a host OUT of scope even if included

in_scope(host) is False unless an include matches and no exclusion matches.
With no patterns given, the scope defaults to the target domain + subdomains,
so existing single-target scans behave exactly as before.
"""

from urllib.parse import urlparse


def _norm_host(value):
    """Lowercase, strip scheme/path/port — accept a host or a full URL."""
    if not value:
        return ""
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
    return value.split(":", 1)[0].strip(".")


class Scope:
    """An include/exclude allowlist of host patterns."""

    def __init__(self, includes=None, excludes=None):
        self.includes = list(includes or [])
        self.excludes = list(excludes or [])

    @classmethod
    def from_spec(cls, patterns=None, default_target=None):
        """
        Build a Scope from a list of patterns. Entries starting with '!' are
        exclusions. If no include patterns remain and default_target is given,
        the target (apex + subdomains) becomes the sole include.
        """
        includes, excludes = [], []
        for raw in (patterns or []):
            pattern = (raw or "").strip().lower()
            if not pattern or pattern.startswith("#"):
                continue
            if pattern.startswith("!"):
                excludes.append(pattern[1:].strip())
            else:
                includes.append(pattern)
        if not includes and default_target:
            includes.append(_norm_host(default_target))
        return cls(includes, excludes)

    @staticmethod
    def _matches(host, pattern):
        pattern = pattern.strip().lower()
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return host.endswith(suffix)
        pattern = pattern.strip(".")
        if not pattern:
            return False
        return host == pattern or host.endswith("." + pattern)

    def in_scope(self, host_or_url):
        """True if the host is covered by an include and no exclude."""
        host = _norm_host(host_or_url)
        if not host:
            return False
        if any(self._matches(host, ex) for ex in self.excludes):
            return False
        return any(self._matches(host, inc) for inc in self.includes)

    def __bool__(self):
        return bool(self.includes)
