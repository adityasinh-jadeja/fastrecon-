"""
FastRecon Access-Control Bypass — 401/403 bypass probing.

When an endpoint returns 401/403, the content is often still reachable through
a well-known trick: a path-normalisation quirk, a trusted proxy header, or an
alternate HTTP method. These bypasses are a staple of bug-bounty work because a
"protected" admin panel that opens to `X-Forwarded-For: 127.0.0.1` is a real,
reportable access-control flaw.

This module takes endpoints that recon already saw return 401/403 and replays
them with a battery of bypass techniques, flagging any that yield a 200 with
materially different content than the blocked page.

False-positive guards:
  - Only probes URLs that actually returned 401/403 on a clean request.
  - A hit must be a 200 GET/POST whose body differs from the blocked page by a
    meaningful margin (SPA/soft-200 sites return 200 for everything).
  - HEAD/OPTIONS are tried for signal but never used to confirm on their own.
"""

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastrecon.vuln_scanner import _fetch

# Minimum body-length delta (bytes) between the blocked page and a candidate
# 200 response for the bypass to count — filters generic soft-200 pages.
_MIN_BODY_DELTA = 48

# Proxy / rewrite headers commonly trusted by misconfigured front ends.
_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
]


def _path_variants(path):
    """Path-normalisation tricks that can slip past prefix-based ACLs."""
    if not path:
        path = "/"
    return [
        path + "/",
        path + "/.",
        path + "//",
        path + "/..;/",
        path + "..;/",
        path + "%20",
        path + "%09",
        path + "?",
        path + "#",
        path + ".json",
        path.upper(),
        "/%2e" + path,
    ]


async def check_access_bypass(session, url, semaphore):
    """
    Probe a single 401/403 URL for access-control bypasses.
    Returns a list with at most one finding (the first working bypass).
    """
    findings = []
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"

    async with semaphore:
        base_status, _, base_body, _ = await _fetch(session, url)
        if base_status not in (401, 403):
            return findings  # not actually blocked — nothing to bypass
        base_len = len(base_body or "")

        candidates = []
        # Path tricks (GET).
        for variant in _path_variants(path):
            candidates.append(("GET", root + variant, None, f"path:{variant}"))
        # Rewrite headers that re-point the request to the blocked path.
        for header in ({"X-Original-URL": path}, {"X-Rewrite-URL": path}):
            candidates.append(("GET", root + "/", header, f"header:{next(iter(header))}"))
        # Trusted-proxy headers on the original URL.
        for header in _BYPASS_HEADERS:
            candidates.append(("GET", url, header, f"header:{next(iter(header))}"))
        # Alternate methods.
        for method in ("POST", "HEAD", "OPTIONS"):
            candidates.append((method, url, None, f"method:{method}"))

        for method, candidate_url, headers, label in candidates:
            status, _, body, tls_unverified = await _fetch(
                session, candidate_url, method=method, headers=headers,
            )
            if status != 200:
                continue
            # HEAD/OPTIONS can't confirm content access on their own.
            if method in ("HEAD", "OPTIONS"):
                continue
            body_len = len(body or "")
            if body_len == 0:
                continue
            if abs(body_len - base_len) < _MIN_BODY_DELTA:
                continue

            findings.append({
                "severity": "HIGH",
                "type": "Access Control Bypass",
                "asset": url,
                "service": "Web Application",
                "details": (
                    f"Endpoint returned {base_status} normally but 200 via {label}. "
                    f"Protected content may be reachable without authorization."
                ),
                "evidence": f"Technique: {label} | {base_status}→200 | body {base_len}→{body_len} bytes",
                "cname_pattern": "",
                "tls_unverified": tls_unverified,
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "remediation": (
                    "Enforce authorization at the application layer, normalize paths before "
                    "ACL checks, and never trust client-supplied X-Forwarded-*/X-Original-URL headers."
                ),
            })
            return findings

    return findings


async def run_bypass_scan(session, endpoints, semaphore, max_targets=15):
    """
    Run access-control bypass probing against discovered 401/403 endpoints.

    Args:
        session: aiohttp ClientSession
        endpoints: list of endpoint dicts (from endpoint discovery) with 'url'/'status'
        semaphore: concurrency limiter
        max_targets: cap on how many blocked endpoints to probe

    Returns:
        List of bypass finding dicts.
    """
    blocked = []
    seen = set()
    for ep in endpoints or []:
        if not isinstance(ep, dict):
            continue
        if ep.get("status") in (401, 403):
            url = ep.get("url", "")
            if url and url not in seen:
                seen.add(url)
                blocked.append(url)

    if not blocked:
        return []

    blocked = blocked[:max_targets]
    print(f"  [BYPASS] Probing {len(blocked)} blocked endpoint(s) for 401/403 bypasses...")

    results = await asyncio.gather(
        *(check_access_bypass(session, url, semaphore) for url in blocked),
        return_exceptions=True,
    )

    findings = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
    return findings
