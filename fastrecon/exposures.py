"""
FastRecon Exposures — GraphQL introspection + content-verified sensitive files.

Two high-signal checks that produce *confirmed* findings:

1. GraphQL introspection: a schema dump handed to anyone who asks is a real
   information-disclosure issue and the first step of most GraphQL attacks.

2. Sensitive file exposure: endpoint discovery flags files like `.env` or
   `.git/config` by status code alone, which misfires on SPA catch-all 200s.
   This verifies the *content* actually matches the file it claims to be, so a
   hit is proof — and attaches a short, length-capped snippet as evidence.
"""

import asyncio
import re
from datetime import datetime, timezone

from fastrecon.vuln_scanner import _fetch

# Minimal introspection query — just enough to prove the schema is readable.
_INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/console",
    "/query",
    "/graphql.php",
]

# (path, severity, [content markers]) — a 200 whose body matches a marker is a
# confirmed exposure. Markers are deliberately specific to avoid SPA false hits.
_SENSITIVE_FILES = [
    ("/.env", "CRITICAL", [r"^[A-Z0-9_]{3,}=", r"APP_KEY", r"DB_PASSWORD", r"SECRET_KEY", r"AWS_"]),
    ("/.git/config", "CRITICAL", [r"\[core\]", r"\[remote ", r"repositoryformatversion"]),
    ("/.git/HEAD", "HIGH", [r"ref:\s*refs/"]),
    ("/.aws/credentials", "CRITICAL", [r"aws_access_key_id", r"\[default\]"]),
    ("/.htpasswd", "HIGH", [r"^[\w.-]+:\$(apr1|2y|1)\$"]),
    ("/.npmrc", "HIGH", [r"_authToken", r"//registry\."]),
    ("/phpinfo.php", "MEDIUM", [r"phpinfo\(\)", r"PHP Version\s*</td>"]),
    ("/server-status", "MEDIUM", [r"Apache Server Status", r"Server uptime"]),
    ("/.svn/entries", "HIGH", [r"svn://", r"dir\n"]),
    ("/docker-compose.yml", "MEDIUM", [r"^services:", r"image:\s"]),
]

# How much matched content to include as proof (keep it short — don't exfiltrate).
_EVIDENCE_LEN = 80


async def check_graphql_introspection(session, base_url, semaphore):
    """POST a tiny introspection query to known GraphQL paths; flag if it works."""
    findings = []
    headers = {"Content-Type": "application/json"}
    root = base_url.rstrip("/")

    async with semaphore:
        for path in _GRAPHQL_PATHS:
            url = f"{root}{path}"
            status, _, body, tls_unverified = await _fetch(
                session, url, method="POST", headers=headers, data=_INTROSPECTION_QUERY,
            )
            if status == 200 and body and "__schema" in body and "queryType" in body:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "GraphQL Introspection",
                    "asset": url,
                    "service": "GraphQL API",
                    "details": (
                        "GraphQL introspection is enabled — the full schema (types, queries, "
                        "mutations) is readable by anyone, exposing the API's attack surface."
                    ),
                    "evidence": "Introspection query returned a __schema/queryType response",
                    "cname_pattern": "",
                    "tls_unverified": tls_unverified,
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "remediation": "Disable introspection in production GraphQL servers.",
                })
                return findings  # one is enough

    return findings


def _match_marker(body, markers):
    """Return the first matching marker's evidence snippet, or None."""
    for marker in markers:
        match = re.search(marker, body, re.IGNORECASE | re.MULTILINE)
        if match:
            # Grab the line around the match as proof, length-capped.
            start = body.rfind("\n", 0, match.start()) + 1
            end = body.find("\n", match.start())
            if end == -1:
                end = len(body)
            snippet = body[start:end].strip()[:_EVIDENCE_LEN]
            return snippet or marker
    return None


async def check_sensitive_files(session, base_url, semaphore):
    """Fetch known sensitive paths and confirm by content, not just status."""
    findings = []
    root = base_url.rstrip("/")

    async with semaphore:
        for path, severity, markers in _SENSITIVE_FILES:
            url = f"{root}{path}"
            status, _, body, tls_unverified = await _fetch(session, url)
            if status != 200 or not body:
                continue

            snippet = _match_marker(body, markers)
            if not snippet:
                continue  # 200 but content doesn't match — likely a catch-all page

            findings.append({
                "severity": severity,
                "type": "Sensitive File Exposure",
                "asset": url,
                "service": "Web Server",
                "details": (
                    f"Sensitive file {path} is publicly accessible and its content was "
                    f"verified (not just a 200 status) — may leak secrets or source."
                ),
                "evidence": f"Confirmed content at {path}: {snippet!r}",
                "cname_pattern": "",
                "tls_unverified": tls_unverified,
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "remediation": (
                    "Block access to dotfiles, VCS directories, and config/backup files at "
                    "the web server; never deploy them to the web root."
                ),
            })

    return findings


async def run_exposures_scan(session, base_url, semaphore):
    """Run GraphQL introspection + sensitive-file checks; return merged findings."""
    results = await asyncio.gather(
        check_graphql_introspection(session, base_url, semaphore),
        check_sensitive_files(session, base_url, semaphore),
        return_exceptions=True,
    )
    findings = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
    return findings
