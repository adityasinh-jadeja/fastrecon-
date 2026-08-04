"""
FastRecon Endpoint Discovery — Path fuzzing, JS link extraction, and hidden endpoint detection.
"""

import asyncio
import re
import ssl
from datetime import datetime, timezone

from fastrecon.config import (
    ENDPOINT_PATHS_LARGE,
    ENDPOINT_PATHS_MEDIUM,
    ENDPOINT_PATHS_SMALL,
    ENDPOINT_TIMEOUT,
)


async def fuzz_path(session, base_url, path, semaphore):
    """
    Check if a path exists on the target.
    Returns endpoint info dict if interesting, None otherwise.
    """
    async with semaphore:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            async with session.get(
                url,
                timeout=ENDPOINT_TIMEOUT,
                allow_redirects=False,
                ssl=ssl_context,
            ) as response:
                status = response.status
                content_length = int(response.headers.get("Content-Length", 0))

                # Interesting status codes
                if status in (200, 201, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503):
                    body = ""
                    # Read body for 200/500 to check for info disclosure
                    if status in (200, 500) and content_length < 500000:
                        try:
                            body = await response.text()
                        except Exception:
                            pass

                    # Determine severity/interest level
                    severity = _classify_finding(path, status, body)
                    if severity is None:
                        return None

                    endpoint_info = {
                        "url": url,
                        "path": path,
                        "status": status,
                        "contentLength": content_length,
                        "severity": severity,
                        "type": _classify_type(path),
                        "redirect": str(response.headers.get("Location", "")) if status in (301, 302, 307, 308) else "",
                    }

                    return endpoint_info

        except Exception:
            pass

        return None


def _classify_finding(path, status, body=""):
    """Classify the severity of a found endpoint."""
    path_lower = path.lower()

    # Critical: Sensitive files accessible
    critical_paths = [
        ".env", ".git/config", ".git/HEAD", ".aws/credentials",
        ".ssh/", "id_rsa", "wp-config.php", ".htpasswd",
        ".npmrc", ".pypirc",
    ]
    for cp in critical_paths:
        if cp in path_lower and status == 200:
            return "CRITICAL"

    # High: Admin panels, debug endpoints, database files
    high_paths = [
        "admin", "phpmyadmin", "phpinfo", "server-status",
        "server-info", "debug", "actuator", "elmah",
        "backup", ".sql", ".bak", "dump",
        "wp-json/wp/v2/users", "graphiql",
    ]
    for hp in high_paths:
        if hp in path_lower and status == 200:
            return "HIGH"

    # Check for info disclosure in response body
    if status == 200 and body:
        disclosure_patterns = [
            r"password\s*[:=]",
            r"api[_-]?key\s*[:=]",
            r"secret[_-]?key\s*[:=]",
            r"access[_-]?token\s*[:=]",
            r"aws[_-]?access",
            r"BEGIN\s+(RSA|DSA|EC)\s+PRIVATE\s+KEY",
        ]
        for pattern in disclosure_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return "CRITICAL"

    # Medium: Exposed APIs, config files, error pages with details
    medium_paths = [
        "api", "swagger", "openapi", "graphql",
        "config", "settings", "console",
        "wp-", "xmlrpc", "jenkins", "solr",
    ]
    for mp in medium_paths:
        if mp in path_lower and status in (200, 401, 403):
            return "MEDIUM"

    # 500 errors = potential info disclosure
    if status == 500:
        return "MEDIUM"

    # 403 = exists but blocked (informational)
    if status == 403:
        return "LOW"

    # 401 = requires auth (interesting)
    if status == 401:
        return "LOW"

    # 200 on common paths is informational
    if status == 200:
        return "INFO"

    # Redirects on admin paths
    if status in (301, 302, 307, 308):
        for mp in ["admin", "login", "dashboard", "manage", "portal"]:
            if mp in path_lower:
                return "INFO"
        return None  # Skip random redirects

    return None


def _classify_type(path):
    """Classify the type of endpoint found."""
    path_lower = path.lower()

    if any(x in path_lower for x in ["admin", "dashboard", "manage", "panel", "cpanel"]):
        return "Admin Panel"
    elif any(x in path_lower for x in ["login", "signin", "auth"]):
        return "Authentication"
    elif any(x in path_lower for x in ["api", "rest", "graphql", "swagger", "openapi"]):
        return "API Endpoint"
    elif any(x in path_lower for x in [".env", ".git", ".aws", ".ssh", "config", "settings"]):
        return "Sensitive File"
    elif any(x in path_lower for x in ["backup", ".sql", ".bak", "dump", ".zip", ".tar"]):
        return "Backup/Archive"
    elif any(x in path_lower for x in ["debug", "trace", "phpinfo", "server-status", "actuator"]):
        return "Debug/Info"
    elif any(x in path_lower for x in ["jenkins", "grafana", "prometheus", "solr", "kibana"]):
        return "DevOps Tool"
    elif any(x in path_lower for x in ["upload", "file", "media"]):
        return "File Upload"
    elif any(x in path_lower for x in ["wp-", "joomla", "drupal"]):
        return "CMS"
    else:
        return "Other"


async def extract_js_links(session, base_url, html_body, semaphore):
    """
    Extract JavaScript file URLs from HTML, then parse them for API endpoints.
    """
    js_urls = set()
    api_endpoints = set()

    # Find JS file URLs
    script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in script_pattern.finditer(html_body):
        src = match.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = base_url.rstrip("/") + src
        elif not src.startswith("http"):
            src = base_url.rstrip("/") + "/" + src
        js_urls.add(src)

    # Fetch and parse JS files for API endpoints
    for js_url in list(js_urls)[:20]:  # Limit to 20 JS files
        async with semaphore:
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                async with session.get(
                    js_url, timeout=ENDPOINT_TIMEOUT, ssl=ssl_context
                ) as response:
                    if response.status == 200:
                        js_content = await response.text()
                        # Extract API paths from JS
                        api_patterns = [
                            r'["\']/(api/[^"\'?\s]+)["\']',
                            r'["\']/(v[12]/[^"\'?\s]+)["\']',
                            r'fetch\(["\']([^"\']+)["\']',
                            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                            r'url:\s*["\']([^"\']+)["\']',
                            r'endpoint:\s*["\']([^"\']+)["\']',
                        ]
                        for pattern in api_patterns:
                            for match in re.finditer(pattern, js_content):
                                endpoint = match.group(1)
                                if endpoint and len(endpoint) < 200 and not endpoint.startswith("http"):
                                    api_endpoints.add(endpoint)
            except Exception:
                continue

    return list(js_urls), list(api_endpoints)


async def extract_html_links(html_body, base_url):
    """Extract all links from HTML response."""
    links = set()

    # <a href="...">
    href_pattern = re.compile(r'<a[^>]+href=["\']([^"\'#]+)["\']', re.IGNORECASE)
    for match in href_pattern.finditer(html_body):
        link = match.group(1)
        if link.startswith("/"):
            link = base_url.rstrip("/") + link
        if link.startswith("http"):
            links.add(link)

    # <form action="...">
    form_pattern = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in form_pattern.finditer(html_body):
        action = match.group(1)
        if action.startswith("/"):
            action = base_url.rstrip("/") + action
        if action.startswith("http"):
            links.add(action)

    return list(links)


def generate_alerts_from_endpoints(endpoints, target):
    """Generate security alerts from discovered endpoints."""
    alerts = []

    for ep in endpoints:
        if ep["severity"] in ("CRITICAL", "HIGH"):
            alerts.append({
                "severity": ep["severity"],
                "type": f"Exposed {ep['type']}",
                "asset": ep["url"],
                "service": ep["type"],
                "details": f"{ep['type']} found at {ep['path']} (HTTP {ep['status']})",
                "evidence": f"URL: {ep['url']} returned HTTP {ep['status']}",
                "cname_pattern": "",
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            })

    return alerts


async def run_endpoint_discovery(session, target, base_url, html_body="", mode="normal", concurrency=30):
    """
    Execute full endpoint discovery.

    Args:
        session: aiohttp ClientSession
        target: Target domain
        base_url: Base URL (e.g., https://example.com)
        html_body: HTML body from initial probe (for link extraction)
        mode: Scan mode (light/normal/aggressive)
        concurrency: Max concurrent requests

    Returns:
        (endpoints list, js_files list, api_endpoints list, html_links list, alerts list)
    """
    print(f"\n{'='*60}")
    print("  PHASE 6: ENDPOINT DISCOVERY")
    print(f"{'='*60}")

    semaphore = asyncio.Semaphore(concurrency)

    # Select wordlist based on mode
    if mode == "light":
        paths = ENDPOINT_PATHS_SMALL
    elif mode == "aggressive":
        paths = ENDPOINT_PATHS_LARGE
    else:
        paths = ENDPOINT_PATHS_MEDIUM

    print(f"  Fuzzing {len(paths)} paths on {base_url} (mode: {mode})...")

    # Path fuzzing
    tasks = [fuzz_path(session, base_url, path, semaphore) for path in paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    endpoints = []
    for result in results:
        if isinstance(result, dict) and result is not None:
            endpoints.append(result)
            severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟡", "INFO": "⚪"}.get(result["severity"], "⚪")
            print(f"  {severity_icon} [{result['status']}] {result['path']} — {result['type']}")

    # Extract JS links and API endpoints
    print("\n  Extracting JS files and API endpoints...")
    js_files, api_endpoints = await extract_js_links(session, base_url, html_body, semaphore)
    print(f"  [JS] Found {len(js_files)} JS files, {len(api_endpoints)} API endpoints")

    # Extract HTML links
    html_links = await extract_html_links(html_body, base_url) if html_body else []
    print(f"  [HTML] Found {len(html_links)} links")

    # Generate alerts from findings
    alerts = generate_alerts_from_endpoints(endpoints, target)

    # Sort endpoints by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    endpoints.sort(key=lambda x: severity_order.get(x["severity"], 5))

    print(f"\n  ✓ Endpoint discovery complete: {len(endpoints)} found, {len(alerts)} alert(s)")

    return endpoints, js_files, api_endpoints, html_links, alerts
